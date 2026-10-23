"""OAuth Code + PKCE with verified user access tokens and Asserter group membership."""

from __future__ import annotations

import json
import logging
import math
import secrets
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from ..diagnostics import verification_step
from ..models import LOGIN_SCOPES, Identity, Parent
from .tokens import verify_user_access_token

logger = logging.getLogger(__name__)


def _log_groups(source: str, claims: dict[str, Any], parent: Parent, **checks: bool) -> None:
    """Log bounded group diagnostics, excluding tokens and unrelated user claims."""
    entries = claims.get("groups")
    groups: list[Any] = []
    if isinstance(entries, list):
        for group in entries[:50]:
            if isinstance(group, str):
                groups.append(group[:200])
            elif isinstance(group, dict):
                groups.append(
                    {
                        key: str(group[key])[:200]
                        for key in ("id", "value", "name", "display")
                        if isinstance(group.get(key), str)
                    }
                )
            else:
                groups.append({"invalid_type": type(group).__name__})
    logger.info(
        "OAuth group diagnostics: %s",
        json.dumps(
            {
                "source": source,
                "claim_names": sorted(claims)[:50],
                "groups_present": "groups" in claims,
                "groups_type": type(entries).__name__,
                "group_count": len(entries) if isinstance(entries, list) else 0,
                "groups": groups,
                "groups_truncated": isinstance(entries, list) and len(entries) > 50,
                "expected_group_ids": {
                    "ogc_admin": parent.admin_group_id,
                    "ogc_viewer": parent.viewer_group_id,
                },
                **checks,
            }
        ),
    )


def endpoint(value: str, origin: str) -> str:
    """Constrain discovered endpoints to the saved identity-domain HTTPS origin."""
    parsed, saved = urlsplit(value), urlsplit(origin)
    if (
        parsed.scheme != "https"
        or parsed.hostname != saved.hostname
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("OIDC endpoint is outside the configured identity domain")
    return value


async def metadata(parent: Parent) -> dict[str, Any]:
    """Read trusted discovery metadata with TLS, timeouts and redirects disabled."""
    async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
        response = await client.get(parent.domain.url + "/.well-known/openid-configuration")
        response.raise_for_status()
        data: dict[str, Any] = response.json()
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint(data[name], parent.domain.url)
    if not str(data.get("issuer", "")).startswith("https://"):
        raise ValueError("OIDC discovery has no valid issuer")
    return data


async def begin(parent: Parent, callback: str) -> tuple[str, dict[str, Any]]:
    """Create a one-time Code+PKCE authorization bound to state."""
    meta = await metadata(parent)
    verifier = secrets.token_urlsafe(64)
    async with AsyncOAuth2Client(
        parent.client_id,
        parent.client_secret.get_secret_value(),
        scope=" ".join(LOGIN_SCOPES),
        redirect_uri=callback,
        code_challenge_method="S256",
        timeout=15,
        follow_redirects=False,
        trust_env=False,
    ) as oauth:
        url, state = oauth.create_authorization_url(
            meta["authorization_endpoint"], code_verifier=verifier
        )
    return str(url), {"state": state, "verifier": verifier, "metadata": meta}


async def finish(
    parent: Parent, callback: str, code: str, pending: dict[str, Any]
) -> tuple[Identity, dict[str, Any]]:
    """Validate the user access token before asserting group membership."""
    meta = pending["metadata"]
    with verification_step("OAuth authorization-code exchange"):
        async with AsyncOAuth2Client(
            parent.client_id,
            parent.client_secret.get_secret_value(),
            redirect_uri=callback,
            timeout=15,
            follow_redirects=False,
            trust_env=False,
        ) as oauth:
            token = await oauth.fetch_token(
                meta["token_endpoint"], code=code, code_verifier=pending["verifier"]
            )
        access_token = token.get("access_token")
        logger.info(
            "OAuth code exchange completed: %s",
            json.dumps(
                {
                    "access_token_received": isinstance(access_token, str) and bool(access_token),
                    "requested_scopes": list(LOGIN_SCOPES),
                    "scope_parameter_returned": "scope" in token,
                }
            ),
        )
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("The token endpoint did not return a usable access token")
    with verification_step("OAuth signing-key retrieval"):
        # The configured domain is trusted through TLS and discovery. Some domains require
        # this credential even to read signing keys. Never forward it to another origin.
        key_url = endpoint(meta["jwks_uri"], parent.domain.url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
            response = await client.get(
                key_url,
                headers={"Authorization": "Bearer " + access_token, "Accept": "application/json"},
            )
            logger.info("OAuth signing-key response status: %s", response.status_code)
            response.raise_for_status()
            keys = response.json()
    with verification_step("OAuth access-token verification"):
        claims = verify_user_access_token(
            access_token, keys, meta["issuer"], parent.client_id, parent.domain.url
        )
        _log_groups("verified_access_token", claims, parent, signature_verified=True)
        subject = str(claims["sub"])
        user_id = claims.get("user_id")
        attribute = (
            "id"
            if isinstance(user_id, str) and user_id
            else {"id": "id", "username": "userName", "ocid": "ocid"}.get(
                str(claims.get("sub_mappingattr") or "userName").casefold()
            )
        )
        if attribute not in {"id", "userName", "ocid"}:
            raise ValueError("Access-token subject mapping is unsupported")
        grant = {
            "access_token": str(token["access_token"]),
            "access_token_expires_at": float(claims["exp"]),
            "subject": subject,
            "assertion_attribute": attribute,
            "assertion_value": user_id if attribute == "id" and user_id else subject,
        }
    with verification_step("OAuth Asserter group authorization"):
        identity = await membership(parent, grant)
    return identity, grant


async def membership(parent: Parent, grant: dict[str, Any]) -> Identity:
    """Assert the verified access-token identity and current groups without scanner credentials."""
    assertion = grant.get("access_token")
    expires = grant.get("access_token_expires_at")
    attribute, value = grant.get("assertion_attribute"), grant.get("assertion_value")
    if (
        not isinstance(assertion, str)
        or not assertion
        or not isinstance(expires, (int, float))
        or not math.isfinite(expires)
        or expires <= time.time()
        or attribute not in {"id", "userName", "ocid"}
        or not isinstance(value, str)
        or not value
    ):
        raise ValueError("Human access-token authorization expired or unavailable; sign in again")
    async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
        response = await client.post(
            parent.domain.url + "/admin/v1/Asserter",
            params={"attributes": "id,userName,ocid,type,groups"},
            headers={
                "Authorization": "Bearer " + assertion,
                "Content-Type": "application/scim+json",
                "Accept": "application/scim+json",
            },
            json={
                "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:Asserter"],
                "subjectType": "user",
                "mappingAttribute": attribute,
                "mappingAttributeValue": value,
                "includeMemberships": True,
            },
        )
        logger.info("OAuth Asserter response status: %s", response.status_code)
        if response.status_code == 401:
            raise ValueError("Human authorization expired; sign in again")
        response.raise_for_status()
        user = response.json()
    actual = user.get(attribute) if isinstance(user, dict) else None
    bound = isinstance(actual, str) and (
        actual.casefold() == value.casefold() if attribute == "userName" else actual == value
    )
    if isinstance(user, dict):
        _log_groups("asserter", user, parent, subject_matches=bound)
    if (
        not isinstance(user, dict)
        or not user.get("id")
        or not bound
        or user.get("type", "User") != "User"
    ):
        raise ValueError("Asserter identity does not match the verified access token")
    entries = user.get("groups", [])
    if not isinstance(entries, list):
        raise ValueError("Asserter group membership is malformed")
    group_ids: set[str] = set()
    for group in entries:
        if not isinstance(group, dict) or not isinstance(group.get("value"), str):
            raise ValueError("Asserter group membership is malformed")
        group_ids.add(group["value"])
    groups = frozenset(
        name
        for name, group_id in (
            ("ogc_admin", parent.admin_group_id),
            ("ogc_viewer", parent.viewer_group_id),
        )
        if group_id and group_id in group_ids
    )
    logger.info("OAuth matched application groups: %s", json.dumps(sorted(groups)))
    identity = Identity(subject=grant["subject"], groups=groups)
    if not identity.allowed:
        raise ValueError("Membership of ogc_admin or ogc_viewer is required")
    return identity
