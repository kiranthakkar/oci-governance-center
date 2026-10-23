"""Parent API-key issuance and child confidential-client UPST exchange; no child API keys."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import oci
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..diagnostics import PublicFailure, verification_step
from ..models import PARENT_EXCHANGE_SCOPE, ChildCredentials, Domain, Parent, domain_origin
from ..oci_clients import all_items, client
from .tokens import verify_jwt

logger = logging.getLogger(__name__)


class ScanAccessFailure(PublicFailure):
    """An access/trust/identity check failed; no resource response is exposed."""


def fingerprint(private_key: str) -> str:
    """Compute the OCI public-key fingerprint without exposing private material."""
    key = serialization.load_pem_private_key(private_key.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("Use an unencrypted RSA API private key of at least 2048 bits")
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.md5(public, usedforsecurity=False).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def api_signer(parent: Parent) -> Any:
    """Use the official SDK signer for the registered parent API key only."""
    key = parent.private_key.get_secret_value()
    if fingerprint(key) != parent.fingerprint:
        raise ValueError("API public-key fingerprint does not match private key")
    return oci.signer.Signer(
        tenancy=parent.domain.tenancy_ocid,
        user=parent.user_ocid,
        fingerprint=parent.fingerprint,
        private_key_file_location=None,
        private_key_content=key,
    )


def bind_identity(signer: Any, domain: Domain, expected_user: str) -> None:
    """Verify GetTenancy/GetUser/GetDomain ownership; requires read tenancies/users/domains."""
    with verification_step("default-domain metadata validation"):
        domain.check_guid()
    with verification_step("IAM client initialization"):
        identity = client("identity", signer, domain.home_region)
    with verification_step("GetTenancy (parent/child tenancy access)"):
        tenancy = identity.get_tenancy(domain.tenancy_ocid).data
    with verification_step("GetUser (scanner identity access)"):
        user = identity.get_user(expected_user).data
    with verification_step("GetDomain (default identity-domain access)"):
        actual = identity.get_domain(domain.domain_ocid).data
    checks = (
        (
            tenancy.id == domain.tenancy_ocid,
            "The returned tenancy does not match the configured tenancy.",
        ),
        (
            user.id == expected_user,
            "The returned scanner user does not match the configured user OCID.",
        ),
        (
            user.compartment_id == domain.tenancy_ocid,
            "The scanner user belongs to a different tenancy.",
        ),
        (user.lifecycle_state == "ACTIVE", "The scanner user is not active."),
        (
            actual.display_name == "Default",
            "The configured identity domain is not the Default domain.",
        ),
        (
            actual.compartment_id == domain.tenancy_ocid,
            "The identity domain belongs to a different tenancy.",
        ),
        (
            domain_origin(actual.url) == domain.url,
            "The configured domain URL does not match GetDomain.",
        ),
        (actual.lifecycle_state == "ACTIVE", "The configured identity domain is not active."),
    )
    for passed, explanation in checks:
        if not passed:
            raise ScanAccessFailure(explanation)


def verify_parent(parent: Parent) -> Parent:
    """Verify key ownership/default-domain metadata and exact app group IDs via read-only APIs."""
    with verification_step("API-key validation (unencrypted RSA PEM private key)"):
        signer = api_signer(parent)
    bind_identity(signer, parent.domain, parent.user_ocid)
    with verification_step("identity-domain client initialization"):
        domains = client("domains", signer, parent.domain.home_region, parent.domain.url)
    with verification_step("identity-domain ListUsers (find the ogc scanner user)"):
        users = all_items(
            domains.list_users,
            filter=f'ocid eq "{parent.user_ocid}"',
            attributes="id,ocid,userName,groups",
        )
        if len(users) != 1 or users[0].user_name != "ogc":
            raise ScanAccessFailure("Parent API key must belong to the default-domain ogc user")
    with verification_step("identity-domain ListGroups (OGC groups and scanner membership)"):
        groups = all_items(
            domains.list_groups,
            filter=(
                'displayName eq "ogc_admin" or displayName eq "ogc_viewer" '
                'or displayName eq "ogc_scanner"'
            ),
            attributes="id,ocid,displayName,members",
        )
        named = {g.display_name: g for g in groups}
        if len(named) != len(groups):
            raise ScanAccessFailure("OGC group names are ambiguous")
        if not all(name in named for name in ("ogc_admin", "ogc_viewer", "ogc_scanner")):
            raise ScanAccessFailure(
                "Required ogc_admin, ogc_viewer, or ogc_scanner group is missing"
            )
        members = named["ogc_scanner"].members or []
        if not any(m.value == users[0].id for m in members):
            raise ScanAccessFailure("ogc must belong to ogc_scanner")
    return parent.model_copy(
        update={"admin_group_id": named["ogc_admin"].id, "viewer_group_id": named["ogc_viewer"].id}
    )


class Exchange:
    """Per-worker, short-lived WIF credentials; use a new exchange before each collection unit."""

    def __init__(
        self,
        parent: Parent,
        credentials: ChildCredentials | None = None,
    ) -> None:
        self.parent = parent
        self.credentials = credentials
        self.signer = api_signer(parent)
        self.http = requests.Session()
        self.http.trust_env = False

    def _post(self, domain: Domain | str, data: dict[str, str]) -> dict[str, Any]:
        child_exchange = data.get("requested_token_type") == "urn:oci:token-type:oci-upst"
        auth: Any = self.signer
        stage = "parent_api_key_to_jwt"
        if child_exchange:
            if self.credentials is None:
                raise ScanAccessFailure(
                    "Configure the child confidential application's client ID and secret first"
                )
            auth = requests.auth.HTTPBasicAuth(
                self.credentials.client_id, self.credentials.client_secret.get_secret_value()
            )
            stage = "child_jwt_to_upst"
        assertion = data.get("subject_token")
        fingerprint = hashlib.sha256(assertion.encode()).hexdigest()[:12] if assertion else "none"
        logger.info(
            "Token exchange started: stage=%s, authentication=%s, subject_token_sha256=%s",
            stage,
            "confidential_client_basic" if child_exchange else "parent_api_key_signature",
            fingerprint,
        )
        response = self.http.post(
            (domain.url if isinstance(domain, Domain) else domain_origin(domain))
            + "/oauth2/v1/token",
            data=data,
            auth=auth,
            timeout=(10, 30),
            allow_redirects=False,
        )
        logger.info("Token exchange response: stage=%s, status=%s", stage, response.status_code)
        if response.status_code != 200:
            # Only authored explanations and recognized OAuth codes reach the UI/logs.
            # Never expose response descriptions: they can echo subject tokens or secrets.
            message = f"Token exchange rejected (HTTP {response.status_code})"
            try:
                body = response.json()
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}
            code = body.get("error")
            hints = {
                "invalid_client": "The identity domain rejected caller authentication.",
                "unauthorized_client": (
                    "The exchange caller is not authorized; check the trust's OAuth client binding "
                    "and that its client ID matches the configured child application."
                ),
                "invalid_grant": (
                    "Check the trust issuer, signing keys, exact parent subject rule "
                    "and mapped child service user."
                ),
                "invalid_request": "Check the token exchange parameters and public-key format.",
                "invalid_scope": "The identity domain rejected the requested scope.",
                "unsupported_grant_type": "The identity domain rejected the token-exchange grant.",
                "access_denied": "The identity domain denied token exchange access.",
                "server_error": "The identity-domain token service encountered an error.",
                "temporarily_unavailable": "The identity-domain token service is unavailable.",
            }
            if isinstance(code, str) and code in hints:
                message += f"; OAuth error: {code}. {hints[code]}"
            else:
                message += "; no recognized OAuth error code was returned."
            description = body.get("error_description")
            # Categorize known failure terms, without displaying server-provided text.
            if isinstance(description, str):
                text = description.casefold()
                categories = (
                    (
                        ("impersonat", "mapping", "subject"),
                        "OCI referenced subject mapping or impersonation; compare the trust rule "
                        "with the parent's issued JWT subject.",
                    ),
                    (
                        ("issuer", "trust"),
                        "OCI referenced issuer or trust configuration; verify the active trust.",
                    ),
                    (
                        ("public_key", "public key"),
                        "OCI referenced the supplied UPST public key; check its encoding.",
                    ),
                    (
                        ("signature", "signing", "certificate"),
                        "OCI referenced signature verification; "
                        "check the parent JWKS and caller signing.",
                    ),
                    (
                        ("client",),
                        "OCI referenced client authorization; the child app's trust binding alone "
                        "must include the configured confidential application's client ID.",
                    ),
                )
                for markers, hint in categories:
                    if any(marker in text for marker in markers):
                        message += " " + hint
                        break
            request_id = response.headers.get("opc-request-id")
            if isinstance(request_id, str) and re.fullmatch(r"[A-Za-z0-9_./:-]{1,200}", request_id):
                message += f" Request ID: {request_id}."
            logger.warning("%s", message)
            raise ScanAccessFailure(message)
        result: dict[str, Any] = response.json()
        return result

    def parent_jwt(self) -> str:
        """API-key-to-JWT signed request per Oracle's two-legged exchange example."""
        data = self._post(
            self.parent.domain,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": PARENT_EXCHANGE_SCOPE,
            },
        )
        token = str(data.get("access_token", ""))
        if not token:
            raise ScanAccessFailure("Parent exchange did not return an access token")
        # Use the parent's public signing-key endpoint, never key URLs from token headers.
        response = self.http.get(
            self.parent.domain.url + "/admin/v1/SigningCert/jwk",
            timeout=(10, 30),
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise ScanAccessFailure("Parent assertion verification keys unavailable")
        discovery = self.http.get(
            self.parent.domain.url + "/.well-known/openid-configuration",
            timeout=(10, 30),
            allow_redirects=False,
        )
        if discovery.status_code != 200:
            raise ScanAccessFailure("Parent issuer metadata unavailable")
        expected_issuer = discovery.json().get("issuer")
        if not expected_issuer:
            raise ScanAccessFailure("Parent domain has no issuer metadata")
        claims = verify_jwt(token, response.json(), str(expected_issuer))
        # Resolve the scanner through the configured OCID, never through token-controlled filters.
        domains = client(
            "domains", self.signer, self.parent.domain.home_region, self.parent.domain.url
        )
        users = all_items(
            domains.list_users,
            filter=f'ocid eq "{self.parent.user_ocid}"',
            attributes="id,ocid,userName",
        )
        if len(users) != 1 or users[0].ocid != self.parent.user_ocid or users[0].user_name != "ogc":
            raise ScanAccessFailure(
                "Parent scanner lookup did not identify the configured ogc user"
            )
        user = users[0]
        mapping = claims.get("sub_mappingattr")
        expected = {"id": user.id, "ocid": user.ocid, "username": user.user_name}
        if mapping is None:
            subject_matches = claims["sub"] in expected.values()
        else:
            subject_matches = (
                isinstance(mapping, str)
                and mapping.casefold() in expected
                and claims["sub"] == expected[mapping.casefold()]
            )
        identity_matches = (
            subject_matches
            and claims.get("sub_type", "user") == "user"
            and ("user_id" not in claims or claims["user_id"] == user.id)
        )
        # Log only verification outcomes: no token, subject, key or other credential material.
        logger.info(
            "Parent assertion identity verification: subject_matches=%s, "
            "user_id_present=%s, identity_matches=%s",
            subject_matches,
            "user_id" in claims,
            identity_matches,
        )
        if not identity_matches:
            raise ScanAccessFailure(
                "Parent assertion principal does not match ogc; "
                "check subject mapping, user identity and subject type"
            )
        return token

    def _exchange_child(self, url: str) -> tuple[Any, float]:
        """Obtain a short-lived signer before discovering the child's IAM metadata."""
        url = domain_origin(url)
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        result = self._post(
            url,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:oci:token-type:oci-upst",
                "subject_token_type": "jwt",
                "subject_token": self.parent_jwt(),
                "public_key": base64.b64encode(public).decode(),
            },
        )
        token = str(result.get("token", ""))
        if not token:
            raise ScanAccessFailure("Child exchange did not return an OCI security token")
        signer = oci.auth.signers.SecurityTokenSigner(token, private)
        # The payload is used only for scheduling renewal. Callers authenticate the signer
        # with OCI reads before accepting it; unverified claims never establish identity.
        try:
            payload = token.split(".")[1]
            expiry = float(
                json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"]
            )
        except (ValueError, IndexError, KeyError) as error:
            raise ScanAccessFailure("Child token has no usable expiration") from error
        if expiry <= time.time() + 60:
            raise ScanAccessFailure("Child token expires too soon")
        return signer, expiry

    def _issue_child(self, domain: Domain, expected_user: str) -> tuple[Any, float]:
        """Renew a configured child's signer and revalidate its saved identity."""
        domain.check_guid()
        signer, expiry = self._exchange_child(domain.url)
        bind_identity(signer, domain, expected_user)
        return signer, expiry

    def discover_child(self, tenancy_ocid: str, url: str) -> tuple[Domain, str]:
        """Discover child metadata with its UPST; look up ogc by username, never manual OCID."""
        url = domain_origin(url)
        with verification_step("child token exchange"):
            signer, _ = self._exchange_child(url)
        with verification_step("child tenancy and home-region discovery"):
            # This endpoint is only a bootstrap route. Never persist the parent's region as
            # the child's home region: use the child's returned region subscriptions instead.
            bootstrap = client("identity", signer, self.parent.domain.home_region)
            tenancy = bootstrap.get_tenancy(tenancy_ocid).data
            if tenancy.id != tenancy_ocid:
                raise ScanAccessFailure("The returned tenancy does not match the selected child")
            regions = all_items(bootstrap.list_region_subscriptions, tenancy_ocid)
            home = [r for r in regions if r.is_home_region and r.status == "READY"]
            if len(home) != 1:
                raise ScanAccessFailure("Could not identify one active child home region")
            region = home[0].region_name
        with verification_step("child default-domain discovery"):
            identity = client("identity", signer, region)
            matches = [
                d
                for d in all_items(identity.list_domains, tenancy_ocid)
                if d.display_name == "Default"
                and d.compartment_id == tenancy_ocid
                and d.lifecycle_state == "ACTIVE"
                and domain_origin(d.url) == url
            ]
            if len(matches) != 1:
                raise ScanAccessFailure(
                    "The supplied URL does not identify the selected child's active Default domain"
                )
            domain = Domain(
                tenancy_ocid=tenancy_ocid,
                domain_ocid=matches[0].id,
                guid=str(urlsplit(url).hostname).removeprefix("idcs-").split(".")[0],
                url=url,
                home_region=region,
            )
        with verification_step("child identity-domain lookup (ogc service user)"):
            domains = client("domains", signer, region, url)
            users = all_items(
                domains.list_users,
                filter='userName eq "ogc"',
                attributes=(
                    "id,ocid,userName,active,"
                    "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User:serviceUser"
                ),
            )
            if len(users) != 1 or users[0].user_name != "ogc":
                raise ScanAccessFailure("Expected exactly one ogc user in the child Default domain")
            user = users[0]
            extension = user.urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user
            if not user.active or extension is None or extension.service_user is not True:
                raise ScanAccessFailure("The child ogc identity must be an active service user")
            if not isinstance(user.ocid, str) or not user.ocid.startswith("ocid1.user."):
                raise ScanAccessFailure("The child ogc service user has no usable user OCID")
        bind_identity(signer, domain, user.ocid)
        return domain, user.ocid

    def child_signer(self, domain: Domain, expected_user: str) -> Any:
        """Return a worker-local SDK signer that renews and rebinds before token expiration."""
        return RefreshingSigner(lambda: self._issue_child(domain, expected_user))

    def close(self) -> None:
        """Release the worker's transport and in-memory token state."""
        self.http.close()


class RefreshingSigner(oci.auth.signers.SecurityTokenSigner):  # type: ignore[misc]
    """Renew child UPST through its credential supplier, forwarding SDK signing."""

    def __init__(self, supplier: Callable[[], tuple[Any, float]]) -> None:
        self._supplier = supplier
        self._current, self._expiry = supplier()
        self._lock = threading.Lock()
        super().__init__(self._current.api_key.removeprefix("ST$"), self._current.private_key)

    def __call__(self, request: Any, enforce_content_headers: bool = True) -> Any:
        with self._lock:
            if time.time() + 60 >= self._expiry:
                self._current, self._expiry = self._supplier()
            return self._current(request, enforce_content_headers=enforce_content_headers)
