"""Authentication diagnostics expose group claims and failure steps, never bearer credentials."""

import asyncio
import logging
from unittest.mock import AsyncMock

import httpx
import pytest

from oci_governance_center.auth import oidc
from oci_governance_center.diagnostics import PublicFailure
from tests.unit.test_jwt_and_analysis import signed


def configure(
    parent, key, monkeypatch, *, user_groups, token_groups=None, scope=None, key_status=200
):
    parent = parent.model_copy(
        update={"admin_group_id": "synthetic-admin", "viewer_group_id": "synthetic-viewer"}
    )
    identity_token, keys = signed(
        key,
        iss=parent.domain.url,
        sub="synthetic-human",
        aud=parent.client_id,
        nonce="synthetic-nonce",
        user_id="synthetic-human-guid",
        **({"groups": token_groups} if token_groups is not None else {}),
    )
    access_token, keys = signed(
        key,
        iss=parent.domain.url,
        sub="synthetic-human",
        user_id="synthetic-human-guid",
        aud="https://identity.oraclecloud.com/",
        client_name=parent.client_id,
        sub_type="user",
        tok_type="AT",
        groups=["synthetic-admin"],
    )
    oauth = AsyncMock()
    oauth.__aenter__.return_value = oauth
    oauth.fetch_token.return_value = {
        "access_token": access_token,
    }
    if scope is not None:
        oauth.fetch_token.return_value["scope"] = scope
    monkeypatch.setattr(oidc, "AsyncOAuth2Client", lambda *args, **kwargs: oauth)

    def response(request):
        if request.url.path == "/jwks":
            if request.headers.get("Authorization") != "Bearer " + access_token:
                return httpx.Response(401, json={"detail": "synthetic-private-key-endpoint"})
            return httpx.Response(key_status, json=keys)
        assert request.url.path == "/admin/v1/Asserter"
        return httpx.Response(
            200,
            json={
                "id": "synthetic-human-guid",
                "userName": "synthetic-human",
                "type": "User",
                "groups": user_groups,
                "email": "must-not-log@example.test",
            },
        )

    original = httpx.AsyncClient
    monkeypatch.setattr(
        oidc.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(response), **kw),
    )
    pending = {
        "verifier": "synthetic-verifier",
        "nonce": "synthetic-nonce",
        "metadata": {
            "token_endpoint": parent.domain.url + "/oauth2/v1/token",
            "jwks_uri": parent.domain.url + "/jwks",
            "issuer": parent.domain.url,
            "asserter_endpoint": parent.domain.url + "/admin/v1/Asserter",
        },
    }
    return parent, pending, identity_token, access_token


def test_authentication_logs_group_claims_without_tokens(parent, key, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=oidc.__name__)
    parent, pending, identity_token, access_token = configure(
        parent,
        key,
        monkeypatch,
        user_groups=[{"value": "synthetic-admin", "display": "ogc_admin"}],
    )
    identity, _ = asyncio.run(
        oidc.finish(parent, "http://127.0.0.1:8000/auth/callback", "synthetic-code", pending)
    )
    assert identity.admin
    assert '"access_token_received": true' in caplog.text
    assert '"scope_parameter_returned": false' in caplog.text
    assert '"requested_scopes": ["urn:opc:idm:__myscopes__"]' in caplog.text
    assert "has_identity_token" not in caplog.text
    assert "verified_access_token" in caplog.text
    assert "asserter" in caplog.text
    assert "synthetic-admin" in caplog.text
    assert "ogc_admin" in caplog.text
    for sensitive in [
        identity_token,
        access_token,
        parent.client_secret.get_secret_value(),
        key,
        "synthetic-code",
        "synthetic-verifier",
        "synthetic-nonce",
        "must-not-log@example.test",
    ]:
        assert sensitive not in caplog.text


def test_missing_asserter_groups_logs_reason_before_authentication_fails(
    parent, key, monkeypatch, caplog
):
    caplog.set_level(logging.INFO)
    parent, pending, _, _ = configure(parent, key, monkeypatch, user_groups=[])
    with pytest.raises(PublicFailure):
        asyncio.run(
            oidc.finish(parent, "http://127.0.0.1:8000/auth/callback", "synthetic-code", pending)
        )
    assert "Asserter group authorization" in caplog.text
    assert "Membership of ogc_admin or ogc_viewer is required" in caplog.text
    assert '"group_count": 0' in caplog.text


def test_access_token_validation_failure_is_logged_without_token(parent, key, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    parent, pending, identity_token, access_token = configure(
        parent,
        key,
        monkeypatch,
        user_groups=[{"value": "synthetic-admin"}],
    )
    pending["metadata"]["issuer"] = "https://wrong-issuer.example"
    with pytest.raises(PublicFailure):
        asyncio.run(
            oidc.finish(parent, "http://127.0.0.1:8000/auth/callback", "synthetic-code", pending)
        )
    assert "OAuth access-token verification" in caplog.text
    assert "verified_access_token" not in caplog.text
    assert identity_token not in caplog.text and access_token not in caplog.text
    assert "wrong-nonce" not in caplog.text


def test_signing_key_denial_names_key_retrieval_stage(parent, key, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    parent, pending, _, access_token = configure(
        parent,
        key,
        monkeypatch,
        user_groups=[],
        key_status=401,
    )
    with pytest.raises(PublicFailure, match="OAuth signing-key retrieval"):
        asyncio.run(
            oidc.finish(parent, "http://127.0.0.1:8000/auth/callback", "synthetic-code", pending)
        )
    assert "OAuth signing-key response status: 401" in caplog.text
    assert "Asserter response status" not in caplog.text
    assert access_token not in caplog.text


def test_signing_key_origin_is_checked_before_forwarding_token(parent, key, monkeypatch):
    from unittest.mock import Mock

    parent, pending, _, _ = configure(parent, key, monkeypatch, user_groups=[])
    pending["metadata"]["jwks_uri"] = "https://untrusted.example/jwks"
    transport = Mock(side_effect=AssertionError("No request should be made"))
    monkeypatch.setattr(oidc.httpx, "AsyncClient", transport)
    with pytest.raises(PublicFailure, match="outside the configured identity domain"):
        asyncio.run(
            oidc.finish(parent, "http://127.0.0.1:8000/auth/callback", "synthetic-code", pending)
        )
    transport.assert_not_called()
