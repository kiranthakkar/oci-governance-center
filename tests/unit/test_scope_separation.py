"""Human login and scanner assertion issuance use distinct, fixed scopes."""

from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest

from oci_governance_center.auth import oidc
from oci_governance_center.auth.scanner import Exchange
from oci_governance_center.models import Parent
from oci_governance_center.provisioning.bundle import terraform

SCANNER_SCOPE = "urn:opc:idm:__myscopes__"


def test_authorization_url_requests_human_identity_scopes(parent, monkeypatch):
    import asyncio

    monkeypatch.setattr(
        oidc,
        "metadata",
        AsyncMock(
            return_value={
                "authorization_endpoint": parent.domain.url + "/oauth2/v1/authorize",
            }
        ),
    )
    url, pending = asyncio.run(oidc.begin(parent, "http://127.0.0.1:8000/auth/callback"))
    params = parse_qs(urlsplit(url).query)
    assert params["scope"] == ["urn:opc:idm:__myscopes__"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["state"] == [pending["state"]]
    assert "nonce" not in params
    assert "nonce" not in pending


def test_parent_scanner_assertion_requests_fixed_myscopes_even_with_old_settings(
    parent, monkeypatch
):
    # Stop after inspecting the outbound exchange, before any response verification reads.
    class ObservedExchange(Exception):
        pass

    def inspect_post(domain, data):
        assert domain == parent.domain
        assert data["scope"] == SCANNER_SCOPE
        assert "client_id" not in data and "client_secret" not in data
        raise ObservedExchange

    old = parent.model_copy(update={"exchange_scope": "urn:opc:resource:consumer::all"})
    exchange = Exchange(old)
    monkeypatch.setattr(exchange, "_post", inspect_post)
    with pytest.raises(ObservedExchange):
        exchange.parent_jwt()
    exchange.close()


def test_saved_parent_settings_normalize_the_legacy_scope(parent):
    saved = parent.model_dump()
    saved["exchange_scope"] = "urn:opc:resource:consumer::all"
    assert Parent.model_validate(saved).exchange_scope == SCANNER_SCOPE


def test_login_terraform_allows_human_identity_scopes():
    login = terraform("parent")["resource"]["oci_identity_domains_app"]["login"]
    assert login["allowed_scopes"] == [{"fqs": s} for s in ("urn:opc:idm:__myscopes__",)]
