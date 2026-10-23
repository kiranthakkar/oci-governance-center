"""Scanner separation, identity binding and read-only SDK enforcement."""

from types import SimpleNamespace as NS
from unittest.mock import Mock

import oci
import pytest

from oci_governance_center.auth.oidc import endpoint
from oci_governance_center.auth.scanner import (
    Exchange,
    ScanAccessFailure,
    api_signer,
    bind_identity,
)
from oci_governance_center.models import domain_origin
from oci_governance_center.oci_clients import OPERATIONS, ReadOnlyClient, all_items


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost",
        "https://example.com",
        "https://127.0.0.1",
        "https://idcs-" + "a" * 32 + ".identity.oraclecloud.com@evil.test",
        "https://idcs-" + "a" * 32 + ".identity.oraclecloud.com/path",
    ],
)
def test_domain_rejects_arbitrary_endpoints(value):
    with pytest.raises(ValueError):
        domain_origin(value)


def test_oidc_discovery_blocks_cross_origin_and_credentials(domain):
    assert endpoint(domain.url + "/oauth2/v1/token", domain.url).endswith("/token")
    assert endpoint(domain.url + ":443/oauth2/v1/token", domain.url)
    with pytest.raises(ValueError):
        endpoint("https://evil.test/oauth2/v1/token", domain.url)


def test_scanner_exchange_has_signature_auth_and_no_client_credentials(parent, monkeypatch):
    transport = Mock()
    transport.post.return_value.status_code = 200
    transport.post.return_value.json.return_value = {"access_token": "synthetic-token"}
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    exchange = Exchange(parent)
    exchange._post(parent.domain, {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange"})
    kwargs = transport.post.call_args.kwargs
    assert isinstance(kwargs["auth"], oci.signer.Signer)
    assert "client_id" not in kwargs["data"] and "client_secret" not in kwargs["data"]
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == (10, 30)
    assert parent.client_secret.get_secret_value() not in str(transport.post.call_args)


def test_wrong_parent_private_key_fingerprint_is_rejected(parent):
    with pytest.raises(ValueError):
        api_signer(parent.model_copy(update={"fingerprint": "00:" * 15 + "00"}))


def test_binding_rejects_wrong_owning_tenancy(parent, monkeypatch):
    identity = Mock()
    identity.get_tenancy.return_value.data = NS(id=parent.domain.tenancy_ocid)
    identity.get_user.return_value.data = NS(
        id=parent.user_ocid, compartment_id="ocid1.tenancy.oc1..aaaawrong", lifecycle_state="ACTIVE"
    )
    identity.get_domain.return_value.data = NS(
        display_name="Default",
        compartment_id=parent.domain.tenancy_ocid,
        url=parent.domain.url,
        lifecycle_state="ACTIVE",
    )
    monkeypatch.setattr("oci_governance_center.auth.scanner.client", lambda *_: identity)
    with pytest.raises(ScanAccessFailure):
        bind_identity(object(), parent.domain, parent.user_ocid)


def test_read_only_boundary_blocks_aliases_getattr_and_wrapped_client():
    raw = Mock()
    wrapped = ReadOnlyClient(raw, OPERATIONS["identity"])
    wrapped.get_tenancy("synthetic")
    raw.get_tenancy.assert_called_once_with("synthetic")
    for forbidden in (
        "create_user",
        "delete_user",
        "update_user",
        "base_client",
        "_client",
        "__dict__",
        "call_api",
    ):
        with pytest.raises(AttributeError):
            getattr(wrapped, forbidden)
    with pytest.raises(AttributeError):
        wrapped._client = raw
    assert all(
        name.startswith(("get_", "list_", "search_", "summarize_"))
        for names in OPERATIONS.values()
        for name in names
    )


def test_scim_multiple_pages_use_sdk_paginator_without_losing_resources():
    calls = []

    def list_users(**kwargs):
        calls.append(kwargs["start_index"])
        start = kwargs["start_index"]
        resources = [NS(id=str(start))]
        return oci.response.Response(
            200, {}, NS(resources=resources, total_results=2, start_index=start), NS()
        )

    assert [u.id for u in all_items(list_users)] == ["1", "2"]
    assert calls == [1, 2]


def test_scim_nonprogress_fails_instead_of_publishing_empty():
    def list_users(**kwargs):
        return oci.response.Response(
            200, {}, NS(resources=[], total_results=2, start_index=1), NS()
        )

    with pytest.raises(ValueError, match="no progress"):
        all_items(list_users)


def test_real_sdk_clients_construct_with_api_signer_without_config_files(parent):
    from oci_governance_center.oci_clients import client

    signer = api_signer(parent)
    for kind, operations in OPERATIONS.items():
        wrapped = client(
            kind,
            signer,
            parent.domain.home_region,
            parent.domain.url if kind == "domains" else None,
        )
        assert callable(getattr(wrapped, sorted(operations)[0]))


def test_child_signer_renews_before_expiry_and_rebinds_via_supplier(key, monkeypatch):
    import time

    from oci_governance_center.auth.scanner import RefreshingSigner

    signer = Mock()
    signer.api_key = "ST$synthetic-token"
    from cryptography.hazmat.primitives import serialization

    signer.private_key = serialization.load_pem_private_key(key.encode(), password=None)
    supplier = Mock(side_effect=[(signer, time.time() + 3600), (signer, time.time() + 7200)])
    refreshing = RefreshingSigner(supplier)
    refreshing._expiry = time.time() + 10
    refreshing(Mock())
    assert supplier.call_count == 2
    signer.assert_called_once()


def test_scim_repeated_page_is_rejected():
    def list_users(**kwargs):
        return oci.response.Response(
            200, {}, NS(resources=[NS(id="one")], total_results=2, start_index=1), NS()
        )

    with pytest.raises(ValueError, match="repeated"):
        all_items(list_users)
