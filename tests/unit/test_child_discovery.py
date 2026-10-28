"""URL-only child verification discovers metadata with child credentials and exact username."""

from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest

from oci_governance_center.auth.scanner import Exchange, ScanAccessFailure
from oci_governance_center.diagnostics import PublicFailure
from oci_governance_center.models import Identity
from oci_governance_center.storage import StaleWork
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


@pytest.fixture
def discovery(parent, child, monkeypatch):
    exchange = Exchange(parent)
    signer = object()
    monkeypatch.setattr(exchange, "_exchange_child", Mock(return_value=(signer, 9999999999)))
    identity = Mock()
    identity.get_tenancy.return_value.data = NS(id=child.ocid)
    domain = NS(
        id=child.domain.domain_ocid,
        display_name="Default",
        home_region="eu-frankfurt-1",
        compartment_id=child.ocid,
        lifecycle_state="ACTIVE",
        url=child.domain.url,
    )
    user = NS(
        id="child-scim-id",
        ocid=child.user_ocid,
        user_name="ogc",
        active=True,
        urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user=NS(service_user=True),
    )
    region = NS(region_name="eu-frankfurt-1", is_home_region=True, status="READY")
    sources = {"regions": [region], "domains": [domain], "users": [user], "compartments": []}
    identity.list_region_subscriptions = "regions"
    identity.list_domains = "domains"
    identity.list_compartments = "compartments"
    domains = NS(list_users="users")
    calls = []

    def construct(kind, actual_signer, region, endpoint=None):
        assert actual_signer is signer
        calls.append((kind, region, endpoint))
        return domains if kind == "domains" else identity

    def items(method, *args, **kwargs):
        if method == "users":
            assert kwargs["filter"] == 'userName eq "ogc"'
            assert "ocid eq" not in kwargs["filter"]
            assert "serviceUser" in kwargs["attributes"]
        return sources[method]

    monkeypatch.setattr("oci_governance_center.auth.scanner.client", construct)
    monkeypatch.setattr("oci_governance_center.auth.scanner.all_items", items)
    bind = Mock()
    monkeypatch.setattr("oci_governance_center.auth.scanner.bind_identity", bind)
    yield exchange, sources, calls, bind, signer
    exchange.close()


def test_discovers_domain_home_region_and_service_user(child, discovery):
    exchange, sources, calls, bind, signer = discovery
    domain, user_ocid = exchange.discover_child(child.ocid, child.domain.url)
    assert domain.domain_ocid == child.domain.domain_ocid
    assert domain.guid == child.domain.guid
    assert domain.home_region == "eu-frankfurt-1"
    assert user_ocid == child.user_ocid
    assert ("domains", "eu-frankfurt-1", child.domain.url) in calls
    bind.assert_called_once_with(signer, domain, child.user_ocid)


@pytest.mark.parametrize(
    "failure",
    [
        "missing-user",
        "duplicate-user",
        "wrong-name",
        "inactive-user",
        "ordinary-user",
        "missing-ocid",
        "wrong-domain",
        "inactive-domain",
        "wrong-tenancy",
        "missing-home-region",
    ],
)
def test_discovery_rejects_invalid_child_artifacts(child, discovery, failure):
    exchange, sources, calls, bind, signer = discovery
    if failure == "missing-user":
        sources["users"] = []
    elif failure == "duplicate-user":
        sources["users"] *= 2
    elif failure == "wrong-name":
        sources["users"][0].user_name = "other"
    elif failure == "inactive-user":
        sources["users"][0].active = False
    elif failure == "ordinary-user":
        sources["users"][
            0
        ].urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user.service_user = False
    elif failure == "missing-ocid":
        sources["users"][0].ocid = None
    elif failure == "wrong-domain":
        sources["domains"][0].url = "https://idcs-" + "c" * 32 + ".identity.oraclecloud.com"
    elif failure == "inactive-domain":
        sources["domains"][0].lifecycle_state = "INACTIVE"
    elif failure == "wrong-tenancy":
        sources["domains"][0].compartment_id = "ocid1.tenancy.oc1..wrong"
    else:
        sources["regions"] = []
    with pytest.raises(PublicFailure):
        exchange.discover_child(child.ocid, child.domain.url)
    bind.assert_not_called()


def test_untrusted_url_is_rejected_before_exchange(discovery, child):
    exchange, *_ = discovery
    with pytest.raises(ValueError):
        exchange.discover_child(child.ocid, "https://evil.example")
    exchange._exchange_child.assert_not_called()


def test_configure_persists_only_verified_discovery(service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    exchange = Mock()
    exchange.discover_child.return_value = (child.domain, child.user_ocid)
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: exchange)
    configured = service.configure_child(
        child.ocid, child.domain.url, generation, "child-client", "synthetic-child-secret"
    )
    exchange.discover_child.assert_called_once_with(child.ocid, child.domain.url)
    exchange.close.assert_called_once()
    assert configured.domain == child.domain and configured.user_ocid == child.user_ocid
    assert configured.status == "active" and configured.revision == child.revision + 1
    exchange.discover_child.side_effect = ScanAccessFailure("missing service user")
    with pytest.raises(ScanAccessFailure):
        service.configure_child(
            child.ocid, child.domain.url, generation, "child-client", "synthetic-child-secret"
        )
    assert service.store.children(generation)[0] == configured


def test_configuration_changed_during_discovery_is_fenced(service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    exchange = Mock()

    def discover(*args):
        service.pause(child.ocid, generation)
        return child.domain, child.user_ocid

    exchange.discover_child.side_effect = discover
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: exchange)
    with pytest.raises(StaleWork):
        service.configure_child(
            child.ocid, child.domain.url, generation, "child-client", "synthetic-child-secret"
        )
    assert service.store.children(generation)[0].status == "paused"


def test_child_form_and_post_need_only_url(settings, service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(
            return_value=Identity(subject="synthetic-human", groups=frozenset({"ogc_admin"}))
        ),
    )
    exchange = Mock()
    exchange.discover_child.return_value = (child.domain, child.user_ocid)
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: exchange)
    page = client.get("/children/" + child.ocid)
    assert page.status_code == 200
    assert 'name="url"' in page.text
    for field in ("guid", "domain_ocid", "home_region", "user_ocid", "tenancy_ocid"):
        assert f'name="{field}"' not in page.text
    response = client.post(
        "/children/" + child.ocid + "/configure",
        data={
            "csrf": "synthetic-csrf",
            "url": child.domain.url,
            "client_id": "child-client",
            "client_secret": "synthetic-child-secret",
        },
    )
    assert response.status_code == 303
    exchange.discover_child.assert_called_once_with(child.ocid, child.domain.url)
    page = client.get("/children/" + child.ocid)
    assert 'name="client_id"' in page.text and 'value="child-client"' in page.text
    assert 'name="client_secret" type="password"' in page.text
    assert "synthetic-child-secret" not in page.text
    assert "Leave blank to retain" in page.text


def test_child_scanner_domain_can_be_non_default_in_another_region(child, discovery):
    exchange, sources, calls, bind, signer = discovery
    sources["domains"][0].display_name = "Automation"
    sources["domains"][0].home_region = "uk-london-1"
    domain, user = exchange.discover_child(child.ocid, child.domain.url)
    assert domain.home_region == "eu-frankfurt-1"
    assert domain.region == "uk-london-1"
    assert ("domains", "uk-london-1", child.domain.url) in calls
    bind.assert_called_once_with(signer, domain, user)
