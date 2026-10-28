"""Scanner domains can be non-default and regional without weakening ownership checks."""

from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from oci_governance_center.auth.scanner import bind_identity, verify_parent
from oci_governance_center.diagnostics import PublicFailure
from oci_governance_center.models import Domain
from oci_governance_center.provisioning.bundle import terraform


@pytest.fixture
def selected(parent, monkeypatch):
    domain = parent.domain.model_copy(update={"region": "eu-frankfurt-1"})
    metadata = NS(
        id=domain.domain_ocid,
        compartment_id=domain.tenancy_ocid,
        url=domain.url,
        lifecycle_state="ACTIVE",
        home_region=domain.region,
        display_name="Engineering",
        type="SECONDARY",
    )
    user = NS(
        id="selected-ogc",
        ocid=parent.user_ocid,
        user_name="ogc",
        active=True,
        domain_ocid=domain.domain_ocid,
        tenancy_ocid=domain.tenancy_ocid,
    )
    groups = [
        NS(id=name, display_name=name, members=[NS(value=user.id)])
        for name in ("ogc_scanner", "ogc_admin", "ogc_viewer")
    ]
    identity = Mock()
    identity.get_tenancy.return_value.data = NS(id=domain.tenancy_ocid)
    identity.get_domain.return_value.data = metadata
    identity.get_user.side_effect = AssertionError("Legacy GetUser must not be used")
    identity.list_compartments = lambda *a, **k: []
    queries = []

    def list_users(**kwargs):
        queries.append(kwargs)
        return [user]

    domains = NS(list_users=list_users, list_groups=lambda **kwargs: groups)
    calls = []

    def client(kind, signer, region, endpoint=None):
        calls.append((kind, region, endpoint))
        return domains if kind == "domains" else identity

    monkeypatch.setattr("oci_governance_center.auth.scanner.client", client)
    monkeypatch.setattr(
        "oci_governance_center.auth.scanner.all_items", lambda method, *a, **k: method(*a, **k)
    )
    return domain, metadata, user, calls, identity, queries


def test_non_default_cross_region_parent_verifies_using_scim(parent, selected):
    domain, metadata, user, calls, identity, queries = selected
    verified = verify_parent(parent.model_copy(update={"domain": domain}))
    assert verified.domain.home_region == parent.domain.home_region
    assert verified.domain.identity_region == "eu-frankfurt-1"
    assert ("domains", "eu-frankfurt-1", domain.url) in calls
    assert ("identity", parent.domain.home_region, None) in calls
    assert verified.admin_group_id == "ogc_admin"
    assert all(q["filter"] == f'ocid eq "{parent.user_ocid}"' for q in queries)
    identity.get_user.assert_not_called()


def test_domain_region_is_discovered_when_not_entered(parent, selected):
    domain, *_ = selected
    verified = verify_parent(parent)
    assert verified.domain.region == domain.region


@pytest.mark.parametrize("problem", ["domain", "tenancy", "region", "inactive", "url", "domain-id"])
def test_selected_domain_binding_rejects_mismatches(parent, selected, problem):
    domain, metadata, user, *_ = selected
    if problem == "domain":
        user.domain_ocid = "ocid1.domain.oc1..foreign"
    elif problem == "tenancy":
        user.tenancy_ocid = "ocid1.tenancy.oc1..foreign"
    elif problem == "region":
        metadata.home_region = "uk-london-1"
    elif problem == "inactive":
        user.active = False
    elif problem == "url":
        metadata.url = "https://idcs-" + "c" * 32 + ".identity.oraclecloud.com"
    else:
        metadata.id = "ocid1.domain.oc1..foreign"
    with pytest.raises(PublicFailure):
        bind_identity(object(), domain, parent.user_ocid)


def test_compartment_hosted_domain_is_verified_against_tenancy(parent, selected):
    domain, metadata, user, calls, identity, queries = selected
    metadata.compartment_id = "ocid1.compartment.oc1..selected"
    identity.list_compartments = lambda *a, **k: [NS(id=metadata.compartment_id)]
    bind_identity(object(), domain, parent.user_ocid)


def test_legacy_domain_records_keep_region_fallback(parent):
    stored = parent.domain.model_dump(exclude={"region"})
    domain = Domain.model_validate(stored)
    assert domain.region == "" and domain.identity_region == domain.home_region


@pytest.mark.parametrize("kind", ["parent", "child"])
def test_terraform_scanner_policy_targets_created_group_not_default_domain(kind):
    config = terraform(kind)
    statements = config["resource"]["oci_identity_policy"]["scanner"]["statements"]
    assert all("group id ${oci_identity_domains_group.scanner.ocid}" in s for s in statements)
    condition = config["resource"]["oci_identity_domains_user"]["scanner"]["lifecycle"][
        "precondition"
    ][0]["condition"]
    assert "display_name" not in condition
    assert "oci_identity_compartments.tenancy.compartments" in condition
    if kind == "parent":
        key = config["resource"]["oci_identity_domains_api_key"]["scanner"]
        assert key["user"][0]["value"] == "${oci_identity_domains_user.scanner.id}"
        assert "oci_identity_api_key" not in config["resource"]


def test_parent_setup_records_separate_domain_region(settings, service, parent):
    from tests.unit.test_web import COOKIE, browser, csrf

    client = browser(settings, service)
    token = csrf(client.get("/setup"))
    client.post(
        "/setup/unlock",
        data={
            "csrf": token,
            "password": settings.setup_password.get_secret_value(),
        },
    )
    response = client.post(
        "/setup/metadata",
        data={
            "csrf": csrf(client.get("/setup")),
            "name": parent.name,
            **parent.domain.model_dump(),
            "region": "eu-frankfurt-1",
        },
    )
    assert response.status_code == 200
    draft = service.store.session(client.cookies.get(COOKIE))["setup_metadata"]["domain"]
    assert draft["home_region"] == parent.domain.home_region
    assert draft["region"] == "eu-frankfurt-1"
