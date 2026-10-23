"""Organization ownership is verified independently of parent rows in member listings."""

from datetime import UTC, datetime

import oci
import pytest

from oci_governance_center.collectors.inventory import discover
from oci_governance_center.diagnostics import PublicFailure

MODEL = oci.tenant_manager_control_plane.models
ORG = "ocid1.organization.oc1..aaaafakeorg"
OTHER = "ocid1.tenancy.oc1..aaaafakeother"
CHILD = "ocid1.tenancy.oc1..aaaafakechild"


def member(tenancy=CHILD, role="CHILD", **kwargs):
    return MODEL.OrganizationTenancySummary(
        tenancy_id=tenancy,
        name="Synthetic tenancy",
        role=role,
        lifecycle_state=kwargs.pop("lifecycle_state", "ACTIVE"),
        **kwargs,
    )


def configure(monkeypatch, organizations, members):
    calls = []

    class OrganizationClient:
        def list_organizations(self, compartment_id):
            return oci.response.Response(
                200, {}, MODEL.OrganizationCollection(items=organizations), None
            )

        def list_organization_tenancies(self, organization_id):
            calls.append(organization_id)
            return oci.response.Response(
                200, {}, MODEL.OrganizationTenancyCollection(items=members), None
            )

    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.client", lambda *_: OrganizationClient()
    )
    return calls


def owned(domain, **kwargs):
    return MODEL.OrganizationSummary(id=ORG, compartment_id=domain.tenancy_ocid, **kwargs)


def test_owned_organization_with_children_only_is_valid(domain, monkeypatch):
    configure(monkeypatch, [owned(domain)], [member()])
    children = discover(object(), domain)
    assert [child.ocid for child in children] == [CHILD]
    # Discovery cannot know the child's home region; it must not inherit the parent's.
    assert [child.home_region for child in children] == [""]


def test_owned_parent_with_no_children_is_valid(domain, monkeypatch):
    configure(monkeypatch, [owned(domain)], [])
    assert discover(object(), domain) == []


def test_parent_row_is_not_returned_as_a_child(domain, monkeypatch):
    configure(monkeypatch, [owned(domain)], [member(domain.tenancy_ocid, "PARENT"), member()])
    assert [child.ocid for child in discover(object(), domain)] == [CHILD]


def test_unrelated_organizations_are_not_used(domain, monkeypatch):
    unrelated = MODEL.OrganizationSummary(
        id="ocid1.organization.oc1..aaaafakeother", compartment_id=OTHER
    )
    calls = configure(monkeypatch, [unrelated, owned(domain)], [member()])
    assert len(discover(object(), domain)) == 1
    assert calls == [ORG]


def test_child_cannot_enroll_as_parent(domain, monkeypatch):
    configure(monkeypatch, [MODEL.OrganizationSummary(id=ORG, compartment_id=OTHER)], [member()])
    with pytest.raises(PublicFailure, match="owning tenancy"):
        discover(object(), domain)


@pytest.mark.parametrize("members", [[member(OTHER, "PARENT")], [member(role="CHILD")]])
def test_conflicting_membership_is_rejected(domain, monkeypatch, members):
    if members[0].role == "CHILD":
        members[0].tenancy_id = domain.tenancy_ocid
    configure(monkeypatch, [owned(domain)], members)
    with pytest.raises(PublicFailure, match="conflict"):
        discover(object(), domain)


def test_departed_and_deleted_children_are_excluded(domain, monkeypatch):
    configure(
        monkeypatch,
        [owned(domain)],
        [
            member("ocid1.tenancy.oc1..aaaafakeleft", time_left=datetime(2026, 1, 1, tzinfo=UTC)),
            member("ocid1.tenancy.oc1..aaaafakedeleted", lifecycle_state="DELETED"),
            member(),
        ],
    )
    assert [child.ocid for child in discover(object(), domain)] == [CHILD]


def test_multiple_owned_organizations_require_resolution(domain, monkeypatch):
    second = MODEL.OrganizationSummary(
        id="ocid1.organization.oc1..aaaafakesecond", compartment_id=domain.tenancy_ocid
    )
    configure(monkeypatch, [owned(domain), second], [])
    with pytest.raises(PublicFailure, match="Multiple"):
        discover(object(), domain)
