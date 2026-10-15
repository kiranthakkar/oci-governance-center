"""Organization discovery (read-only). docs/control-plane.md §4.

Uses ``oci.tenant_manager_control_plane.OrganizationClient`` in the parent's home region.
Required IAM: ``read organizations-family in tenancy`` (verify family name against current docs).
"""

from __future__ import annotations

from typing import Any

from oci_security_center.models import Organization, OrganizationTenancy
from oci_security_center.oci_clients import list_all


def discover_organizations(org_client: Any, parent_tenancy_ocid: str) -> list[Organization]:
    """Return the Organizations owned by the parent tenancy, with their tenancies.

    Calls: ``OrganizationClient.list_organizations``, ``list_organization_tenancies``.
    """
    organizations: list[Organization] = []
    for org in list_all(org_client.list_organizations, compartment_id=parent_tenancy_ocid):
        tenancies = [
            OrganizationTenancy(
                tenancy_ocid=t.tenancy_id,
                name=t.name,
                role=str(t.role or ""),
                lifecycle_state=t.lifecycle_state,
                governance_status=t.governance_status,
                organization_id=org.id,
            )
            for t in list_all(org_client.list_organization_tenancies, organization_id=org.id)
        ]
        organizations.append(
            Organization(
                id=org.id,
                display_name=org.display_name,
                parent_tenancy_ocid=parent_tenancy_ocid,
                lifecycle_state=org.lifecycle_state,
                tenancies=tuple(tenancies),
            )
        )
    return organizations
