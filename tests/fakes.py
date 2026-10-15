"""Fake OCI clients returning real SDK model objects with synthetic data (AGENTS.md §2.5)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import oci
from oci.response import Response


def resp(data: Any) -> Response:
    return Response(200, {}, data, None)


def service_error(status: int, code: str) -> oci.exceptions.ServiceError:
    return oci.exceptions.ServiceError(status, code, {}, f"{code} (fake)")


@dataclass
class FakeTenancyData:
    ocid: str
    name: str
    policies: list[tuple[str, str, list[str]]] = field(default_factory=list)  # (id, name, stmts)
    groups: dict[str, str] = field(default_factory=dict)  # name -> ocid
    dynamic_groups: dict[str, str] = field(default_factory=dict)  # name -> ocid
    home_region: str = "us-ashburn-1"
    deny: bool = False  # 404 everything


class FakeIdentity:
    def __init__(self, world: dict[str, FakeTenancyData]) -> None:
        self.world = world

    def _t(self, ocid: str) -> FakeTenancyData:
        t = self.world.get(ocid)
        if t is None or t.deny:
            raise service_error(404, "NotAuthorizedOrNotFound")
        return t

    def get_tenancy(self, ocid: str, **_: Any) -> Response:
        t = self._t(ocid)
        return resp(oci.identity.models.Tenancy(id=t.ocid, name=t.name, home_region_key="IAD"))

    def list_region_subscriptions(self, ocid: str, **_: Any) -> Response:
        t = self._t(ocid)
        return resp(
            [
                oci.identity.models.RegionSubscription(
                    region_key="IAD", region_name=t.home_region, status="READY", is_home_region=True
                )
            ]
        )

    def list_compartments(self, ocid: str, **_: Any) -> Response:
        self._t(ocid)
        return resp(
            [
                oci.identity.models.Compartment(
                    id="ocid1.compartment.oc1..aaaafakecomp",
                    compartment_id=ocid,
                    name="Prod",
                    lifecycle_state="ACTIVE",
                )
            ]
        )

    def list_policies(self, compartment_id: str, **_: Any) -> Response:
        t = self._t(compartment_id)
        return resp(
            [
                oci.identity.models.Policy(
                    id=pid,
                    compartment_id=t.ocid,
                    name=name,
                    statements=stmts,
                    lifecycle_state="ACTIVE",
                )
                for pid, name, stmts in t.policies
            ]
        )

    def list_groups(self, compartment_id: str, **_: Any) -> Response:
        t = self._t(compartment_id)
        return resp(
            [
                oci.identity.models.Group(
                    id=o, name=n, compartment_id=t.ocid, lifecycle_state="ACTIVE"
                )
                for n, o in t.groups.items()
            ]
        )

    def list_dynamic_groups(self, compartment_id: str, **_: Any) -> Response:
        t = self._t(compartment_id)
        return resp(
            [
                oci.identity.models.DynamicGroup(
                    id=o,
                    name=n,
                    compartment_id=t.ocid,
                    matching_rule="ALL {instance.id = 'x'}",
                    lifecycle_state="ACTIVE",
                )
                for n, o in t.dynamic_groups.items()
            ]
        )


class FakeOrganizations:
    def __init__(self, parent: str, children: list[tuple[str, str]], fail: bool = False) -> None:
        self.parent, self.children, self.fail = parent, children, fail

    def list_organizations(self, compartment_id: str, **_: Any) -> Response:
        if self.fail:
            raise service_error(404, "NotAuthorizedOrNotFound")
        m = oci.tenant_manager_control_plane.models
        return resp(
            m.OrganizationCollection(
                items=[
                    m.OrganizationSummary(
                        id="ocid1.organization.oc1..aaaafakeorg",
                        display_name="Org",
                        compartment_id=compartment_id,
                        lifecycle_state="ACTIVE",
                    )
                ]
            )
        )

    def list_organization_tenancies(self, organization_id: str, **_: Any) -> Response:
        m = oci.tenant_manager_control_plane.models
        items = [
            m.OrganizationTenancySummary(
                tenancy_id=self.parent, name="Parent", role="PARENT", lifecycle_state="ACTIVE"
            )
        ]
        items += [
            m.OrganizationTenancySummary(
                tenancy_id=o,
                name=n,
                role="CHILD",
                lifecycle_state="ACTIVE",
                governance_status="OPTED_IN",
            )
            for o, n in self.children
        ]
        return resp(m.OrganizationTenancyCollection(items=items))


class FakeCloudGuard:
    def __init__(self, world: dict[str, FakeTenancyData]) -> None:
        self.world = world

    def get_configuration(self, ocid: str, **_: Any) -> Response:
        if self.world[ocid].deny:
            raise service_error(404, "NotAuthorizedOrNotFound")
        return resp(
            oci.cloud_guard.models.Configuration(status="ENABLED", reporting_region="us-ashburn-1")
        )


class FakeAudit:
    def __init__(self, world: dict[str, FakeTenancyData]) -> None:
        self.world = world

    def list_events(self, ocid: str, start: Any, end: Any, **_: Any) -> Response:
        if self.world[ocid].deny:
            raise service_error(404, "NotAuthorizedOrNotFound")
        return resp([])


class FakeClients:
    """A ``ClientMaker`` that hands out fakes by SDK client class."""

    def __init__(self, world: dict[str, FakeTenancyData], orgs: FakeOrganizations) -> None:
        self.world, self.orgs = world, orgs
        self.calls: list[str] = []
        self.regions: list[tuple[str, str | None]] = []  # (client class, region)

    def __call__(
        self,
        client_cls: Callable[..., Any],
        region: str | None = None,
        service_endpoint: str | None = None,
    ) -> Any:
        name = getattr(client_cls, "__name__", str(client_cls))
        self.calls.append(name)
        self.regions.append((name, region))
        if client_cls is oci.identity.IdentityClient:
            return FakeIdentity(self.world)
        if client_cls is oci.tenant_manager_control_plane.OrganizationClient:
            return self.orgs
        if client_cls is oci.cloud_guard.CloudGuardClient:
            return FakeCloudGuard(self.world)
        if client_cls is oci.audit.AuditClient:
            return FakeAudit(self.world)
        raise AssertionError(f"unexpected client {client_cls}")
