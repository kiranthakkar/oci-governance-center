"""Identity collector (read-only): tenancy, regions, compartments, policies, groups.

All functions take an ``oci.identity.IdentityClient`` (home region) so they are easy to mock.
Required IAM: ``inspect tenancies``, ``inspect compartments``, ``read policies``,
``inspect groups``, ``inspect dynamic-groups`` (or ``read all-resources`` for the scanner).

Note: the IAM ``list_groups`` / ``list_dynamic_groups`` APIs return Default-domain objects.
Groups in
named identity domains need the Identity Domains API (TODO, docs/control-plane.md §2.5).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import oci

from oci_security_center.collection.base import Collected, TenancyContext, TenancyScoped
from oci_security_center.models import CollectionScope, Envelope
from oci_security_center.oci_clients import ClientMaker, list_all, pick, to_plain

POLICY_FIELDS = (
    "id",
    "compartment_id",
    "name",
    "description",
    "statements",
    "lifecycle_state",
    "time_created",
    "version_date",
)
COMPARTMENT_FIELDS = (
    "id",
    "compartment_id",
    "name",
    "description",
    "lifecycle_state",
    "time_created",
)
GROUP_FIELDS = ("id", "compartment_id", "name", "description", "lifecycle_state", "time_created")
DYNAMIC_GROUP_FIELDS = (*GROUP_FIELDS, "matching_rule")
REGION_FIELDS = ("region_key", "region_name", "status", "is_home_region")


def get_tenancy(identity: Any, tenancy_ocid: str) -> dict[str, Any]:
    """``IdentityClient.get_tenancy`` → {id, name, home_region_key, description}."""
    return pick(
        to_plain(identity.get_tenancy(tenancy_ocid).data),
        ("id", "name", "description", "home_region_key"),
    )


def list_region_subscriptions(identity: Any, tenancy_ocid: str) -> list[dict[str, Any]]:
    """``IdentityClient.list_region_subscriptions``."""
    resp = identity.list_region_subscriptions(tenancy_ocid)
    return [pick(to_plain(r), REGION_FIELDS) for r in resp.data]


def home_region(regions: Iterable[dict[str, Any]]) -> str | None:
    for r in regions:
        if r.get("is_home_region"):
            return str(r["region_name"])
    return None


def list_compartments(identity: Any, tenancy_ocid: str) -> list[dict[str, Any]]:
    """All ACCESSIBLE compartments in the subtree, plus a synthetic root entry."""
    items = list_all(
        identity.list_compartments,
        tenancy_ocid,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
    )
    root = {
        "id": tenancy_ocid,
        "compartment_id": None,
        "name": "(root)",
        "description": None,
        "lifecycle_state": "ACTIVE",
        "time_created": None,
    }
    return [root, *(pick(to_plain(c), COMPARTMENT_FIELDS) for c in items)]


def list_policies(identity: Any, compartment_ocid: str) -> list[dict[str, Any]]:
    """``IdentityClient.list_policies`` for one compartment (policies have no subtree flag)."""
    return [
        pick(to_plain(p), POLICY_FIELDS) for p in list_all(identity.list_policies, compartment_ocid)
    ]


def list_all_policies(
    identity: Any, compartments: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for comp in compartments:
        if comp.get("lifecycle_state") not in (None, "ACTIVE"):
            continue
        out.extend(list_policies(identity, str(comp["id"])))
    return out


def list_groups(identity: Any, tenancy_ocid: str) -> list[dict[str, Any]]:
    return [
        {**pick(to_plain(g), GROUP_FIELDS), "domain": "Default"}
        for g in list_all(identity.list_groups, tenancy_ocid)
    ]


def list_dynamic_groups(identity: Any, tenancy_ocid: str) -> list[dict[str, Any]]:
    return [
        {**pick(to_plain(g), DYNAMIC_GROUP_FIELDS), "domain": "Default"}
        for g in list_all(identity.list_dynamic_groups, tenancy_ocid)
    ]


def to_envelopes(
    dataset_schema: str,
    tenancy_ocid: str,
    records: Iterable[dict[str, Any]],
    run_id: str,
    key_field: str = "id",
) -> list[Envelope]:
    return [
        Envelope(
            schema_id=dataset_schema,
            tenancy_ocid=tenancy_ocid,
            record_key=str(r[key_field]),
            data=r,
            run_id=run_id,
            compartment_ocid=r.get("compartment_id"),
            resource_ocid=r.get("id"),
        )
        for r in records
    ]


# --- Tier 1 collectors (docs/collection.md §3) ----------------------------------------------------
DOMAIN_FIELDS = (
    "id",
    "compartment_id",
    "display_name",
    "url",
    "home_region",
    "replica_regions",
    "type",
    "lifecycle_state",
)


def _identity_client(ctx: TenancyContext, clients: ClientMaker) -> Any:
    return clients(oci.identity.IdentityClient, ctx.home_region)


def _active_compartments(ctx: TenancyContext) -> list[str]:
    return [
        str(c["id"])
        for c in ctx.current("identity.compartments")
        if c.get("lifecycle_state") in (None, "ACTIVE")
    ]


class RegionSubscriptionsCollector(TenancyScoped):
    """``IdentityClient.list_region_subscriptions``. IAM: ``inspect tenancies``."""

    dataset = "identity.region_subscriptions"
    tier = 1
    depends_on: tuple[str, ...] = ()

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        identity = clients(
            oci.identity.IdentityClient, ctx.tenancy.home_region or ctx.parent.home_region
        )
        regions = list_region_subscriptions(identity, ctx.tenancy_ocid)
        return Collected([ctx.envelope(self.dataset, str(r["region_name"]), r) for r in regions])


class CompartmentsCollector(TenancyScoped):
    """``IdentityClient.list_compartments`` (subtree, ACCESSIBLE). IAM: ``inspect compartments``."""

    dataset = "identity.compartments"
    tier = 1
    depends_on: tuple[str, ...] = ("identity.region_subscriptions",)

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        items = list_compartments(_identity_client(ctx, clients), ctx.tenancy_ocid)
        return Collected(
            [
                ctx.envelope(
                    self.dataset,
                    str(c["id"]),
                    c,
                    compartment_ocid=c.get("compartment_id"),
                    resource_ocid=c["id"],
                )
                for c in items
            ]
        )


class _PerCompartment(TenancyScoped):
    """Collect one list call per active compartment; any failed compartment = incomplete."""

    depends_on: tuple[str, ...] = ("identity.compartments",)

    def list_in(self, client: Any, compartment_ocid: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        client = _identity_client(ctx, clients)
        expected = _active_compartments(ctx)
        out = Collected(expected_children=tuple(expected))
        visited: list[str] = []
        for cid in expected:
            try:
                rows = self.list_in(client, cid)
            except oci.exceptions.ServiceError as exc:
                out.errors.append(f"{cid}: {exc.status} {exc.code}")
                continue
            visited.append(cid)
            out.records += [
                ctx.envelope(
                    self.dataset, str(r["id"]), r, compartment_ocid=cid, resource_ocid=r["id"]
                )
                for r in rows
            ]
        out.visited_children = tuple(visited)
        return out


class PoliciesCollector(_PerCompartment):
    """``IdentityClient.list_policies`` per compartment. IAM: ``read policies``."""

    dataset = "identity.policies"
    tier = 1

    def list_in(self, client: Any, compartment_ocid: str) -> list[dict[str, Any]]:
        return list_policies(client, compartment_ocid)


class DomainsCollector(_PerCompartment):
    """``IdentityClient.list_domains`` per compartment (domains can live anywhere).
    IAM: ``inspect domains`` (covered by ``read all-resources``)."""

    dataset = "identity.domains"
    tier = 1

    def list_in(self, client: Any, compartment_ocid: str) -> list[dict[str, Any]]:
        return [
            pick(to_plain(d), DOMAIN_FIELDS)
            for d in list_all(client.list_domains, compartment_id=compartment_ocid)
        ]
