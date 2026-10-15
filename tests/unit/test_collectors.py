"""Tier 1 collectors and the scan runner, against an in-memory fake OCI (no live calls)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import oci
import pytest
from oci.response import Response

from fakes import service_error
from oci_security_center.collection.registry import COLLECTORS, GROUPS, collectors_for_tier
from oci_security_center.collection.runner import ScanRunner
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import (
    FindingSource,
    FindingStatus,
    OnboardingStatus,
    OrgRole,
    Tenancy,
)
from oci_security_center.storage.datasets import DATASETS
from oci_security_center.storage.sqlite import SqliteStores, open_stores

P = "ocid1.tenancy.oc1..aaaafakeparent"
C = "ocid1.tenancy.oc1..aaaafakechild1"
COMP = "ocid1.compartment.oc1..aaaafakecomp"
D1 = "ocid1.domain.oc1..aaaafakedomain1"
D2 = "ocid1.domain.oc1..aaaafakedomain2"
DOMAIN_URL = {D1: "https://idcs-one.identity.oraclecloud.com", D2: "https://idcs-two.example"}

idm = oci.identity_domains.models
cgm = oci.cloud_guard.models
opm = oci.optimizer.models


def resp(data: Any) -> Response:
    return Response(200, {}, data, None)


@dataclass
class Tenant:
    ocid: str
    home: str = "us-ashburn-1"
    cloud_guard: str = "ENABLED"
    problems: list[dict[str, Any]] = field(default_factory=list)
    zone_problems: set[str] = field(default_factory=set)
    domains: dict[str, str] = field(default_factory=lambda: {D1: COMP})  # domain -> compartment
    users: dict[str, list[tuple[str, str, list[str]]]] = field(default_factory=dict)
    groups: dict[str, list[tuple[str, str, list[str]]]] = field(default_factory=dict)
    enrolled: bool = True
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    fail: dict[str, int] = field(default_factory=dict)  # "<call>[:<arg>]" -> HTTP status
    member_truncation: bool = False
    total_overcount: int = 0


class FakeWorld:
    """A ``ClientMaker``: returns fake clients that answer from the tenants below."""

    def __init__(self, tenants: dict[str, Tenant]) -> None:
        self.tenants = tenants
        self.calls: list[tuple[str, str | None, str | None]] = []

    def __call__(
        self,
        client_cls: Callable[..., Any],
        region: str | None = None,
        service_endpoint: str | None = None,
    ) -> Any:
        name = getattr(client_cls, "__name__", "")
        self.calls.append((name, region, service_endpoint))
        return {
            "IdentityClient": _Identity,
            "IdentityDomainsClient": _Domains,
            "CloudGuardClient": _CloudGuard,
            "OptimizerClient": _Optimizer,
        }[name](self, service_endpoint)


class _Base:
    def __init__(self, world: FakeWorld, endpoint: str | None) -> None:
        self.world, self.endpoint = world, endpoint

    def _check(self, t: Tenant, call: str, arg: str = "") -> None:
        for key in (f"{call}:{arg}", call):
            if key in t.fail:
                raise service_error(t.fail[key], "Failure")


class _Identity(_Base):
    def list_region_subscriptions(self, tenancy: str, **_: Any) -> Response:
        t = self.world.tenants[tenancy]
        return resp(
            [
                oci.identity.models.RegionSubscription(
                    region_key="X", region_name=t.home, status="READY", is_home_region=True
                )
            ]
        )

    def list_compartments(self, tenancy: str, **_: Any) -> Response:
        return resp(
            [
                oci.identity.models.Compartment(
                    id=f"{COMP}-{tenancy[-6:]}",
                    compartment_id=tenancy,
                    name="Prod",
                    lifecycle_state="ACTIVE",
                )
            ]
        )

    def _tenant_of(self, compartment: str) -> Tenant:
        for t in self.world.tenants.values():
            if compartment in (t.ocid, f"{COMP}-{t.ocid[-6:]}"):
                return t
        raise service_error(404, "NotAuthorizedOrNotFound")

    def list_policies(self, compartment_id: str, **_: Any) -> Response:
        t = self._tenant_of(compartment_id)
        self._check(t, "list_policies", compartment_id)
        return resp(
            [
                oci.identity.models.Policy(
                    id=f"ocid1.policy.oc1..{compartment_id.replace('.', '')[-20:]}",
                    compartment_id=compartment_id,
                    name="p",
                    statements=["Allow group A to read all-resources in tenancy"],
                    lifecycle_state="ACTIVE",
                )
            ]
        )

    def list_domains(self, compartment_id: str, **_: Any) -> Response:
        t = self._tenant_of(compartment_id)
        self._check(t, "list_domains", compartment_id)
        here = f"{COMP}-{t.ocid[-6:]}"
        if compartment_id != here:
            return resp([])
        return resp(
            [
                oci.identity.models.DomainSummary(
                    id=d,
                    compartment_id=here,
                    display_name=d[-7:],
                    url=DOMAIN_URL[d],
                    home_region=t.home,
                    type="DEFAULT",
                    lifecycle_state="ACTIVE",
                    replica_regions=[],
                    license_type="should-not-be-stored",
                )
                for d in t.domains
            ]
        )


class _Domains(_Base):
    def _domain(self) -> tuple[Tenant, str]:
        for t in self.world.tenants.values():
            for d in t.domains:
                if DOMAIN_URL[d] == self.endpoint:
                    return t, d
        raise service_error(404, "NotAuthorizedOrNotFound")

    def _page(
        self, cls: Any, items: list[Any], start_index: int, count: int, t: Tenant
    ) -> Response:
        page = items[start_index - 1 : start_index - 1 + count]
        return resp(cls(resources=page, total_results=len(items) + t.total_overcount))

    def list_users(
        self, start_index: int = 1, count: int = 50, attributes: str = "", **_: Any
    ) -> Response:
        t, d = self._domain()
        self._check(t, "list_users", d)
        users = [
            idm.User(
                id=uid,
                ocid=f"ocid1.user.oc1..{uid}",
                user_name=name,
                groups=[idm.UserGroups(value=g) for g in groups]
                if "groups" in attributes
                else None,
            )
            for uid, name, groups in t.users.get(d, [])
        ]
        return self._page(idm.Users, users, start_index, count, t)

    def list_groups(self, start_index: int = 1, count: int = 50, **_: Any) -> Response:
        t, d = self._domain()
        groups = []
        for gid, name, members in t.groups.get(d, []):
            shown = members[:-1] if t.member_truncation else members
            groups.append(
                idm.Group(
                    id=gid,
                    ocid=f"ocid1.group.oc1..{gid}",
                    display_name=name,
                    members=[
                        idm.GroupMembers(value=m, ocid=f"ocid1.user.oc1..{m}", type="User")
                        for m in shown
                    ],
                )
            )
        return self._page(idm.Groups, groups, start_index, count, t)

    def list_dynamic_resource_groups(
        self, start_index: int = 1, count: int = 50, **_: Any
    ) -> Response:
        t, _d = self._domain()
        rows = [
            idm.DynamicResourceGroup(
                id="dg1",
                ocid="ocid1.dynamicgroup.oc1..dg1",
                display_name="Scanners",
                matching_rule="ALL {instance.id = 'x'}",
            )
        ]
        return self._page(idm.DynamicResourceGroups, rows, start_index, count, t)


class _CloudGuard(_Base):
    def get_configuration(self, tenancy: str, **_: Any) -> Response:
        t = self.world.tenants[tenancy]
        return resp(
            cgm.Configuration(
                status=t.cloud_guard, reporting_region=t.home, self_manage_resources=False
            )
        )

    def list_problems(self, compartment_id: str, problem_category: str = "", **_: Any) -> Response:
        t = self.world.tenants[compartment_id]
        self._check(t, "list_problems")
        rows = [p for p in t.problems if not problem_category or p["id"] in t.zone_problems]
        return resp(cgm.ProblemCollection(items=[cgm.ProblemSummary(**p) for p in rows]))

    def list_security_zones(self, compartment_id: str, **_: Any) -> Response:
        return resp(cgm.SecurityZoneCollection(items=[]))


class _Optimizer(_Base):
    def list_enrollment_statuses(self, compartment_id: str, **_: Any) -> Response:
        t = self.world.tenants[compartment_id]
        return resp(
            opm.EnrollmentStatusCollection(
                items=[
                    opm.EnrollmentStatusSummary(
                        id=f"enr-{t.ocid[-6:]}",
                        status="ACTIVE" if t.enrolled else "INACTIVE",
                        lifecycle_state="ACTIVE",
                    )
                ]
            )
        )

    def list_categories(self, compartment_id: str, **_: Any) -> Response:
        return resp(opm.CategoryCollection(items=[opm.CategorySummary(id="cat1", name="cost")]))

    def list_recommendations(self, compartment_id: str, category_id: str, **_: Any) -> Response:
        t = self.world.tenants[compartment_id]
        return resp(
            opm.RecommendationCollection(
                items=[
                    opm.RecommendationSummary(category_id=category_id, **r)
                    for r in t.recommendations
                ]
            )
        )


def _problem(pid: str, **kw: Any) -> dict[str, Any]:
    return {
        "id": pid,
        "compartment_id": P,
        "detector_id": "IAAS_CONFIGURATION_DETECTOR",
        "detector_rule_id": "BUCKET_IS_PUBLIC",
        "risk_level": "HIGH",
        "resource_id": "ocid1.bucket.oc1..b1",
        "resource_name": "b1",
        "resource_type": "Bucket",
        "lifecycle_state": "ACTIVE",
        "lifecycle_detail": "OPEN",
        "region": "us-ashburn-1",
        **kw,
    }


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_root=tmp_path, deployment=DeploymentMode.WORKSTATION, max_workers=2)


@pytest.fixture
def stores(settings: Settings) -> SqliteStores:
    s = open_stores(settings)
    gen = s.state.current_generation()
    s.state.set_setting("parent_tenancy_ocid", P)
    s.state.set_organization_parent(P, gen)
    for ocid, role, status in (
        (P, OrgRole.PARENT, OnboardingStatus.ACTIVE),
        (C, OrgRole.CHILD, OnboardingStatus.ACTIVE),
    ):
        s.state.upsert_tenancy(
            Tenancy(
                ocid=ocid,
                name=ocid[-6:],
                alias=f"a{ocid[-6:]}",
                org_role=role,
                onboarding_status=status,
                home_region="us-ashburn-1",
                parent_tenancy_ocid=P if role is OrgRole.CHILD else None,
            )
        )
    return s


@pytest.fixture
def world() -> FakeWorld:
    return FakeWorld(
        {
            P: Tenant(
                P,
                problems=[_problem("pr1"), _problem("pr2")],
                zone_problems={"pr2"},
                users={D1: [("u1", "alice", ["g1"]), ("u2", "bob", [])]},
                groups={D1: [("g1", "Admins", ["u1"])]},
                recommendations=[
                    {
                        "id": "rec1",
                        "name": "Delete idle",
                        "importance": "HIGH",
                        "status": "PENDING",
                    },
                    {"id": "rec2", "name": "Done", "importance": "LOW", "status": "IMPLEMENTED"},
                ],
            ),
            C: Tenant(C, cloud_guard="DISABLED", enrolled=False, domains={D2: COMP}),
        }
    )


def _run(settings: Settings, stores: SqliteStores, world: FakeWorld, **kw: Any) -> Any:
    return ScanRunner(settings, stores, world, collectors_for_tier(1)).scan(**kw)


def _current(stores: SqliteStores, tenancy: str, dataset: str, **dims: str) -> list[dict[str, Any]]:
    from oci_security_center.models import CollectionScope

    scope = CollectionScope(
        generation=stores.state.current_generation(), tenancy_ocid=tenancy, dataset=dataset, **dims
    )
    return [e.data for e in stores.data.read_current(scope)]


def _open(stores: SqliteStores, **filters: Any) -> list[Any]:
    return stores.data.list_findings(status=FindingStatus.OPEN, **filters)


# --- registry ----------------------------------------------------------------------------------
def test_registry_is_ordered_registered_and_grouped() -> None:
    seen: set[str] = set()
    for c in COLLECTORS:
        assert c.dataset in DATASETS
        assert DATASETS[c.dataset].tier == c.tier
        assert set(c.depends_on) <= seen, f"{c.dataset} runs before its dependencies"
        seen.add(c.dataset)
    assert set().union(*GROUPS.values()) == {c.dataset for c in collectors_for_tier(1)}


# --- full scan ---------------------------------------------------------------------------------
def test_full_tier1_scan(settings: Settings, stores: SqliteStores, world: FakeWorld) -> None:
    summary = _run(settings, stores, world)
    statuses = {(o.tenancy_ocid, o.dataset): o.status for o in summary.outcomes}
    assert statuses[(P, "identity.policies")] == "ok"
    assert statuses[(P, "identity_domains.users")] == "ok"
    assert statuses[(C, "cloud_guard.problems")] == "not_applicable"  # Cloud Guard disabled
    assert statuses[(C, "optimizer.recommendations")] == "not_applicable"
    assert summary.ok

    users = _current(stores, P, "identity_domains.users", domain=D1)
    assert sorted(u["user_name"] for u in users) == ["alice", "bob"]
    assert set(users[0]) == {"domain_ocid", "id", "ocid", "user_name"}  # minimal fields only
    [domain] = _current(stores, P, "identity.domains")
    assert "license_type" not in domain
    [group] = _current(stores, P, "identity_domains.groups", domain=D1)
    assert group["members"] == [{"value": "u1", "ocid": "ocid1.user.oc1..u1", "type": "User"}]

    # identity-domain calls go to the domain URL; Cloud Guard to the reporting region
    assert ("IdentityDomainsClient", None, DOMAIN_URL[D1]) in world.calls
    assert ("CloudGuardClient", "us-ashburn-1", None) in world.calls

    findings = _open(stores)
    by_rule = {(f.tenancy_ocid, f.rule_id) for f in findings}
    assert (C, "GOV-CG-001") in by_rule
    assert (C, "GOV-ADV-001") in by_rule
    assert (P, "GOV-CG-001") not in by_rule
    problems = {f.identity["problem_id"]: f for f in findings if f.rule_id == "CG-PROBLEM"}
    assert problems["pr1"].source is FindingSource.CLOUD_GUARD
    assert problems["pr2"].source is FindingSource.SECURITY_ZONE
    advisor = [f for f in findings if f.source is FindingSource.ADVISOR]
    assert [f.identity["recommendation_id"] for f in advisor] == ["rec1"]  # pending only

    caps = {(c["tenancy_ocid"], c["capability"]): c["status"] for c in stores.state.capabilities(1)}
    assert caps[(P, "identity_domains.users")] == "supported"
    assert stores.data.scan_runs()[0]["status"] == "ok"


def test_resolved_problem_and_enabled_cloud_guard_resolve_findings(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    _run(settings, stores, world)
    world.tenants[P].problems = [_problem("pr1")]
    world.tenants[C].cloud_guard = "ENABLED"
    _run(settings, stores, world)
    rules = {(f.tenancy_ocid, f.rule_id, f.identity.get("problem_id")) for f in _open(stores)}
    assert (P, "CG-PROBLEM", "pr1") in rules
    assert (P, "CG-PROBLEM", "pr2") not in rules
    assert (C, "GOV-CG-001", None) not in rules


def test_volatile_fields_dont_count_as_changes(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    from datetime import UTC, datetime

    world.tenants[P].problems = [
        _problem("pr1", time_last_detected=datetime(2026, 10, 1, tzinfo=UTC))
    ]
    _run(settings, stores, world, only={"cloud_guard.configuration", "cloud_guard.problems"})
    world.tenants[P].problems = [
        _problem("pr1", time_last_detected=datetime(2026, 10, 2, tzinfo=UTC))
    ]
    _run(settings, stores, world, only={"cloud_guard.problems"})
    kinds = [c["change_type"] for c in stores.data.list_changes(P, "cloud_guard.problems")]
    assert kinds == ["added"]


# --- partial collections and coverage ----------------------------------------------------------
def test_failed_compartment_keeps_rows_and_raises_scoped_coverage(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    _run(settings, stores, world)
    before = _current(stores, P, "identity.policies")
    assert before
    world.tenants[P].fail["list_policies"] = 403
    summary = _run(settings, stores, world, only={"identity.policies"})
    assert {o.status for o in summary.outcomes if o.tenancy_ocid == P} == {"partial"}
    assert _current(stores, P, "identity.policies") == before  # never replaced by partial data
    [cov] = _open(stores, rule_id="OSC-ACCESS-002", tenancy_ocid=P)
    assert cov.identity["subject"] == "identity.policies"
    assert "Last complete collection" in cov.description

    del world.tenants[P].fail["list_policies"]
    _run(settings, stores, world, only={"identity.policies"})
    assert _open(stores, rule_id="OSC-ACCESS-002", tenancy_ocid=P) == []


def test_neighbouring_domain_success_doesnt_resolve_a_failed_domain(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    world.tenants[P].domains = {D1: COMP, D2: COMP}
    world.tenants[P].fail["list_users:" + D2] = 404
    _run(settings, stores, world)
    [cov] = [
        f
        for f in _open(stores, rule_id="OSC-ACCESS-002", tenancy_ocid=P)
        if f.identity["subject"] == "identity_domains.users"
    ]
    assert cov.identity["domain"] == D2
    caps = {
        (c["capability"], c["scope_key"]): c["status"]
        for c in stores.state.capabilities(1, P)
        if c["capability"] == "identity_domains.users"
    }
    assert set(caps.values()) == {"supported", "unsupported"}
    _run(settings, stores, world, only={"identity_domains.users"})  # D1 succeeds again
    assert any(f.identity.get("domain") == D2 for f in _open(stores, rule_id="OSC-ACCESS-002"))


def test_unverified_membership_or_short_paging_is_partial(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    _run(settings, stores, world)
    world.tenants[P].member_truncation = True
    summary = _run(settings, stores, world, only={"identity_domains.groups"})
    [outcome] = [o for o in summary.outcomes if o.tenancy_ocid == P]
    assert outcome.status == "partial"
    assert "could not be verified" in outcome.detail
    [group] = _current(stores, P, "identity_domains.groups", domain=D1)
    assert group["members"]  # the complete earlier member list is kept

    world.tenants[P].member_truncation = False
    world.tenants[P].total_overcount = 5  # the source reports more users than it returns
    summary = _run(settings, stores, world, only={"identity_domains.users"})
    assert [o.status for o in summary.outcomes if o.tenancy_ocid == P] == ["partial"]


def test_missing_dependency_and_busy_scope(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    summary = _run(settings, stores, world, only={"identity.policies"})  # compartments never ran
    assert {o.status for o in summary.outcomes} == {"dependency_missing"}
    assert _open(stores, rule_id="OSC-ACCESS-002")

    from oci_security_center.models import CollectionScope

    scope = CollectionScope(generation=1, tenancy_ocid=P, dataset="identity.region_subscriptions")
    assert stores.state.acquire_lease(scope.lease_key, 1, "another-run", 60)
    summary = _run(settings, stores, world, only={"identity.region_subscriptions"})
    assert {(o.tenancy_ocid, o.status) for o in summary.outcomes} == {(P, "skipped"), (C, "ok")}


def test_only_active_tenancies_are_scanned(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    child = stores.state.get_tenancy(C)
    assert child is not None
    stores.state.upsert_tenancy(
        child.model_copy(update={"onboarding_status": OnboardingStatus.PENDING})
    )
    summary = _run(settings, stores, world, only={"identity.region_subscriptions"})
    assert {o.tenancy_ocid for o in summary.outcomes} == {P}


def test_scans_pause_during_maintenance(
    settings: Settings, stores: SqliteStores, world: FakeWorld
) -> None:
    from oci_security_center.storage.errors import MaintenanceError

    token = stores.state.begin_maintenance("switch")
    with pytest.raises(MaintenanceError):
        _run(settings, stores, world)
    stores.state.end_maintenance(token)


def test_failed_compartment_discovery_blocks_policy_completeness(
    settings: Settings, stores: SqliteStores
) -> None:
    class DiscoveryWorld(FakeWorld):
        fail_discovery = False

        def __call__(
            self,
            client_cls: Callable[..., Any],
            region: str | None = None,
            service_endpoint: str | None = None,
        ) -> Any:
            client = super().__call__(client_cls, region, service_endpoint)
            if client_cls.__name__ == "IdentityClient" and self.fail_discovery:

                def fail(*args: object, **kwargs: object) -> None:
                    raise service_error(403, "NotAuthorized")

                client.list_compartments = fail
            return client

    world = DiscoveryWorld({P: Tenant(P), C: Tenant(C)})
    runner = ScanRunner(settings, stores, world, collectors_for_tier(1))
    good = runner.scan(only={"identity.compartments", "identity.policies"})
    assert good.ok
    world.fail_discovery = True
    failed = runner.scan(only={"identity.compartments", "identity.policies"})
    assert all(
        o.status == "dependency_missing"
        for o in failed.outcomes
        if o.dataset == "identity.policies"
    )
    # A later policy-only run must also refuse the previously failed scope discovery.
    failed = runner.scan(only={"identity.policies"})
    assert all(o.status == "dependency_missing" for o in failed.outcomes)
    world.fail_discovery = False
    assert runner.scan(only={"identity.compartments", "identity.policies"}).ok
