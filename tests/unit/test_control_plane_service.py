from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakeClients, FakeOrganizations, FakeTenancyData
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane.service import Actor, ControlPlane, ControlPlaneError
from oci_security_center.models import (
    CheckStatus,
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    FindingSource,
    FindingStatus,
    OnboardingStatus,
    OrgRole,
    Tenancy,
    utcnow,
)
from oci_security_center.storage.sqlite import open_stores

PARENT = "ocid1.tenancy.oc1..aaaafakeparent"
CHILD1 = "ocid1.tenancy.oc1..aaaafakechild1"
CHILD2 = "ocid1.tenancy.oc1..aaaafakechild2"
DG = "ocid1.dynamicgroup.oc1..aaaafakedg"
ADMINS = "ocid1.group.oc1..aaaafakeadmins"
ACTOR = Actor("tester@example.com", "admin")


@pytest.fixture
def world() -> dict[str, FakeTenancyData]:
    return {
        PARENT: FakeTenancyData(
            PARENT, "Parent", groups={"OSC-Admins": ADMINS}, dynamic_groups={"OSC-Scanner-DG": DG}
        ),
        CHILD1: FakeTenancyData(CHILD1, "Child One"),
        CHILD2: FakeTenancyData(CHILD2, "Child Two", deny=True),
    }


@pytest.fixture
def cp(tmp_path: Path) -> ControlPlane:
    s = Settings(data_root=tmp_path, deployment=DeploymentMode.OCI)
    return ControlPlane(s, open_stores(s))


@pytest.fixture
def clients(world: dict[str, FakeTenancyData]) -> FakeClients:
    return FakeClients(
        world, FakeOrganizations(PARENT, [(CHILD1, "Child One"), (CHILD2, "Child Two")])
    )


def test_connect_and_discover(cp: ControlPlane, clients: FakeClients) -> None:
    parent = cp.connect_parent(clients, PARENT, None, ACTOR)
    assert parent.org_role is OrgRole.PARENT
    assert parent.home_region == "us-ashburn-1"
    result = cp.discover_children(clients, ACTOR)
    assert result.organizations == 1
    assert {c.ocid for c in result.children} == {CHILD1, CHILD2}
    assert all(c.onboarding_status is OnboardingStatus.DISCOVERED for c in cp.children())
    assert {c.alias for c in cp.children()} == {"osc_child_one", "osc_child_two"}
    # rediscovery keeps status
    cp.select_child(CHILD1, ACTOR)
    cp.discover_children(clients, ACTOR)
    assert cp.state.get_tenancy(CHILD1).onboarding_status is OnboardingStatus.PENDING  # type: ignore[union-attr]


def test_connect_parent_uses_unique_alias_when_default_is_taken(
    cp: ControlPlane, clients: FakeClients
) -> None:
    cp.state.upsert_tenancy(
        Tenancy(
            ocid=CHILD1,
            name="Existing child",
            alias="osc_parent",
            org_role=OrgRole.CHILD,
            parent_tenancy_ocid=PARENT,
            onboarding_status=OnboardingStatus.PENDING,
        )
    )

    parent = cp.connect_parent(clients, PARENT, None, ACTOR)

    assert parent.alias == "osc_parent_2"
    assert cp.state.get_tenancy(PARENT) == parent
    assert cp.connect_parent(clients, PARENT, None, ACTOR).alias == parent.alias


def test_discovery_without_org_allows_manual(cp: ControlPlane, world: dict) -> None:  # type: ignore[type-arg]
    clients = FakeClients(world, FakeOrganizations(PARENT, [], fail=True))
    cp.connect_parent(clients, PARENT, "HQ", ACTOR)
    result = cp.discover_children(clients, ACTOR)
    assert "register children manually" in result.message
    child = cp.register_child(CHILD1, "Child One", ACTOR)
    assert child.onboarding_status is OnboardingStatus.PENDING


def test_connect_parent_error_is_explained(
    cp: ControlPlane,
    world: dict,  # type: ignore[type-arg]
    clients: FakeClients,
) -> None:
    world[PARENT].deny = True
    with pytest.raises(ControlPlaneError, match="NotAuthorizedOrNotFound"):
        cp.connect_parent(clients, PARENT, None, ACTOR)


def test_policy_views_and_parent_checks(
    cp: ControlPlane,
    world: dict,  # type: ignore[type-arg]
    clients: FakeClients,
) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.discover_children(clients, ACTOR)
    cp.select_child(CHILD1, ACTOR)
    principals = cp.principals(clients)
    assert principals.scanner.ocid == DG
    views = cp.parent_policy_views(principals)
    assert [v.policy_name for v in views] == ["osc-parent-access", "osc-endorse-children"]
    endorse_text = views[1].text
    assert f"Define tenancy osc_child_one as {CHILD1}" in endorse_text
    assert CHILD2 not in endorse_text  # not selected

    world[PARENT].policies = [
        (
            "ocid1.policy.oc1..aaaafakep1",
            "osc",
            [
                "Allow dynamic-group OSC-Scanner-DG to read all-resources in tenancy",
                f"Define tenancy osc_child_one as {CHILD1}",
            ],
        )
    ]
    checks = {c.requirement_id: c for c in cp.refresh_parent_checks(clients, ACTOR)}
    assert checks[f"parent_access:{PARENT}:scanner-read-all"].status is CheckStatus.DETECTED
    assert checks[f"endorse:{CHILD1}:define-child"].status is CheckStatus.DETECTED
    assert checks[f"endorse:{CHILD1}:endorse-scanner"].status is CheckStatus.MISSING
    open_cov = cp.stores.data.list_findings(
        source=FindingSource.COVERAGE, status=FindingStatus.OPEN
    )
    assert any("endorse-scanner" in f.identity["subject"] for f in open_cov)

    # fix it -> finding resolves
    world[PARENT].policies[0][2].append(
        "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy osc_child_one"
    )
    cp.refresh_parent_checks(clients, ACTOR)
    still_open = cp.stores.data.list_findings(
        source=FindingSource.COVERAGE, status=FindingStatus.OPEN
    )
    assert not any("endorse-scanner" in f.identity["subject"] for f in still_open)


def test_verify_child_success_and_failure(
    cp: ControlPlane,
    world: dict,  # type: ignore[type-arg]
    clients: FakeClients,
) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.discover_children(clients, ACTOR)
    for c in (CHILD1, CHILD2):
        cp.select_child(c, ACTOR)
    world[CHILD1].policies = [
        (
            "ocid1.policy.oc1..aaaafakec1",
            "osc-admit-parent",
            [
                f"Define tenancy osc_parent as {PARENT}",
                f"Define dynamic-group OSC_Scanner_DG as {DG}",
                "Admit dynamic-group OSC_Scanner_DG of tenancy osc_parent to read all-resources in "
                "tenancy",
            ],
        )
    ]
    ok = cp.verify_child(clients, CHILD1, ACTOR)
    assert ok.ok
    assert cp.state.get_tenancy(CHILD1).onboarding_status is OnboardingStatus.VERIFIED  # type: ignore[union-attr]
    _, admit = cp.child_policy_views(CHILD1, cp.principals(clients))
    assert {admit.status_of(r) for r in admit.requirements} == {CheckStatus.DETECTED}
    assert cp.activate_child(CHILD1, ACTOR).onboarding_status is OnboardingStatus.ACTIVE

    bad = cp.verify_child(clients, CHILD2, ACTOR)
    assert not bad.ok
    assert "Endorse" in bad.summary
    child2 = cp.state.get_tenancy(CHILD2)
    assert child2 is not None
    assert child2.onboarding_status is OnboardingStatus.ERROR
    with pytest.raises(ControlPlaneError):
        cp.activate_child(CHILD2, ACTOR)
    assert any(
        f.tenancy_ocid == CHILD2
        for f in cp.stores.data.list_findings(source=FindingSource.COVERAGE)
    )


def test_control_plane_events_recorded(cp: ControlPlane, clients: FakeClients) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    actions = [e["action"] for e in cp.state.list_events()]
    assert "parent.connect" in actions


# --- review fixes ------------------------------------------------------------------------------
def _open_coverage(cp: ControlPlane) -> set[str]:
    return {
        f.identity["subject"]
        for f in cp.stores.data.list_findings(
            source=FindingSource.COVERAGE, status=FindingStatus.OPEN
        )
    }


def test_failed_policy_read_keeps_findings_open(
    cp: ControlPlane,
    world: dict,  # type: ignore[type-arg]
    clients: FakeClients,
) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.refresh_parent_checks(clients, ACTOR)  # nothing applied -> missing findings
    missing = _open_coverage(cp)
    assert missing

    world[PARENT].deny = True  # e.g. "read policies" was removed
    cp.refresh_parent_checks(clients, ACTOR)
    assert _open_coverage(cp) == missing | {"policy_read"}

    world[PARENT].deny = False
    world[PARENT].policies = [
        ("ocid1.policy.oc1..aaaafakep1", "osc", [r.statement for r in _parent_reqs(cp)])
    ]
    cp.refresh_parent_checks(clients, ACTOR)
    assert _open_coverage(cp) == set()  # a complete check resolves everything


def _parent_reqs(cp: ControlPlane) -> list:  # type: ignore[type-arg]
    return [r for v in cp.parent_policy_views(cp.principals(None)) for r in v.requirements]


def test_register_child_refuses_known_tenancies(cp: ControlPlane, clients: FakeClients) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.discover_children(clients, ACTOR)
    alias = cp.state.get_tenancy(CHILD1).alias  # type: ignore[union-attr]
    with pytest.raises(ControlPlaneError, match="parent tenancy"):
        cp.register_child(PARENT, "oops", ACTOR)
    with pytest.raises(ControlPlaneError, match="already registered"):
        cp.register_child(CHILD1, "Child One", ACTOR)
    assert cp.parent().org_role is OrgRole.PARENT  # type: ignore[union-attr]
    assert cp.state.get_tenancy(CHILD1).alias == alias  # type: ignore[union-attr]


def test_alias_change_resets_onboarding(cp: ControlPlane, clients: FakeClients) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.discover_children(clients, ACTOR)
    cp.select_child(CHILD1, ACTOR)
    cp.verify_child(clients, CHILD1, ACTOR)
    cp.activate_child(CHILD1, ACTOR)

    same = cp.select_child(CHILD1, ACTOR, "osc_child_one")  # unchanged alias
    assert same.onboarding_status is OnboardingStatus.ACTIVE

    changed = cp.select_child(CHILD1, ACTOR, "osc_kid")
    assert changed.onboarding_status is OnboardingStatus.PENDING
    assert "alias changed from osc_child_one to osc_kid" in (changed.status_detail or "")
    with pytest.raises(ControlPlaneError):
        cp.activate_child(CHILD1, ACTOR)


def test_rediscovery_keeps_known_fields(cp: ControlPlane, clients: FakeClients) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)
    cp.discover_children(clients, ACTOR)
    cp.select_child(CHILD1, ACTOR)
    cp.verify_child(clients, CHILD1, ACTOR)
    scanned = utcnow()
    child = cp.state.get_tenancy(CHILD1)
    assert child is not None
    cp.state.upsert_tenancy(child.model_copy(update={"last_scanned_at": scanned}))

    cp.discover_children(clients, ACTOR)
    after = cp.state.get_tenancy(CHILD1)
    assert after is not None
    assert after.subscribed_regions == ("us-ashburn-1",)
    assert after.last_scanned_at == scanned
    assert after.onboarding_status is OnboardingStatus.VERIFIED


def test_verify_uses_child_home_region(
    cp: ControlPlane,
    world: dict,  # type: ignore[type-arg]
    clients: FakeClients,
) -> None:
    world[CHILD1].home_region = "eu-frankfurt-1"
    cp.connect_parent(clients, PARENT, None, ACTOR)  # parent home: us-ashburn-1
    cp.discover_children(clients, ACTOR)
    cp.select_child(CHILD1, ACTOR)

    clients.regions.clear()
    assert cp.verify_child(clients, CHILD1, ACTOR).ok
    regional = {(c, r) for c, r in clients.regions if c in ("CloudGuardClient", "AuditClient")}
    assert regional == {
        ("CloudGuardClient", "eu-frankfurt-1"),
        ("AuditClient", "eu-frankfurt-1"),
    }
    child = cp.state.get_tenancy(CHILD1)
    assert child is not None
    assert child.home_region == "eu-frankfurt-1"

    clients.regions.clear()
    cp.verify_child(clients, CHILD1, ACTOR)  # known now: identity calls go there too
    assert clients.regions[0] == ("IdentityClient", "eu-frankfurt-1")  # the smoke test's


def test_replacing_a_connection_deletes_its_old_local_secret(
    cp: ControlPlane, clients: FakeClients
) -> None:
    cp.connect_parent(clients, PARENT, None, ACTOR)

    def save(ref: str) -> None:
        cp.save_connection(
            Connection(
                id="",
                tenancy_ocid=PARENT,
                method=ConnectionMethod.API_KEY,
                purpose=ConnectionPurpose.SCAN,
                secret_ref=ref,
            ),
            ACTOR,
        )

    cp.state.put_secret_ciphertext("one", b"c1")
    cp.state.put_secret_ciphertext("two", b"c2")
    save("local:one")
    save("local:one")  # same ref kept
    assert cp.state.get_secret_ciphertext("one") is not None
    save("local:two")
    assert cp.state.get_secret_ciphertext("one") is None
    assert cp.state.get_secret_ciphertext("two") is not None
