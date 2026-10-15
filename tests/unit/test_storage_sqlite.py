from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oci_security_center.config import Settings
from oci_security_center.models import (
    CollectionManifest,
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    FindingStatus,
    OnboardingStatus,
    OrgRole,
    Severity,
    Tenancy,
)
from oci_security_center.storage.errors import (
    IncompleteSnapshotError,
    LeaseError,
    MaintenanceError,
    ScopeError,
    StaleGenerationError,
    StaleRunError,
)
from oci_security_center.storage.sqlite import SqliteStores, open_stores
from oci_security_center.storage.sqlite.retention import purge

T1 = "ocid1.tenancy.oc1..aaaafake0001"
T2 = "ocid1.tenancy.oc1..aaaafake0002"
D1 = "ocid1.domain.oc1..aaaafakedomain1"
D2 = "ocid1.domain.oc1..aaaafakedomain2"
T0 = datetime(2026, 10, 1, tzinfo=UTC)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_root=tmp_path / "osc")


@pytest.fixture
def s(settings: Settings) -> SqliteStores:
    return open_stores(settings)


def _scope(s: SqliteStores, dataset: str = "identity.policies", **dims: str) -> CollectionScope:
    return CollectionScope(
        generation=s.state.current_generation(), tenancy_ocid=T1, dataset=dataset, **dims
    )


def _env(key: str, run: str = "r", domain: str | None = None, **data: object) -> Envelope:
    return Envelope(
        schema_id="x.v1",
        tenancy_ocid=T1,
        record_key=key,
        data={"name": key, **data},
        run_id=run,
        domain=domain,
    )


def _manifest(
    s: SqliteStores,
    scope: CollectionScope,
    run: str,
    started: datetime = T0,
    lease: str | None = None,
    **kw: object,
) -> CollectionManifest:
    token = lease or s.state.acquire_lease(scope.lease_key, scope.generation, run, 60)
    assert token is not None
    return CollectionManifest.model_validate(
        {
            "scope": scope,
            "run_id": run,
            "lease_token": token,
            "started_at": started,
            "pages_complete": True,
            **kw,
        }
    )


def _publish(
    s: SqliteStores,
    scope: CollectionScope,
    records: list[Envelope],
    run: str,
    started: datetime = T0,
) -> object:
    manifest = _manifest(s, scope, run, started)
    try:
        return s.data.apply_snapshot(scope, records, manifest)
    finally:
        s.state.release_lease(scope.lease_key, manifest.lease_token)


def _keys(s: SqliteStores, scope: CollectionScope) -> set[str]:
    return {e.record_key for e in s.data.read_current(scope)}


def test_files_are_private(settings: Settings) -> None:
    open_stores(settings)
    assert stat.S_IMODE(settings.data_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(settings.db_path.stat().st_mode) == 0o600


# --- scoped snapshots ----------------------------------------------------------------------------
def test_snapshot_added_modified_removed(s: SqliteStores) -> None:
    scope = _scope(s)
    r1 = _publish(s, scope, [_env("p1", statements=["a"]), _env("p2")], "r1")
    assert (r1.added, r1.modified, r1.removed) == (2, 0, 0)  # type: ignore[attr-defined]
    r2 = _publish(
        s, scope, [_env("p1", statements=["b"]), _env("p3")], "r2", T0 + timedelta(hours=1)
    )
    assert (r2.added, r2.modified, r2.removed, r2.unchanged) == (1, 1, 1, 0)  # type: ignore[attr-defined]
    assert _keys(s, scope) == {"p1", "p3"}
    changes = s.data.list_changes(T1, "identity.policies")
    r2_changes = [c for c in changes if c["run_id"] == "r2"]
    assert sorted(c["change_type"] for c in r2_changes) == ["added", "modified", "removed"]
    assert {(c["generation"], c["scope_key"], c["schema_version"]) for c in r2_changes} == {
        (scope.generation, "{}", 1)
    }
    r3 = _publish(
        s,
        scope,
        [_env("p1", statements=["b"]), _env("p3"), _env("p2")],
        "r3",
        T0 + timedelta(hours=2),
    )
    assert (r3.added, r3.unchanged) == (1, 2)  # type: ignore[attr-defined]
    assert s.data.last_success(scope) is not None


def test_complete_empty_snapshot_removes_only_its_scope(s: SqliteStores) -> None:
    d1 = _scope(s, "identity_domains.users", domain=D1)
    d2 = _scope(s, "identity_domains.users", domain=D2)
    _publish(s, d1, [_env("u1", domain=D1)], "r1")
    _publish(s, d2, [_env("u2", domain=D2)], "r1")
    _publish(s, d1, [], "r2", T0 + timedelta(hours=1))  # domain 1 is now empty
    assert _keys(s, d1) == set()
    assert _keys(s, d2) == {"u2"}


def test_incomplete_collection_never_replaces_rows(s: SqliteStores) -> None:
    scope = _scope(s, "identity.compartments")
    _publish(s, scope, [_env("c1"), _env("c2")], "r1")
    later = T0 + timedelta(hours=1)
    for kw in (
        {"pages_complete": False},
        {"errors": ("429 throttled",)},
        {"expected_children": ("cA", "cB"), "visited_children": ("cA",)},
    ):
        manifest = _manifest(s, scope, "r2", later, **kw)
        with pytest.raises(IncompleteSnapshotError):
            s.data.apply_snapshot(scope, [_env("c1")], manifest)
        s.state.release_lease(scope.lease_key, manifest.lease_token)
    s.data.record_partial(_manifest(s, scope, "r2", later, expected_children=("cA",)))
    assert _keys(s, scope) == {"c1", "c2"}
    with s.db.read() as conn:
        item = conn.execute(
            "SELECT status, complete, error FROM scan_run_items WHERE run_id='r2'"
        ).fetchone()
    assert (item["status"], item["complete"]) == ("partial", 0)
    assert "missed cA" in item["error"]


def test_scope_must_match_registry_and_records(s: SqliteStores) -> None:
    with pytest.raises(ValueError, match="scoped by"):
        _publish(s, _scope(s, "identity_domains.users"), [], "r1")  # domain required
    with pytest.raises(ValueError, match="scoped by"):
        _publish(s, _scope(s, region="us-ashburn-1"), [], "r1")  # can't narrow arbitrarily
    d1 = _scope(s, "identity_domains.users", domain=D1)
    with pytest.raises(ScopeError, match="outside the domain"):
        _publish(s, d1, [_env("u1", domain=D2)], "r1")
    other = Envelope(schema_id="x", tenancy_ocid=T2, record_key="k", data={}, run_id="r")
    with pytest.raises(ScopeError, match="another tenancy"):
        _publish(s, _scope(s), [other], "r2")
    with pytest.raises(ScopeError, match="different scope"):
        s.data.apply_snapshot(_scope(s), [], _manifest(s, d1, "r3"))


def test_duplicates(s: SqliteStores) -> None:
    scope = _scope(s)
    _publish(s, scope, [_env("p1"), _env("p1")], "r1")  # identical duplicate is fine
    with pytest.raises(ScopeError, match="conflicting duplicate"):
        _publish(s, scope, [_env("p1"), _env("p1", extra=1)], "r2")


def test_lease_fencing(s: SqliteStores) -> None:
    scope = _scope(s)
    token = s.state.acquire_lease(scope.lease_key, scope.generation, "runner-a", 60)
    assert token is not None
    assert s.state.acquire_lease(scope.lease_key, scope.generation, "runner-b", 60) is None
    with pytest.raises(LeaseError):
        s.data.apply_snapshot(scope, [], _manifest(s, scope, "r1", lease="not-the-token"))
    s.state.release_lease(scope.lease_key, token)
    expired = s.state.acquire_lease(scope.lease_key, scope.generation, "runner-a", -1)
    assert expired is not None
    with pytest.raises(LeaseError, match="expired"):
        s.data.apply_snapshot(scope, [], _manifest(s, scope, "r1", lease=expired))
    assert s.state.renew_lease(scope.lease_key, expired) is False


def test_delayed_older_run_cannot_replace_newer_snapshot(s: SqliteStores) -> None:
    scope = _scope(s)
    _publish(s, scope, [_env("new")], "new-run", T0 + timedelta(hours=2))
    with pytest.raises(StaleRunError):
        _publish(s, scope, [_env("old")], "old-run", T0)
    assert _keys(s, scope) == {"new"}


def test_generation_and_maintenance_fencing(s: SqliteStores) -> None:
    scope = _scope(s)
    manifest = _manifest(s, scope, "r1")
    token = s.state.begin_maintenance("test")
    with pytest.raises(MaintenanceError):
        s.data.apply_snapshot(scope, [_env("p1")], manifest)
    with pytest.raises(MaintenanceError):
        s.state.begin_maintenance("someone-else")
    new_gen = s.state.end_maintenance(token, advance_generation=True)
    assert new_gen == scope.generation + 1
    with pytest.raises((StaleGenerationError, LeaseError)):
        s.data.apply_snapshot(scope, [_env("p1")], manifest)
    with pytest.raises(StaleGenerationError):
        s.state.acquire_lease(scope.lease_key, scope.generation, "late", 60)


def test_expired_maintenance_can_be_taken_over(s: SqliteStores) -> None:
    s.state.begin_maintenance("crashed", ttl_seconds=-1)
    token = s.state.begin_maintenance("recovery")
    s.state.end_maintenance(token)
    assert s.state.organization().state == "active"


# --- audit files ---------------------------------------------------------------------------------
def _audit(event_id: str, when: str) -> Envelope:
    return Envelope(
        schema_id="audit.events.v1",
        tenancy_ocid=T1,
        record_key=event_id,
        region="us-ashburn-1",
        data={
            "event_time": when,
            "event_type": "com.oraclecloud.identity.updatepolicy",
            "principal_id": "ocid1.user.oc1..aaaafakeuser",
            "response_status": 200,
        },
        run_id="r1",
    )


def test_audit_per_generation_idempotent_and_utc_monthly(
    s: SqliteStores, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oci_security_center.storage.sqlite.db import SqliteDatabase

    calls: list[bool] = []
    original = SqliteDatabase.write

    def spy(self: SqliteDatabase, durable: bool = False):  # type: ignore[no-untyped-def]
        if "audit" in str(self.path):
            calls.append(durable)
        return original(self, durable)

    monkeypatch.setattr(SqliteDatabase, "write", spy)
    gen = s.state.current_generation()
    events = [
        _audit("e1", "2026-09-30T23:59:00+00:00"),
        _audit("e2", "2026-09-30T23:30:00-02:00"),  # 01:30 UTC on Oct 1 -> October file
    ]
    assert s.data.append_events(gen, T1, events, "r1") == 2
    assert s.data.append_events(gen, T1, events, "r2") == 0  # overlap window -> no duplicates
    folder = settings.audit_root / f"g{gen}" / T1
    assert sorted(p.name for p in folder.glob("*.db")) == ["2026-09.db", "2026-10.db"]
    rows = s.data.query_audit(
        gen, T1, "2026-10", "principal_id = ?", ("ocid1.user.oc1..aaaafakeuser",)
    )
    assert [(r["event_id"], r["event_time"]) for r in rows] == [("e2", "2026-10-01T01:30:00+00:00")]
    assert calls  # audit batches commit with synchronous=FULL
    assert all(calls)
    with pytest.raises(ValueError, match="naive"):
        s.data.append_events(gen, T1, [_audit("e3", "2026-10-01T00:00:00")], "r3")
    with pytest.raises(StaleGenerationError):
        s.data.append_events(gen + 1, T1, events, "r4")


def test_watermarks(s: SqliteStores) -> None:
    gen = s.state.current_generation()
    assert s.data.get_watermark(gen, T1, "audit.events", "us-ashburn-1") is None
    s.data.set_watermark(gen, T1, "audit.events", "2026-10-07T00:00:00Z", "r1", "us-ashburn-1")
    s.data.set_watermark(gen, T1, "audit.events", "2026-10-08T00:00:00Z", "r2", "us-ashburn-1")
    wm = s.data.get_watermark(gen, T1, "audit.events", "us-ashburn-1")
    assert wm is not None
    assert wm.complete_through == "2026-10-08T00:00:00Z"
    with pytest.raises(StaleGenerationError):
        s.data.set_watermark(gen + 1, T1, "audit.events", "x", "r3", "us-ashburn-1")


# --- findings ------------------------------------------------------------------------------------
def _coverage(s: SqliteStores, subject: str, scope_key: str = "{}", **kw: object) -> Finding:
    return Finding.model_validate(
        {
            "source": FindingSource.COVERAGE,
            "tenancy_ocid": T1,
            "rule_id": "OSC-ACCESS-002",
            "identity": {"rule": "OSC-ACCESS-002", "subject": subject, "stage": "collect"},
            "generation": s.state.current_generation(),
            "scope_key": scope_key,
            "severity": Severity.HIGH,
            "title": "x",
            "first_seen": T0,
            "last_seen": T0,
            **kw,
        }
    )


def test_finding_identity_rules() -> None:
    with pytest.raises(ValueError, match="missing"):
        Finding(
            source=FindingSource.CLOUD_GUARD,
            tenancy_ocid=T1,
            rule_id="cg",
            identity={},
            severity=Severity.HIGH,
            title="x",
        )
    common = {
        "tenancy_ocid": T1,
        "rule_id": "detector-rule",
        "identity": {"problem_id": "ocid1.cloudguardproblem.oc1..aaaafake"},
        "severity": Severity.HIGH,
        "title": "x",
    }
    cg = Finding(source=FindingSource.CLOUD_GUARD, **common)  # type: ignore[arg-type]
    sz = Finding(source=FindingSource.SECURITY_ZONE, **common)  # type: ignore[arg-type]
    assert cg.finding_id == sz.finding_id  # re-classification is the same problem
    other_tenancy = cg.model_copy(update={"tenancy_ocid": T2})
    assert other_tenancy.finding_id != cg.finding_id


def test_simultaneous_failures_coexist_and_resolution_is_scoped(s: SqliteStores) -> None:
    gen = s.state.current_generation()
    a = _coverage(s, "identity.policies@us-ashburn-1", scope_key="scan-a")
    b = _coverage(s, "identity.policies@eu-frankfurt-1", scope_key="scan-a")
    c = _coverage(s, "cloud_guard.problems", scope_key="scan-b")
    s.data.upsert_findings([a, b, c])
    assert len(s.data.list_findings(status=FindingStatus.OPEN)) == 3

    # a complete evaluation of scope "scan-a" saw only b: a resolves, c (other scope) untouched
    resolved = s.data.resolve_absent(
        gen, FindingSource.COVERAGE, T1, "OSC-ACCESS-002", "scan-a", {b.finding_id}
    )
    assert resolved == 1
    statuses = {f.identity["subject"]: f for f in s.data.list_findings()}
    assert statuses[a.identity["subject"]].status is FindingStatus.RESOLVED
    assert statuses[a.identity["subject"]].resolved_at is not None
    assert statuses[a.identity["subject"]].last_seen == T0  # resolution != observation
    assert statuses[b.identity["subject"]].status is FindingStatus.OPEN
    assert statuses[c.identity["subject"]].status is FindingStatus.OPEN


def test_upsert_keeps_first_seen_reopens_and_respects_suppression(s: SqliteStores) -> None:
    gen = s.state.current_generation()
    f = _coverage(s, "x")
    s.data.upsert_findings([f])
    s.data.resolve_absent(gen, FindingSource.COVERAGE, T1, "OSC-ACCESS-002", "{}", set())
    later = T0 + timedelta(days=3)
    s.data.upsert_findings([f.model_copy(update={"first_seen": later, "last_seen": later})])
    [stored] = s.data.list_findings()
    assert stored.finding_id == f.finding_id
    assert (stored.status, stored.resolved_at) == (FindingStatus.OPEN, None)  # reopened
    assert (stored.first_seen, stored.last_seen) == (T0, later)

    with s.db.write() as conn:
        conn.execute("UPDATE findings SET status='suppressed'")
    s.data.upsert_findings([f])
    assert s.data.list_findings()[0].status is FindingStatus.SUPPRESSED


def test_findings_are_fenced(s: SqliteStores) -> None:
    f = _coverage(s, "x")
    token = s.state.begin_maintenance("test")
    with pytest.raises(MaintenanceError):
        s.data.upsert_findings([f])
    s.state.end_maintenance(token, advance_generation=True)
    with pytest.raises(StaleGenerationError):
        s.data.upsert_findings([f])
    assert s.data.list_findings() == []  # reads show the current generation only


# --- retention -----------------------------------------------------------------------------------
def test_retention_purge(s: SqliteStores, settings: Settings) -> None:
    gen = s.state.current_generation()
    now = datetime(2026, 10, 7, tzinfo=UTC)
    s.data.append_events(
        gen,
        T1,
        [
            _audit("old", "2026-06-15T00:00:00+00:00"),
            _audit("edge-old", "2026-07-05T00:00:00+00:00"),
            _audit("edge-new", "2026-07-20T00:00:00+00:00"),
            _audit("new", "2026-10-01T00:00:00+00:00"),
        ],
        "r1",
    )
    old = _coverage(s, "old", resolved_at=now - timedelta(days=120))
    s.data.upsert_findings([old.model_copy(update={"status": FindingStatus.RESOLVED})])
    result = purge(settings, s.db, s.data, now=now)  # cutoff = 2026-07-09
    assert any(f.endswith("2026-06.db") for f in result.files_deleted)
    assert result.rows_deleted["audit_events"] == 1
    assert result.rows_deleted["findings"] == 1
    remaining = [r["event_id"] for r in s.data.query_audit(gen, T1, "2026-07")]
    assert remaining == ["edge-new"]


def test_tenancy_roundtrip(s: SqliteStores) -> None:
    t = Tenancy(
        ocid=T1,
        name="Child One",
        alias="osc_child_one",
        org_role=OrgRole.CHILD,
        onboarding_status=OnboardingStatus.PENDING,
        subscribed_regions=("us-ashburn-1",),
    )
    s.state.upsert_tenancy(t)
    assert s.state.get_tenancy(T1) == t


def test_dataset_tiers_and_tables(s: SqliteStores) -> None:
    from oci_security_center.storage.datasets import DATASETS, datasets_for_tier

    tier1 = {d.id for d in datasets_for_tier(1)}
    assert {"identity_domains.users", "identity_domains.groups", "identity.domains"} <= tier1
    assert "cloud_guard.targets" not in tier1
    assert {d.id for d in datasets_for_tier(2)} == set(DATASETS)
    with s.db.read() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {d.table for d in DATASETS.values()} <= tables


def test_audit_append_requires_active_barrier_and_live_scope_lease(s: SqliteStores) -> None:
    gen = s.state.current_generation()
    events = [_audit("guarded", "2026-10-01T00:00:00+00:00")]
    scope = CollectionScope(
        generation=gen, tenancy_ocid=T1, dataset="audit.events", region="us-ashburn-1"
    )
    lease = s.state.acquire_lease(scope.lease_key, gen, "run", 60)
    token = s.state.begin_maintenance("backup")
    with pytest.raises(MaintenanceError):
        s.data.append_events(gen, T1, events, "run", scope=scope, lease_token=lease)
    s.state.end_maintenance(token)
    s.state.release_lease(scope.lease_key, lease)
    with pytest.raises(LeaseError):
        s.data.append_events(gen, T1, events, "run", scope=scope, lease_token=lease)
    assert not s.data.audit_db_path(gen, T1, "2026-10").exists()


def test_retention_refuses_concurrent_maintenance_and_drains_workers(
    s: SqliteStores, settings: Settings
) -> None:
    gen = s.state.current_generation()
    s.data.append_events(gen, T1, [_audit("old", "2025-01-01T00:00:00+00:00")], "r")
    path = s.data.audit_db_path(gen, T1, "2025-01")
    maintenance = s.state.begin_maintenance("backup")
    with pytest.raises(MaintenanceError):
        purge(settings, s.db, s.data)
    assert path.exists()
    s.state.end_maintenance(maintenance)
    lease = s.state.acquire_lease("worker", gen, "run", 60)
    with pytest.raises(MaintenanceError, match="did not finish"):
        purge(settings.model_copy(update={"switch_drain_seconds": 0.01}), s.db, s.data)
    assert path.exists()
    assert s.state.organization().state == "active"
    s.state.release_lease("worker", lease)
    purge(settings, s.db, s.data)
    assert not path.exists()


def test_maintenance_waits_until_monthly_commit_finishes(
    s: SqliteStores, monkeypatch: pytest.MonkeyPatch
) -> None:
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event

    entered, proceed = Event(), Event()
    original = s.data._audit_db

    def paused(path: Path):
        entered.set()
        assert proceed.wait(3)
        return original(path)

    monkeypatch.setattr(s.data, "_audit_db", paused)
    gen = s.state.current_generation()
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(
            s.data.append_events, gen, T1, [_audit("race", "2026-10-01T00:00:00+00:00")], "r"
        )
        assert entered.wait(3)
        holder = pool.submit(s.state.begin_maintenance, "backup")
        try:
            with pytest.raises(TimeoutError):
                holder.result(timeout=0.05)
        finally:
            proceed.set()
        assert writer.result(timeout=3) == 1
        token = holder.result(timeout=3)
    assert s.data.query_audit(gen, T1, "2026-10")[0]["event_id"] == "race"
    s.state.end_maintenance(token)
