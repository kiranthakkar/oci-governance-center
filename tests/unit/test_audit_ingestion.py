"""Audit ingestion coordinator (docs/delta-fetching.md): checkpoints, gaps, replay, recovery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import oci
import pytest
from oci.response import Response
from test_collectors import FakeWorld, Tenant

from fakes import service_error
from oci_security_center.collection.audit import (
    AuditIngestor,
    Fetched,
    LogSearchSource,
    normalize_audit_event,
    normalize_log_entry,
)
from oci_security_center.collection.base import TenancyContext
from oci_security_center.collection.registry import collectors_for_tier
from oci_security_center.collection.runner import ScanRunner
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import FindingStatus, OnboardingStatus, OrgRole, Tenancy
from oci_security_center.storage.sqlite import SqliteStores, open_stores
from oci_security_center.storage.sqlite.data_store import AUDIT_BACKFILL, AUDIT_FORWARD

P = "ocid1.tenancy.oc1..aaaafakeparent"
C = "ocid1.tenancy.oc1..aaaafakechild1"
REGION = "us-ashburn-1"
NOW = datetime(2026, 10, 1, 12, 5, tzinfo=UTC)  # ingestion delay 5 min -> end = 12:00


def _event(eid: str, when: datetime) -> dict[str, Any]:
    return {"event_id": eid, "event_time": when.isoformat(), "event_type": "x"} | dict.fromkeys(
        (
            "source",
            "principal_id",
            "principal_name",
            "auth_type",
            "ip_address",
            "user_agent",
            "compartment_id",
            "resource_id",
            "action",
            "response_status",
        )
    )


class FakeSource:
    name = "fake"
    query_version = "1"

    def __init__(self) -> None:
        self.events: dict[str, list[dict[str, Any]]] = {P: [], C: []}
        self.fail_between: tuple[datetime, datetime] | None = None
        self.incomplete_longer_than: timedelta | None = None
        self.calls: list[tuple[str, datetime, datetime]] = []
        self.hook: Any = None

    def fetch(self, ctx: TenancyContext, region: str, start: datetime, end: datetime) -> Fetched:
        self.calls.append((ctx.tenancy_ocid, start, end))
        if self.hook:
            self.hook()
        if self.fail_between and start < self.fail_between[1] and end > self.fail_between[0]:
            raise service_error(500, "InternalServerError")
        if self.incomplete_longer_than and end - start > self.incomplete_longer_than:
            return Fetched(complete=False, detail="too many results")
        rows = [
            e
            for e in self.events[ctx.tenancy_ocid]
            if start <= datetime.fromisoformat(e["event_time"]) < end
        ]
        return Fetched(rows)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_root=tmp_path,
        deployment=DeploymentMode.WORKSTATION,
        audit_chunk_minutes=30,
        audit_initial_minutes=60,
        audit_overlap_hours=1,
        audit_backfill_days=1,
        audit_backfill_chunks_per_run=4,
        audit_min_split_minutes=10,
    )


@pytest.fixture
def stores(settings: Settings) -> SqliteStores:
    s = open_stores(settings)
    s.state.set_setting("parent_tenancy_ocid", P)
    s.state.set_organization_parent(P, 1)
    for ocid, role in ((P, OrgRole.PARENT), (C, OrgRole.CHILD)):
        s.state.upsert_tenancy(
            Tenancy(
                ocid=ocid,
                name=ocid[-6:],
                alias=f"a{ocid[-6:]}",
                org_role=role,
                onboarding_status=OnboardingStatus.ACTIVE,
                home_region=REGION,
                parent_tenancy_ocid=P if role is OrgRole.CHILD else None,
            )
        )
    world = FakeWorld({P: Tenant(P), C: Tenant(C)})
    ScanRunner(settings, s, world, collectors_for_tier(1)).scan(
        only={"identity.region_subscriptions", "identity.compartments"}
    )
    return s


@pytest.fixture
def source() -> FakeSource:
    return FakeSource()


def _ingestor(
    settings: Settings, stores: SqliteStores, source: FakeSource, now: datetime = NOW
) -> AuditIngestor:
    return AuditIngestor(settings, stores, FakeWorld({}), source=source, now=lambda: now)


def _wm(stores: SqliteStores, tenancy: str, cursor: str = AUDIT_FORWARD) -> str | None:
    wm = stores.data.get_watermark(1, tenancy, cursor, REGION)
    return wm.complete_through if wm else None


def _stored(stores: SqliteStores, tenancy: str, month: str = "2026-10") -> list[str]:
    return sorted(r["event_id"] for r in stores.data.query_audit(1, tenancy, month, limit=10_000))


def test_first_run_forward_then_backfill(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.events[P] = [
        _event("a", NOW - timedelta(minutes=30)),
        _event("old", NOW - timedelta(hours=2)),
    ]
    summary = _ingestor(settings, stores, source).ingest()
    assert {o.status for o in summary.outcomes} == {"ok"}
    assert _wm(stores, P) == "2026-10-01T12:00:00+00:00"
    # forward covered 11:00-12:00, backfill 4 chunks of 30 min back: 09:00-11:00
    assert _wm(stores, P, AUDIT_BACKFILL) == "2026-10-01T09:00:00+00:00"
    assert _stored(stores, P) == ["a", "old"]
    ledger = stores.data.ledger(1, P, REGION)
    assert {r["cursor"] for r in ledger} == {"forward", "backfill"}
    assert all(r["status"] == "complete" for r in ledger)


def test_overlap_rereads_and_counts_late_events(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.events[P] = [_event("a", NOW - timedelta(minutes=30))]
    _ingestor(settings, stores, source).ingest()
    # an event that happened at 11:50 shows up only now (late), inside the 1h overlap
    source.events[P].append(_event("late", NOW - timedelta(minutes=15)))
    later = NOW + timedelta(minutes=30)
    _ingestor(settings, stores, source, later).ingest()
    assert _stored(stores, P) == ["a", "late"]
    assert _wm(stores, P) == "2026-10-01T12:30:00+00:00"
    forward = stores.data.ledger(1, P, REGION, "forward")
    assert sum(r["inserted"] for r in forward) == 2  # a once, late once; replays insert nothing


def test_gap_stops_the_cursor_and_is_retried(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.fail_between = (NOW - timedelta(minutes=35), NOW - timedelta(minutes=34))
    summary = _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    assert [o.status for o in summary.outcomes] == ["partial"]
    assert _wm(stores, P) == "2026-10-01T11:30:00+00:00"  # first chunk ok, second is a gap
    gaps = [r for r in stores.data.ledger(1, P, REGION) if r["status"] == "gap"]
    assert gaps
    assert "500" in gaps[0]["detail"]
    [cov] = stores.data.list_findings(rule_id="OSC-ACCESS-002", status=FindingStatus.OPEN)
    assert cov.identity["stage"] == "gap"
    assert cov.identity["region"] == REGION

    source.fail_between = None
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    assert _wm(stores, P) == "2026-10-01T12:00:00+00:00"
    assert stores.data.list_findings(rule_id="OSC-ACCESS-002", status=FindingStatus.OPEN) == []


def test_unprovable_chunks_are_split_until_proven(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.incomplete_longer_than = timedelta(minutes=15)
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    pieces = [
        (r["interval_start"][11:16], r["interval_end"][11:16])
        for r in stores.data.ledger(1, P, REGION, "forward")
    ]
    assert pieces[:2] == [("11:00", "11:15"), ("11:15", "11:30")]
    assert _wm(stores, P) == "2026-10-01T12:00:00+00:00"

    source.incomplete_longer_than = timedelta(minutes=5)  # below the 10-minute minimum split
    stores2 = stores
    summary = _ingestor(settings, stores2, source, NOW + timedelta(hours=2)).ingest(
        tenancy_ocids={P}
    )
    assert [o.status for o in summary.outcomes] == ["partial"]
    assert any(r["status"] == "gap" for r in stores.data.ledger(1, P, REGION, "forward"))


def test_crash_between_event_commit_and_checkpoint_replays(
    settings: Settings, stores: SqliteStores, source: FakeSource, monkeypatch: pytest.MonkeyPatch
) -> None:
    source.events[P] = [_event("a", NOW - timedelta(minutes=45))]
    original = stores.data.commit_interval

    def crash(*_: Any, **__: Any) -> None:
        raise KeyboardInterrupt("killed after events were durable")

    monkeypatch.setattr(stores.data, "commit_interval", crash)
    with pytest.raises(KeyboardInterrupt):
        _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    assert _stored(stores, P) == ["a"]  # events durable
    assert _wm(stores, P) is None  # checkpoint not moved

    monkeypatch.setattr(stores.data, "commit_interval", original)
    with stores.db.write() as conn:  # the crashed run's lease expires; simulate by clearing it
        conn.execute("DELETE FROM scope_leases")
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    assert _stored(stores, P) == ["a"]  # idempotent replay
    assert _wm(stores, P) == "2026-10-01T12:00:00+00:00"


def test_month_boundary_events_land_in_both_files(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    now = datetime(2026, 10, 1, 0, 35, tzinfo=UTC)  # window 2026-09-30 23:30 - 2026-10-01 00:30
    source.events[P] = [
        _event("sep", datetime(2026, 9, 30, 23, 45, tzinfo=UTC)),
        _event("oct", datetime(2026, 10, 1, 0, 15, tzinfo=UTC)),
    ]
    _ingestor(settings, stores, source, now).ingest(tenancy_ocids={P})
    assert _stored(stores, P, "2026-09") == ["sep"]
    assert _stored(stores, P, "2026-10") == ["oct"]


def test_lost_month_file_is_refetched(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.events[P] = [_event("a", NOW - timedelta(minutes=30))]
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    path = stores.data.audit_db_path(1, P, "2026-10")
    stores.data.forget_audit_dbs(path.parent)
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)

    _ingestor(settings, stores, source, NOW + timedelta(minutes=10)).ingest(tenancy_ocids={P})
    assert _stored(stores, P) == ["a"]
    rebuilt = [
        f
        for f in stores.data.list_findings(rule_id="OSC-ACCESS-002")
        if f.identity["stage"] == "rebuild"
    ]
    assert rebuilt


def test_switch_mid_run_is_fenced(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    source.events[P] = [_event("a", NOW - timedelta(minutes=30))]

    def switch() -> None:
        token = stores.state.begin_maintenance("switch")
        stores.state.end_maintenance(token, advance_generation=True)
        source.hook = None

    source.hook = switch
    summary = _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    assert [o.status for o in summary.outcomes] == ["failed"]
    assert stores.data.ledger(1, P, REGION) == []
    assert stores.data.get_watermark(2, P, AUDIT_FORWARD, REGION) is None


def test_region_not_shared_with_parent(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    from oci_security_center.models import CollectionManifest, CollectionScope

    scope = CollectionScope(generation=1, tenancy_ocid=C, dataset="identity.region_subscriptions")
    token = stores.state.acquire_lease(scope.lease_key, 1, "t", 60)
    assert token
    later = datetime.now(UTC) + timedelta(hours=1)
    env = [
        stores.data.read_current(scope).__next__(),
    ]
    extra = env[0].model_copy(
        update={
            "record_key": "eu-frankfurt-1",
            "data": {**env[0].data, "region_name": "eu-frankfurt-1", "is_home_region": False},
        }
    )
    stores.data.apply_snapshot(
        scope,
        [env[0], extra],
        CollectionManifest(
            scope=scope, run_id="x", lease_token=token, started_at=later, pages_complete=True
        ),
    )
    summary = _ingestor(settings, stores, source).ingest(tenancy_ocids={C})
    statuses = {o.scope_key: o.status for o in summary.outcomes}
    assert statuses['{"region":"eu-frankfurt-1"}'] == "failed"
    assert statuses['{"region":"us-ashburn-1"}'] == "ok"


def test_reconcile_inserts_late_events_without_moving_checkpoints(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P})
    before = (_wm(stores, P), _wm(stores, P, AUDIT_BACKFILL))
    source.events[P] = [_event("very-late", NOW - timedelta(hours=3))]
    _ingestor(settings, stores, source).ingest(tenancy_ocids={P}, reconcile=True)
    assert "very-late" in _stored(stores, P)
    assert (_wm(stores, P), _wm(stores, P, AUDIT_BACKFILL)) == before
    assert any(r["cursor"] == "reconcile" for r in stores.data.ledger(1, P, REGION))


# --- normalizers and the Logging Search source ----------------------------------------------------
LOG_ENTRY = {
    "datetime": 1759320000000,
    "logContent": {
        "id": "evt-1",
        "type": "com.oraclecloud.identityControlPlane.UpdatePolicy",
        "time": "2026-10-01T11:00:00.000Z",
        "source": "PolicyName",
        "data": {
            "compartmentId": "ocid1.compartment.oc1..c",
            "resourceId": "ocid1.policy.oc1..p",
            "identity": {
                "principalId": "ocid1.user.oc1..u",
                "principalName": "alice",
                "authType": "natv",
                "ipAddress": "192.0.2.10",
                "userAgent": "Console",
                "credentials": "SHOULD-NOT-BE-KEPT",
            },
            "request": {"action": "PUT", "headers": {"Authorization": ["SECRET"]}},
            "response": {"status": "200", "payload": {"x": 1}},
        },
    },
}


def test_log_entry_normalization_keeps_only_allowed_fields() -> None:
    e = normalize_log_entry(LOG_ENTRY)
    assert e is not None
    assert e["event_id"] == "evt-1"
    assert (e["principal_id"], e["ip_address"], e["action"], e["response_status"]) == (
        "ocid1.user.oc1..u",
        "192.0.2.10",
        "PUT",
        200,
    )
    flat = repr(e)
    for leaked in ("SECRET", "SHOULD-NOT-BE-KEPT", "payload"):
        assert leaked not in flat
    assert normalize_log_entry({"logContent": {"time": "x"}}) is None  # no ID: not storable


def test_audit_api_normalization() -> None:
    plain = {
        "event_id": "e2",
        "event_type": "t",
        "event_time": "2026-10-01T11:00:00+00:00",
        "source": "s",
        "data": {
            "compartment_id": "c",
            "resource_id": "r",
            "identity": {"principal_id": "u", "ip_address": "198.51.100.1", "credentials": "K"},
            "request": {"action": "GET", "headers": {"x": "y"}},
            "response": {"status": "404"},
        },
    }
    e = normalize_audit_event(plain)
    assert e is not None
    assert (e["principal_id"], e["response_status"], e["action"]) == ("u", 404, "GET")
    assert "K" not in repr(e.values())


def test_log_search_source_pages_to_exhaustion(stores: SqliteStores, settings: Settings) -> None:
    pages = [
        ([LOG_ENTRY], {"opc-next-page": "p2"}),
        ([{**LOG_ENTRY, "logContent": {**LOG_ENTRY["logContent"], "id": "evt-2"}}], {}),
    ]
    calls: list[Any] = []

    class FakeLogSearch:
        def search_logs(self, details: Any, page: str | None = None, **_: Any) -> Response:
            calls.append((details.search_query, page))
            results, headers = pages[0 if page is None else 1]
            data = oci.loggingsearch.models.SearchResponse(
                results=[oci.loggingsearch.models.SearchResult(data=r) for r in results],
                summary=oci.loggingsearch.models.SearchResultSummary(result_count=len(results)),
            )
            return Response(200, headers, data, None)

    tenancy = stores.state.get_tenancy(P)
    assert tenancy is not None
    ctx = TenancyContext(1, tenancy, tenancy, "r", stores.data, settings)
    src = LogSearchSource(lambda *a, **k: FakeLogSearch())  # type: ignore[arg-type,return-value]
    fetched = src.fetch(ctx, REGION, NOW - timedelta(hours=1), NOW)
    assert fetched.complete
    assert [e["event_id"] for e in fetched.events] == ["evt-1", "evt-2"]
    assert calls[0][0] == f'search "{P}/_Audit_Include_Subcompartment"'
    assert [c[1] for c in calls] == [None, "p2"]


def test_split_backfill_retries_gap_before_advancing_past_it(
    settings: Settings, stores: SqliteStores
) -> None:
    class SplitSource(FakeSource):
        def fetch(
            self, ctx: TenancyContext, region: str, start: datetime, end: datetime
        ) -> Fetched:
            if end - start > timedelta(minutes=15):
                return Fetched(complete=False)
            return super().fetch(ctx, region, start, end)

    s = settings.model_copy(update={"audit_backfill_days": 10, "audit_backfill_chunks_per_run": 1})
    earliest = NOW - timedelta(days=5)
    stores.data.set_watermark(1, P, AUDIT_BACKFILL, earliest.isoformat(), "seed", REGION)
    tenant = stores.state.get_tenancy(P)
    ctx = TenancyContext(1, tenant, tenant, "split", stores.data, s)
    scope = ctx.scope("audit.events", region=REGION)
    token = stores.state.acquire_lease(scope.lease_key, 1, "split", 60)
    source = SplitSource()
    source.fail_between = (earliest - timedelta(minutes=15), earliest)
    ingestor = _ingestor(s, stores, source)
    assert ingestor._backfill(ctx, scope, token)
    assert _wm(stores, P, AUDIT_BACKFILL) == earliest.isoformat()
    source.fail_between = None
    source.events[P] = [_event("gap-event", earliest - timedelta(minutes=5))]
    assert not ingestor._backfill(ctx, scope, token)
    assert "gap-event" in _stored(stores, P, "2026-09")
    assert _wm(stores, P, AUDIT_BACKFILL) == (earliest - timedelta(minutes=30)).isoformat()
    stores.state.release_lease(scope.lease_key, token)


def test_reconcile_resumes_after_restart_and_cycles_retained_window(
    settings: Settings, stores: SqliteStores, source: FakeSource
) -> None:
    s = settings.model_copy(update={"audit_reconcile_chunks_per_run": 4, "audit_chunk_minutes": 60})
    source.events[P] = [_event("old-late", NOW - timedelta(hours=20))]
    for _ in range(6):
        reopened = open_stores(s)
        _ingestor(s, reopened, source).ingest(tenancy_ocids={P}, reconcile=True)
    assert "old-late" in _stored(stores, P, "2026-09")
    assert min(start for _, start, _ in source.calls) == NOW.replace(minute=0) - timedelta(days=1)
    source.calls.clear()
    _ingestor(s, stores, source).ingest(tenancy_ocids={P}, reconcile=True)
    assert max(end for _, _, end in source.calls) == NOW.replace(minute=0) - timedelta(hours=1)
