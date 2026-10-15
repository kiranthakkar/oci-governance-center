"""Audit ingestion coordinator (docs/delta-fetching.md §1-§3, docs/collection.md §3).

Per (generation, tenancy, region), under a scope lease:

* **forward** cursor: from ``complete_through - overlap`` (clamped to retention) up to
  ``now - ingestion_delay``, in bounded chunks, at most ``audit_forward_chunks_per_run`` per run;
* **backfill** cursor: walks back from the earliest complete start towards the retention cutoff,
  at most ``audit_backfill_chunks_per_run`` chunks per run (forward always runs first);
* **reconcile**: persists a separate backward sweep cursor across retained chunks (rate-budgeted);
  it never moves the forward or backfill checkpoint.

Every chunk is fetched to exhaustion. A source that can't prove a chunk complete gets the chunk
split in half down to ``audit_min_split_minutes``; a minimal chunk that still can't be proven
complete is a
**gap**: recorded in the ledger, raised as ``OSC-ACCESS-002`` and never bridged — the cursor stops
before it. Events are written durably (``append_events``) before ``commit_interval`` records the
interval and moves the checkpoint in one durable, generation- and lease-fenced transaction, so a
crash at any point only causes an idempotent replay.

Sources: Logging Search over ``<tenancy>/_Audit_Include_Subcompartment`` (default) or the Audit API
per compartment (``OSC_AUDIT_SOURCE=audit_api``). Only allow-listed fields are kept (collection §1).
Source limits and event-ID uniqueness are capability gate Q2.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import oci

from oci_security_center.collection.base import (
    DependencyMissing,
    TenancyContext,
    evaluation_scope,
)
from oci_security_center.collection.runner import (
    COVERAGE_RULE,
    ScanRunner,
    ScanSummary,
    ScopeOutcome,
)
from oci_security_center.config import Settings
from oci_security_center.control_plane.verify import explain_service_error
from oci_security_center.logging import get_logger
from oci_security_center.models import (
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    Severity,
    utcnow,
)
from oci_security_center.oci_clients import (
    ClientMaker,
    audit_log_search,
    list_all,
    paged_responses,
    to_plain,
)
from oci_security_center.oci_clients.allowlist import ReadOnlyViolation
from oci_security_center.storage.datasets import AUDIT_DATASET
from oci_security_center.storage.errors import StorageError
from oci_security_center.storage.sqlite import SqliteStores
from oci_security_center.storage.sqlite.data_store import (
    AUDIT_BACKFILL,
    AUDIT_FORWARD,
    AUDIT_RECONCILE,
)

log = get_logger(__name__)

# Allow-listed audit fields (collection §1). Nothing else from the event is stored.
AUDIT_FIELDS = (
    "event_id",
    "event_type",
    "event_time",
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


@dataclass
class Fetched:
    events: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = True
    detail: str = ""


class AuditSource(Protocol):
    name: str
    query_version: str

    def fetch(
        self, ctx: TenancyContext, region: str, start: datetime, end: datetime
    ) -> Fetched: ...


def _status(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _keep(event: dict[str, Any]) -> dict[str, Any] | None:
    """Apply the field allow-list; events without ID or time can't be stored idempotently."""
    if not event.get("event_id") or not event.get("event_time"):
        return None
    return {k: event.get(k) for k in AUDIT_FIELDS}


def normalize_log_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    """A Logging Search result for an ``_Audit`` log (Audit v2 schema in ``logContent``)."""
    content = raw.get("logContent") or {}
    data = content.get("data") or {}
    identity = data.get("identity") or {}
    return _keep(
        {
            "event_id": content.get("id"),
            "event_type": content.get("type"),
            "event_time": content.get("time") or raw.get("datetime"),
            "source": content.get("source"),
            "principal_id": identity.get("principalId"),
            "principal_name": identity.get("principalName"),
            "auth_type": identity.get("authType"),
            "ip_address": identity.get("ipAddress"),
            "user_agent": identity.get("userAgent"),
            "compartment_id": data.get("compartmentId"),
            "resource_id": data.get("resourceId"),
            "action": (data.get("request") or {}).get("action"),
            "response_status": _status((data.get("response") or {}).get("status")),
        }
    )


def normalize_audit_event(plain: dict[str, Any]) -> dict[str, Any] | None:
    """An ``AuditClient.list_events`` event converted with ``oci.util.to_dict``."""
    data = plain.get("data") or {}
    identity = data.get("identity") or {}
    return _keep(
        {
            "event_id": plain.get("event_id"),
            "event_type": plain.get("event_type"),
            "event_time": plain.get("event_time"),
            "source": plain.get("source"),
            "principal_id": identity.get("principal_id"),
            "principal_name": identity.get("principal_name"),
            "auth_type": identity.get("auth_type"),
            "ip_address": identity.get("ip_address"),
            "user_agent": identity.get("user_agent"),
            "compartment_id": data.get("compartment_id"),
            "resource_id": data.get("resource_id"),
            "action": (data.get("request") or {}).get("action"),
            "response_status": _status((data.get("response") or {}).get("status")),
        }
    )


class LogSearchSource:
    """``LogSearchClient.search_logs`` with the SDK response generator, paged to exhaustion."""

    name = "logging_search"
    query_version = "1"

    def __init__(self, clients: ClientMaker, result_cap: int | None = None) -> None:
        self.clients, self.result_cap = clients, result_cap

    def fetch(self, ctx: TenancyContext, region: str, start: datetime, end: datetime) -> Fetched:
        client: Any = self.clients(oci.loggingsearch.LogSearchClient, region)
        details = audit_log_search(start, end, ctx.tenancy_ocid)
        out = Fetched()
        for response in paged_responses(client.search_logs, details, limit=1000):
            for result in response.data.results or []:
                event = normalize_log_entry(result.data or {})
                if event is None:
                    out.complete, out.detail = False, "log entry without event ID or time"
                    continue
                out.events.append(event)
        if self.result_cap is not None and len(out.events) >= self.result_cap:
            out.complete, out.detail = False, f"result cap {self.result_cap} reached"
        return out


class AuditApiSource:
    """``AuditClient.list_events`` per active compartment (complete per-compartment fallback)."""

    name = "audit_api"
    query_version = "1"

    def __init__(self, clients: ClientMaker) -> None:
        self.clients = clients

    def fetch(self, ctx: TenancyContext, region: str, start: datetime, end: datetime) -> Fetched:
        client: Any = self.clients(oci.audit.AuditClient, region)
        out = Fetched()
        compartments = [
            str(c["id"])
            for c in ctx.current("identity.compartments")
            if c.get("lifecycle_state") in (None, "ACTIVE")
        ]
        for cid in compartments:
            for e in list_all(client.list_events, cid, start, end):
                event = normalize_audit_event(to_plain(e))
                if event is None:
                    out.complete, out.detail = False, "event without ID or time"
                    continue
                out.events.append(event)
        return out


def _floor_minute(t: datetime) -> datetime:
    return t.astimezone(UTC).replace(second=0, microsecond=0)


def _chunks(start: datetime, end: datetime, size: timedelta) -> list[tuple[datetime, datetime]]:
    out = []
    t = start
    while t < end:
        out.append((t, min(t + size, end)))
        t += size
    return out


class AuditIngestor:
    def __init__(
        self,
        settings: Settings,
        stores: SqliteStores,
        clients: ClientMaker,
        source: AuditSource | None = None,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self.settings = settings
        self.stores = stores
        self.clients = clients
        self.source = source or (
            AuditApiSource(clients)
            if settings.audit_source == "audit_api"
            else LogSearchSource(clients, settings.audit_search_result_cap)
        )
        self.now = now

    # --- entry points ------------------------------------------------------------------------
    def ingest(self, tenancy_ocids: set[str] | None = None, reconcile: bool = False) -> ScanSummary:
        runner = ScanRunner(self.settings, self.stores, self.clients, [])
        org = self.stores.state.organization()
        run_id = f"audit-{uuid.uuid4().hex[:12]}"
        summary = ScanSummary(run_id, org.generation)
        targets = [
            t for t in runner.tenancies() if tenancy_ocids is None or t.ocid in tenancy_ocids
        ]
        if not targets or org.state != "active":
            return summary
        parent = runner.tenancies()[0]
        self.stores.data.begin_scan_run(
            run_id, "audit-reconcile" if reconcile else "audit", org.generation
        )
        for t in targets:
            ctx = TenancyContext(org.generation, t, parent, run_id, self.stores.data, self.settings)
            summary.outcomes += self._tenancy(
                ctx,
                parent_ctx=TenancyContext(
                    org.generation, parent, parent, run_id, self.stores.data, self.settings
                ),
                reconcile=reconcile,
            )
        self.stores.data.finish_scan_run(
            run_id,
            "ok" if summary.ok else "partial",
            {s: summary.count(s) for s in {o.status for o in summary.outcomes}},
        )
        return summary

    def _regions(self, ctx: TenancyContext) -> list[str]:
        return sorted(
            str(r["region_name"])
            for r in ctx.current("identity.region_subscriptions")
            if r.get("status") == "READY"
        )

    def _tenancy(
        self, ctx: TenancyContext, parent_ctx: TenancyContext, reconcile: bool
    ) -> list[ScopeOutcome]:
        try:
            regions = self._regions(ctx)
            parent_regions = set(self._regions(parent_ctx))
        except DependencyMissing as exc:
            scope = ctx.scope(AUDIT_DATASET)
            self._coverage(ctx, scope, "dependency", str(exc))
            return [
                ScopeOutcome(ctx.tenancy_ocid, AUDIT_DATASET, "{}", "dependency_missing", str(exc))
            ]
        outcomes = []
        for region in regions:
            scope = ctx.scope(AUDIT_DATASET, region=region)
            if ctx.tenancy.ocid != parent_ctx.tenancy.ocid and region not in parent_regions:
                # Cross-tenancy reads need the region in both tenancies (control-plane §2.6).
                detail = f"parent tenancy is not subscribed to {region}"
                self._coverage(ctx, scope, "region_not_shared", detail)
                outcomes.append(
                    ScopeOutcome(ctx.tenancy_ocid, AUDIT_DATASET, scope.scope_key, "failed", detail)
                )
                continue
            outcomes.append(self._region(ctx, scope, reconcile))
        return outcomes

    # --- one region ------------------------------------------------------------------------------
    def _region(self, ctx: TenancyContext, scope: CollectionScope, reconcile: bool) -> ScopeOutcome:
        state = self.stores.state
        token = state.acquire_lease(
            scope.lease_key, ctx.generation, ctx.run_id, self.settings.scan_lease_seconds
        )
        if token is None:
            return ScopeOutcome(ctx.tenancy_ocid, AUDIT_DATASET, scope.scope_key, "skipped", "busy")
        try:
            self._check_files(ctx, scope)
            if reconcile:
                problems = self._reconcile(ctx, scope, token)
            else:
                problems = self._forward(ctx, scope, token)
                if not problems:
                    problems = self._backfill(ctx, scope, token)
        except ReadOnlyViolation:
            raise
        except StorageError as exc:  # fenced: switch, lost lease
            return ScopeOutcome(
                ctx.tenancy_ocid, AUDIT_DATASET, scope.scope_key, "failed", type(exc).__name__
            )
        finally:
            state.release_lease(scope.lease_key, token)
        if problems:
            return ScopeOutcome(
                ctx.tenancy_ocid, AUDIT_DATASET, scope.scope_key, "partial", problems
            )
        self.stores.data.resolve_absent(
            ctx.generation,
            FindingSource.COVERAGE,
            ctx.tenancy_ocid,
            COVERAGE_RULE,
            evaluation_scope(scope),
            set(),
        )
        state.record_capability(
            ctx.generation,
            ctx.tenancy_ocid,
            AUDIT_DATASET,
            scope.scope_key,
            "supported",
            f"source {self.source.name}",
        )
        return ScopeOutcome(ctx.tenancy_ocid, AUDIT_DATASET, scope.scope_key, "ok")

    def _bounds(self) -> tuple[datetime, datetime]:
        end = _floor_minute(
            self.now() - timedelta(minutes=self.settings.audit_ingestion_delay_minutes)
        )
        days = self.settings.audit_backfill_days or self.settings.retention_for(AUDIT_DATASET)
        return end - timedelta(days=days), end

    def _chunk_size(self) -> timedelta:
        return timedelta(minutes=self.settings.audit_chunk_minutes)

    def _forward(self, ctx: TenancyContext, scope: CollectionScope, token: str) -> str:
        cutoff, end = self._bounds()
        wm = self.stores.data.get_watermark(
            ctx.generation, ctx.tenancy_ocid, AUDIT_FORWARD, scope.region
        )
        if wm is None:
            start = max(cutoff, end - timedelta(minutes=self.settings.audit_initial_minutes))
        else:
            start = max(
                cutoff,
                datetime.fromisoformat(wm.complete_through)
                - timedelta(hours=self.settings.audit_overlap_hours),
            )
        chunks = _chunks(start, end, self._chunk_size())[
            : self.settings.audit_forward_chunks_per_run
        ]
        return self._ingest(ctx, scope, token, "forward", chunks)

    def _backfill(self, ctx: TenancyContext, scope: CollectionScope, token: str) -> str:
        cutoff, _ = self._bounds()
        data = self.stores.data
        wm = data.get_watermark(ctx.generation, ctx.tenancy_ocid, AUDIT_BACKFILL, scope.region)
        if wm is None:  # nothing behind the forward cursor's first interval yet
            ledger = data.ledger(ctx.generation, ctx.tenancy_ocid, str(scope.region), "forward")
            first = [r for r in ledger if r["status"] == "complete"]
            if not first:
                return ""
            earliest = datetime.fromisoformat(first[0]["interval_start"])
        else:
            earliest = datetime.fromisoformat(wm.complete_through)
        chunks: list[tuple[datetime, datetime]] = []
        t = earliest
        size = self._chunk_size()
        while t > cutoff and len(chunks) < self.settings.audit_backfill_chunks_per_run:
            chunks.append((max(cutoff, t - size), t))
            t -= size
        return self._ingest(ctx, scope, token, "backfill", chunks)

    def _reconcile(self, ctx: TenancyContext, scope: CollectionScope, token: str) -> str:
        cutoff, end = self._bounds()
        oldest_overlap = end - timedelta(hours=self.settings.audit_overlap_hours)
        wm = self.stores.data.get_watermark(
            ctx.generation, ctx.tenancy_ocid, AUDIT_RECONCILE, scope.region
        )
        resume = datetime.fromisoformat(wm.complete_through) if wm else oldest_overlap
        # Reaching the moving retention cutoff completes a sweep; start the next one.
        if resume <= cutoff:
            resume = oldest_overlap
        resume = min(resume, oldest_overlap)
        recent_first: list[tuple[datetime, datetime]] = []
        while resume > cutoff and len(recent_first) < self.settings.audit_reconcile_chunks_per_run:
            start = max(cutoff, resume - self._chunk_size())
            recent_first.append((start, resume))
            resume = start
        return self._ingest(ctx, scope, token, "reconcile", recent_first)

    def _ingest(
        self,
        ctx: TenancyContext,
        scope: CollectionScope,
        token: str,
        cursor: str,
        chunks: Sequence[tuple[datetime, datetime]],
    ) -> str:
        """Fetch + store chunks in order; stop at the first gap. Returns problems ('' if none)."""
        for start, end in chunks:
            for piece_start, piece_end, fetched, error in self._fetch_proven(
                ctx, scope, start, end, reverse=cursor != "forward"
            ):
                if error is not None:
                    self._gap(ctx, scope, token, cursor, piece_start, piece_end, error)
                    return error
                assert fetched is not None
                inserted = self._store(ctx, scope, token, fetched)
                self.stores.state.renew_lease(
                    scope.lease_key, token, self.settings.scan_lease_seconds
                )
                self.stores.data.commit_interval(
                    scope,
                    token,
                    cursor,
                    piece_start,
                    piece_end,
                    ctx.run_id,
                    self.source.name,
                    self.source.query_version,
                    events=len(fetched.events),
                    inserted=inserted,
                )
        return ""

    def _fetch_proven(
        self,
        ctx: TenancyContext,
        scope: CollectionScope,
        start: datetime,
        end: datetime,
        reverse: bool = False,
    ) -> list[tuple[datetime, datetime, Fetched | None, str | None]]:
        """Fetch [start, end); split until each piece is provably complete or minimal."""
        try:
            fetched = self.source.fetch(ctx, str(scope.region), start, end)
        except ReadOnlyViolation:
            raise
        except oci.exceptions.ServiceError as exc:
            return [(start, end, None, explain_service_error(exc))]
        except DependencyMissing as exc:
            return [(start, end, None, str(exc))]
        except Exception as exc:  # network/parse problems are gaps, not crashes
            return [(start, end, None, type(exc).__name__)]
        if fetched.complete:
            return [(start, end, fetched, None)]
        if end - start <= timedelta(minutes=self.settings.audit_min_split_minutes):
            return [(start, end, None, fetched.detail or "source could not prove completeness")]
        middle = _floor_minute(start + (end - start) / 2)
        if middle <= start:
            middle = start + (end - start) / 2
        first_bounds, second_bounds = (
            ((middle, end), (start, middle)) if reverse else ((start, middle), (middle, end))
        )
        first = self._fetch_proven(ctx, scope, *first_bounds, reverse=reverse)
        if any(error for *_, error in first):
            return first
        return first + self._fetch_proven(ctx, scope, *second_bounds, reverse=reverse)

    def _store(
        self, ctx: TenancyContext, scope: CollectionScope, token: str, fetched: Fetched
    ) -> int:
        envelopes = [
            Envelope(
                schema_id=f"{AUDIT_DATASET}.v1",
                tenancy_ocid=ctx.tenancy_ocid,
                record_key=str(e["event_id"]),
                data=e,
                run_id=ctx.run_id,
                region=scope.region,
                compartment_ocid=e.get("compartment_id"),
                resource_ocid=e.get("resource_id"),
            )
            for e in fetched.events
        ]
        return self.stores.data.append_events(
            ctx.generation, ctx.tenancy_ocid, envelopes, ctx.run_id, scope=scope, lease_token=token
        )

    def _gap(
        self,
        ctx: TenancyContext,
        scope: CollectionScope,
        token: str,
        cursor: str,
        start: datetime,
        end: datetime,
        error: str,
    ) -> None:
        self.stores.data.commit_interval(
            scope,
            token,
            cursor,
            start,
            end,
            ctx.run_id,
            self.source.name,
            self.source.query_version,
            status="gap",
            detail=error,
        )
        self._coverage(ctx, scope, "gap", f"{start.isoformat()} to {end.isoformat()}: {error}")

    def _check_files(self, ctx: TenancyContext, scope: CollectionScope) -> None:
        """A month the ledger says is covered must still have its file (delta-fetching §3)."""
        present = self.stores.data.audit_months(ctx.generation, ctx.tenancy_ocid)
        cutoff, _ = self._bounds()
        for row in self.stores.data.ledger(ctx.generation, ctx.tenancy_ocid, str(scope.region)):
            if row["status"] != "complete" or not row["events"]:
                continue
            month = row["interval_start"][:7]
            if month in present or datetime.fromisoformat(row["interval_end"]) < cutoff:
                continue
            since = datetime.fromisoformat(f"{month}-01T00:00:00+00:00")
            self.stores.data.invalidate_audit_coverage(
                ctx.generation,
                ctx.tenancy_ocid,
                str(scope.region),
                since,
                f"audit file for {month} is missing; refetching",
            )
            self._coverage(ctx, scope, "rebuild", f"audit file for {month} was missing; refetching")
            return

    def _coverage(
        self, ctx: TenancyContext, scope: CollectionScope, stage: str, detail: str
    ) -> None:
        dims = scope.dimensions()
        try:
            self.stores.state.record_capability(
                ctx.generation,
                ctx.tenancy_ocid,
                AUDIT_DATASET,
                scope.scope_key,
                "unsupported" if stage == "region_not_shared" else "error",
                detail,
            )
            self.stores.data.upsert_findings(
                [
                    Finding(
                        source=FindingSource.COVERAGE,
                        tenancy_ocid=ctx.tenancy_ocid,
                        rule_id=COVERAGE_RULE,
                        identity={
                            "rule": COVERAGE_RULE,
                            "subject": AUDIT_DATASET,
                            "stage": stage,
                            **dims,
                        },
                        generation=ctx.generation,
                        scope_key=evaluation_scope(scope),
                        severity=Severity.HIGH,
                        title="Audit events not collected"
                        + (f" ({scope.region})" if scope.region else ""),
                        description=f"{detail}. Activity views for this scope have a gap.",
                        region=scope.region,
                    )
                ]
            )
        except StorageError as exc:
            log.warning("could not record audit coverage: %s", type(exc).__name__)
