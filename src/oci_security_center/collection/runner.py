"""Scan runner: runs collectors for every active tenancy (docs/collection.md §9).

* Tenancies: the parent and every child whose onboarding status is ``active``.
* Collectors run in dependency order per tenancy; tenancies run in a bounded thread pool. SDK
  clients are created per call, so no client is shared between threads.
* Every scope takes a scope lease (one active run per scope across processes), collects, and then
  either publishes a complete snapshot or records a partial/failed item — never both.
* Capability status per (tenancy, dataset, scope) records what was proven: ``supported``,
  ``unsupported`` (access denied / not found) or ``error``.
* Coverage: a failed/partial scope raises ``OSC-ACCESS-002`` for exactly that scope; only a later
  complete collection of the same scope resolves it. Disabled tiers are never touched.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

import oci

from oci_security_center.collection.base import (
    Collected,
    Collector,
    DependencyMissing,
    NotApplicable,
    TenancyContext,
    evaluation_scope,
)
from oci_security_center.config import Settings
from oci_security_center.control_plane.verify import explain_service_error
from oci_security_center.logging import get_logger
from oci_security_center.models import (
    CollectionManifest,
    CollectionScope,
    Finding,
    FindingSource,
    OnboardingStatus,
    OrgRole,
    Severity,
    Tenancy,
    utcnow,
)
from oci_security_center.oci_clients import ClientMaker
from oci_security_center.oci_clients.allowlist import ReadOnlyViolation
from oci_security_center.storage.errors import MaintenanceError, StorageError
from oci_security_center.storage.sqlite import SqliteStores

log = get_logger(__name__)

COVERAGE_RULE = "OSC-ACCESS-002"


@dataclass(frozen=True)
class ScopeOutcome:
    tenancy_ocid: str
    dataset: str
    scope_key: str
    status: str  # ok | partial | failed | skipped | not_applicable | dependency_missing
    detail: str = ""
    records: int = 0


@dataclass
class ScanSummary:
    run_id: str
    generation: int
    outcomes: list[ScopeOutcome] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for o in self.outcomes if o.status == status)

    @property
    def ok(self) -> bool:
        return all(o.status in ("ok", "not_applicable", "skipped") for o in self.outcomes)


def active_tenancies(stores: SqliteStores) -> list[Tenancy]:
    """The parent first, then every child whose onboarding status is ``active``."""
    org = stores.state.organization()
    parent = stores.state.get_tenancy(org.parent_tenancy_ocid) if org.parent_tenancy_ocid else None
    if parent is None:
        return []
    children = [
        t
        for t in stores.state.list_tenancies()
        if t.org_role is OrgRole.CHILD
        and t.parent_tenancy_ocid == parent.ocid
        and t.onboarding_status is OnboardingStatus.ACTIVE
    ]
    return [parent, *children]


class ScanRunner:
    def __init__(
        self,
        settings: Settings,
        stores: SqliteStores,
        clients: ClientMaker,
        collectors: Sequence[Collector],
        holder: str = "scan",
    ) -> None:
        self.settings = settings
        self.stores = stores
        self.clients = clients
        self.collectors = list(collectors)
        self.holder = holder

    def tenancies(self) -> list[Tenancy]:
        return active_tenancies(self.stores)

    def scan(
        self,
        only: set[str] | None = None,
        tenancy_ocids: set[str] | None = None,
        trigger: str = "manual",
    ) -> ScanSummary:
        org = self.stores.state.organization()
        if org.state != "active":
            raise MaintenanceError("OSC is in maintenance; scans are paused")
        run_id = f"scan-{uuid.uuid4().hex[:12]}"
        summary = ScanSummary(run_id, org.generation)
        targets = [t for t in self.tenancies() if tenancy_ocids is None or t.ocid in tenancy_ocids]
        if not targets:
            return summary
        parent = targets[0] if targets[0].org_role is OrgRole.PARENT else self.tenancies()[0]
        collectors = [c for c in self.collectors if only is None or c.dataset in only]
        self.stores.data.begin_scan_run(run_id, trigger, org.generation)
        workers = min(self.settings.max_workers, len(targets))
        try:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="osc-scan") as pool:
                futures = [
                    pool.submit(
                        self._tenancy,
                        TenancyContext(
                            org.generation, t, parent, run_id, self.stores.data, self.settings
                        ),
                        collectors,
                    )
                    for t in targets
                ]
                for f in futures:
                    summary.outcomes += f.result()
        finally:
            status = "ok" if summary.ok else "partial"
            self.stores.data.finish_scan_run(
                run_id,
                status,
                {s: summary.count(s) for s in {o.status for o in summary.outcomes}},
            )
        return summary

    # --- per tenancy ------------------------------------------------------------------------
    def _tenancy(self, ctx: TenancyContext, collectors: list[Collector]) -> list[ScopeOutcome]:
        outcomes: list[ScopeOutcome] = []
        for collector in collectors:
            try:
                scopes = list(collector.scopes(ctx))
            except DependencyMissing as exc:
                scope = ctx.scope(collector.dataset)  # tenancy-level marker for the failure
                self._failed(ctx, scope, "dependency", str(exc), "error")
                outcomes.append(
                    ScopeOutcome(
                        ctx.tenancy_ocid, collector.dataset, "{}", "dependency_missing", str(exc)
                    )
                )
                ctx.unavailable.add(collector.dataset)
                continue
            except NotApplicable as exc:
                self.stores.state.record_capability(
                    ctx.generation, ctx.tenancy_ocid, collector.dataset, "{}", "supported", str(exc)
                )
                outcomes.append(
                    ScopeOutcome(
                        ctx.tenancy_ocid, collector.dataset, "{}", "not_applicable", str(exc)
                    )
                )
                continue
            for scope in scopes:
                outcome = self._scope(ctx, collector, scope)
                outcomes.append(outcome)
                if outcome.status not in ("ok", "not_applicable"):
                    ctx.unavailable.add(collector.dataset)
        return outcomes

    def _scope(
        self, ctx: TenancyContext, collector: Collector, scope: CollectionScope
    ) -> ScopeOutcome:
        state = self.stores.state
        ttl = self.settings.scan_lease_seconds
        token = state.acquire_lease(scope.lease_key, ctx.generation, ctx.run_id, ttl)
        if token is None:
            return ScopeOutcome(
                ctx.tenancy_ocid, scope.dataset, scope.scope_key, "skipped", "another run holds it"
            )
        started = utcnow()
        try:
            try:
                collected = collector.collect(ctx, scope, self.clients)
            except ReadOnlyViolation:
                raise
            except NotApplicable as exc:
                state.record_capability(
                    ctx.generation,
                    ctx.tenancy_ocid,
                    scope.dataset,
                    scope.scope_key,
                    "supported",
                    str(exc),
                )
                return ScopeOutcome(
                    ctx.tenancy_ocid, scope.dataset, scope.scope_key, "not_applicable", str(exc)
                )
            except DependencyMissing as exc:
                self._failed(ctx, scope, "dependency", str(exc), "error", started, token)
                return ScopeOutcome(
                    ctx.tenancy_ocid, scope.dataset, scope.scope_key, "dependency_missing", str(exc)
                )
            except oci.exceptions.ServiceError as exc:
                denied = exc.status in (401, 403, 404)
                self._failed(
                    ctx,
                    scope,
                    "access" if denied else "source",
                    explain_service_error(exc),
                    "unsupported" if denied else "error",
                    started,
                    token,
                )
                return ScopeOutcome(
                    ctx.tenancy_ocid,
                    scope.dataset,
                    scope.scope_key,
                    "failed",
                    explain_service_error(exc),
                )
            except Exception as exc:  # network, SDK or parsing problems: report, don't crash
                log.warning("collector %s failed: %s", scope.dataset, type(exc).__name__)
                self._failed(ctx, scope, "source", type(exc).__name__, "error", started, token)
                return ScopeOutcome(
                    ctx.tenancy_ocid, scope.dataset, scope.scope_key, "failed", type(exc).__name__
                )
            return self._publish(ctx, collector, scope, collected, started, token)
        finally:
            state.release_lease(scope.lease_key, token)

    def _manifest(
        self,
        ctx: TenancyContext,
        scope: CollectionScope,
        collected: Collected,
        started: datetime,
        token: str,
    ) -> CollectionManifest:
        return CollectionManifest(
            scope=scope,
            run_id=ctx.run_id,
            lease_token=token,
            started_at=started,
            pages_complete=collected.pages_complete,
            expected_children=collected.expected_children,
            visited_children=collected.visited_children,
            errors=tuple(collected.errors),
            record_count=len(collected.records),
        )

    def _publish(
        self,
        ctx: TenancyContext,
        collector: Collector,
        scope: CollectionScope,
        collected: Collected,
        started: datetime,
        token: str,
    ) -> ScopeOutcome:
        state, data = self.stores.state, self.stores.data
        manifest = self._manifest(ctx, scope, collected, started, token)
        if not manifest.complete:
            detail = (
                "; ".join([*manifest.errors, *(f"missed {c}" for c in manifest.missing_children)])
                or "pages not exhausted"
            )
            self._failed(ctx, scope, "incomplete", detail, "error", manifest=manifest)
            return ScopeOutcome(
                ctx.tenancy_ocid,
                scope.dataset,
                scope.scope_key,
                "partial",
                detail,
                len(collected.records),
            )
        state.renew_lease(scope.lease_key, token, self.settings.scan_lease_seconds)
        try:
            data.apply_snapshot(scope, collected.records, manifest)
        except StorageError as exc:  # stale generation/lease, newer run, scope violation
            detail = f"{type(exc).__name__}: {exc}"
            if not isinstance(exc, MaintenanceError):
                data.record_partial(manifest, status="failed")
            return ScopeOutcome(ctx.tenancy_ocid, scope.dataset, scope.scope_key, "failed", detail)
        state.record_capability(
            ctx.generation, ctx.tenancy_ocid, scope.dataset, scope.scope_key, "supported"
        )
        data.resolve_absent(
            ctx.generation,
            FindingSource.COVERAGE,
            ctx.tenancy_ocid,
            COVERAGE_RULE,
            evaluation_scope(scope),
            set(),
        )
        self._evaluate(ctx, collector, scope, collected)
        return ScopeOutcome(
            ctx.tenancy_ocid, scope.dataset, scope.scope_key, "ok", "", len(collected.records)
        )

    def _evaluate(
        self,
        ctx: TenancyContext,
        collector: Collector,
        scope: CollectionScope,
        collected: Collected,
    ) -> None:
        ev = collector.evaluate(ctx, scope, collected.records)
        key = evaluation_scope(scope)
        findings = [
            f.model_copy(update={"generation": ctx.generation, "scope_key": key})
            for f in ev.findings
        ]
        self.stores.data.upsert_findings(findings)
        for source, rule in ev.rules:
            self.stores.data.resolve_absent(
                ctx.generation,
                source,
                ctx.tenancy_ocid,
                rule,
                key,
                {f.finding_id for f in findings if f.rule_id == rule},
            )

    def _failed(
        self,
        ctx: TenancyContext,
        scope: CollectionScope,
        stage: str,
        detail: str,
        capability: str,
        started: datetime | None = None,
        token: str | None = None,
        manifest: CollectionManifest | None = None,
    ) -> None:
        state, data = self.stores.state, self.stores.data
        if manifest is None:
            manifest = self._manifest(
                ctx,
                scope,
                Collected(pages_complete=False, errors=[detail]),
                started or utcnow(),
                token or "-",
            )
        try:
            data.record_partial(manifest, status="failed" if stage != "incomplete" else "partial")
            state.record_capability(
                ctx.generation, ctx.tenancy_ocid, scope.dataset, scope.scope_key, capability, detail
            )
            last = data.last_success(scope)
            dims = scope.dimensions()
            data.upsert_findings(
                [
                    Finding(
                        source=FindingSource.COVERAGE,
                        tenancy_ocid=ctx.tenancy_ocid,
                        rule_id=COVERAGE_RULE,
                        identity={
                            "rule": COVERAGE_RULE,
                            "subject": scope.dataset,
                            "stage": stage,
                            **dims,
                        },
                        generation=ctx.generation,
                        scope_key=evaluation_scope(scope),
                        severity=Severity.HIGH,
                        title=f"{scope.dataset} not collected"
                        + (f" ({', '.join(f'{k} {v}' for k, v in dims.items())})" if dims else ""),
                        description=(
                            f"{detail}. Last complete collection: "
                            f"{last.isoformat() if last else 'never'}. Data shown for this scope "
                            "is stale or missing."
                        ),
                        region=scope.region,
                    )
                ]
            )
        except StorageError as exc:  # e.g. the organization switched mid-scan: nothing to record
            log.warning("could not record coverage failure: %s", type(exc).__name__)
