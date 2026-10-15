"""View models for the Tier 1 dashboards (docs/collection.md §2-§3, architecture §2).

Rules every view follows:

* coverage is shown next to data: collection tier, last complete collection, scope, and any
  unsupported / failed / partial / stale / never-collected state;
* unknown is never rendered as healthy or empty: a scope that was never collected says so, and
  data from a scope whose latest attempt failed is labelled stale;
* access views show *observed* IAM statements and group membership; identity-domain admin-role
  grants arrive with Tier 4, and no view claims effective permissions.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from oci_security_center.collection.base import DependencyMissing, TenancyContext
from oci_security_center.collection.registry import GROUPS, collectors_for_tier
from oci_security_center.collection.runner import active_tenancies
from oci_security_center.models import (
    FindingSource,
    FindingStatus,
    Severity,
    Tenancy,
    utcnow,
)
from oci_security_center.runtime import Runtime
from oci_security_center.storage.datasets import AUDIT_DATASET
from oci_security_center.storage.sqlite.data_store import AUDIT_BACKFILL, AUDIT_FORWARD

ACCESS_LIMITATION = (
    "Shows IAM policy statements and identity-domain group membership as collected. "
    "Identity-domain administrator roles are not included at Tier 1, and conditions, resource "
    "policies and service-specific authorization are not evaluated: this is not an "
    "effective-permissions view."
)


@dataclass
class ScopeRow:
    tenancy: str
    tenancy_ocid: str
    dataset: str
    scope: str
    state: str  # complete | partial | failed | stale | never | not_applicable | unsupported
    last_success: datetime | None = None
    detail: str = ""

    @property
    def pill(self) -> str:
        return {"complete": "detected", "not_applicable": "detected"}.get(
            self.state, "missing" if self.state in ("failed", "partial") else "unknown"
        )


def _interval(rt: Runtime, dataset: str) -> timedelta:
    s = rt.settings
    if dataset == AUDIT_DATASET:
        return timedelta(minutes=s.schedule_audit_minutes)
    if dataset in GROUPS["governance"]:
        return timedelta(minutes=s.schedule_governance_minutes)
    if dataset in GROUPS["identity"]:
        return timedelta(minutes=s.schedule_identity_minutes)
    return timedelta(minutes=s.schedule_guardrails_minutes)


def _scope_label(scope_key: str) -> str:
    dims = json.loads(scope_key) if scope_key else {}
    return ", ".join(f"{k} {v}" for k, v in dims.items()) or "whole tenancy"


def tenancies(rt: Runtime) -> list[Tenancy]:
    return active_tenancies(rt.stores)


def context(rt: Runtime, tenancy: Tenancy) -> TenancyContext:
    gen = rt.stores.state.current_generation()
    parent = tenancies(rt)[0] if tenancies(rt) else tenancy
    return TenancyContext(gen, tenancy, parent, "view", rt.stores.data, rt.settings)


def coverage(rt: Runtime) -> list[ScopeRow]:
    """Every expected (tenancy, dataset, scope) with its collection state."""
    now = utcnow()
    status = {
        (r["tenancy_ocid"], r["dataset"], r["scope_key"]): r for r in rt.stores.data.scope_status()
    }
    caps = {
        (c["tenancy_ocid"], c["capability"], c["scope_key"]): c
        for c in rt.stores.state.capabilities(rt.stores.state.current_generation())
    }
    rows: list[ScopeRow] = []
    datasets = [c.dataset for c in collectors_for_tier(rt.settings.collection_tier)]
    for t in tenancies(rt):
        seen = {k for k in status if k[0] == t.ocid} | {k for k in caps if k[0] == t.ocid}
        for dataset in [*datasets, AUDIT_DATASET]:
            keys = sorted(k for k in seen if k[1] == dataset) or [(t.ocid, dataset, "{}")]
            for key in keys:
                rows.append(_row(rt, t, key, status.get(key), caps.get(key), now))
    return rows


def _row(
    rt: Runtime,
    t: Tenancy,
    key: tuple[str, str, str],
    st: dict[str, Any] | None,
    cap: dict[str, Any] | None,
    now: datetime,
) -> ScopeRow:
    _, dataset, scope_key = key
    last = datetime.fromisoformat(st["last_success"]) if st and st["last_success"] else None
    row = ScopeRow(t.name, t.ocid, dataset, _scope_label(scope_key), "never", last)
    if dataset == AUDIT_DATASET:
        return _audit_row(rt, row, cap)
    newer_cap = cap is not None and (st is None or cap["checked_at"] > (st["last_attempt"] or ""))
    if cap and newer_cap and cap["status"] == "supported" and cap["detail"]:
        row.state, row.detail = "not_applicable", cap["detail"]  # e.g. Cloud Guard disabled
        return row
    if st is None:
        if cap and cap["status"] in ("unsupported", "error"):
            row.state, row.detail = (
                "unsupported" if cap["status"] == "unsupported" else "failed",
                cap["detail"],
            )
        return row
    latest = st["last_status"]
    if latest in ("failed", "partial"):
        row.state, row.detail = latest, st["last_error"] or ""
    elif last is None:
        row.state = "never"
    elif now - last > 2 * _interval(rt, dataset):
        row.state, row.detail = "stale", f"last complete collection {last:%Y-%m-%d %H:%M} UTC"
    else:
        row.state = "complete"
    if cap and cap["status"] == "unsupported":
        row.state, row.detail = "unsupported", cap["detail"]
    return row


def _audit_row(rt: Runtime, row: ScopeRow, cap: dict[str, Any] | None) -> ScopeRow:
    if cap is None:
        return row
    region = json.loads(cap["scope_key"]).get("region") if cap["scope_key"] != "{}" else None
    gen = rt.stores.state.current_generation()
    wm = rt.stores.data.get_watermark(gen, row.tenancy_ocid, AUDIT_FORWARD, region)
    if wm:
        row.last_success = datetime.fromisoformat(wm.complete_through)
    if cap["status"] == "supported":
        stale = row.last_success is None or utcnow() - row.last_success > 2 * _interval(
            rt, AUDIT_DATASET
        ) + timedelta(minutes=rt.settings.audit_ingestion_delay_minutes)
        row.state = "stale" if stale else "complete"
    else:
        row.state = "unsupported" if cap["status"] == "unsupported" else "failed"
        row.detail = cap["detail"]
    return row


# --- compartments ------------------------------------------------------------------------------
@dataclass
class Node:
    id: str
    name: str
    state: str
    depth: int


def compartments(rt: Runtime, tenancy: Tenancy) -> tuple[list[Node], bool]:
    """Compartment tree (depth-first). Second value: False if never collected completely."""
    try:
        rows = context(rt, tenancy).current("identity.compartments")
    except DependencyMissing:
        return [], False
    children: dict[str | None, list[dict[str, Any]]] = {}
    for r in rows:
        parent = None if r["id"] == tenancy.ocid else r.get("compartment_id")
        children.setdefault(parent, []).append(r)
    out: list[Node] = []

    def walk(parent: str | None, depth: int) -> None:
        for r in sorted(children.get(parent, []), key=lambda r: str(r.get("name"))):
            out.append(Node(str(r["id"]), str(r.get("name")), str(r.get("lifecycle_state")), depth))
            walk(str(r["id"]), depth + 1)

    walk(None, 0)
    return out, True


# --- access --------------------------------------------------------------------------------------
@dataclass
class DomainView:
    id: str
    name: str
    users: list[dict[str, Any]] | None  # None = not collected completely
    groups: list[dict[str, Any]] | None
    dynamic_groups: list[dict[str, Any]] | None


@dataclass
class AccessView:
    domains: list[DomainView] = field(default_factory=list)
    domains_known: bool = False
    policies: list[dict[str, Any]] | None = None
    limitation: str = ACCESS_LIMITATION


def access(rt: Runtime, tenancy: Tenancy) -> AccessView:
    ctx = context(rt, tenancy)
    view = AccessView()
    try:
        view.policies = sorted(ctx.current("identity.policies"), key=lambda p: str(p.get("name")))
    except DependencyMissing:
        view.policies = None
    try:
        domains = ctx.current("identity.domains")
        view.domains_known = True
    except DependencyMissing:
        return view

    def data(dataset: str, domain: str) -> list[dict[str, Any]] | None:
        try:
            return ctx.current(dataset, domain=domain)
        except DependencyMissing:
            return None

    users_by_id: dict[str, str] = {}
    for d in sorted(domains, key=lambda d: str(d.get("display_name"))):
        did = str(d["id"])
        users = data("identity_domains.users", did)
        for u in users or []:
            users_by_id[str(u["id"])] = str(u["user_name"])
        groups = data("identity_domains.groups", did)
        for g in groups or []:
            g["member_names"] = [
                users_by_id.get(str(m["value"]), str(m["value"])) for m in g["members"]
            ]
        view.domains.append(
            DomainView(
                did,
                str(d.get("display_name")),
                users,
                groups,
                data("identity_domains.dynamic_groups", did),
            )
        )
    return view


# --- governance ----------------------------------------------------------------------------------
@dataclass
class GovernanceRow:
    tenancy: Tenancy
    cloud_guard: str  # ENABLED / DISABLED / unknown
    reporting_region: str | None
    problems: Counter[str]
    advisor: str  # enabled / not enabled / unknown
    pending_recommendations: int | None


def governance(rt: Runtime) -> tuple[list[GovernanceRow], list[Any]]:
    rows = []
    for t in tenancies(rt):
        ctx = context(rt, t)
        try:
            cfg = ctx.current("cloud_guard.configuration")
            cg = str(cfg[0].get("status")) if cfg else "unknown"
            region = cfg[0].get("reporting_region") if cfg else None
        except DependencyMissing:
            cg, region = "unknown", None
        try:
            enrolled = any(e.get("status") == "ACTIVE" for e in ctx.current("optimizer.enrollment"))
            advisor = "enabled" if enrolled else "not enabled"
        except DependencyMissing:
            advisor = "unknown"
        try:
            pending: int | None = sum(
                1 for r in ctx.current("optimizer.recommendations") if r.get("status") == "PENDING"
            )
        except DependencyMissing:
            pending = None
        open_problems = rt.stores.data.list_findings(
            tenancy_ocid=t.ocid, rule_id="CG-PROBLEM", status=FindingStatus.OPEN
        )
        rows.append(
            GovernanceRow(
                t, cg, region, Counter(f.severity.value for f in open_problems), advisor, pending
            )
        )
    findings = [
        f
        for f in rt.stores.data.list_findings(status=FindingStatus.OPEN)
        if f.source
        in (
            FindingSource.CLOUD_GUARD,
            FindingSource.SECURITY_ZONE,
            FindingSource.ADVISOR,
            FindingSource.GOVERNANCE,
        )
    ]
    order = list(Severity)
    findings.sort(key=lambda f: (order.index(f.severity), f.tenancy_ocid))
    return rows, findings


# --- activity ------------------------------------------------------------------------------------
@dataclass
class RegionActivity:
    tenancy: Tenancy
    region: str
    forward: datetime | None
    backfill_from: datetime | None
    gaps: int
    days: list[tuple[str, int]]


def activity(rt: Runtime, days: int = 14) -> list[RegionActivity]:
    gen = rt.stores.state.current_generation()
    data = rt.stores.data
    today = utcnow().date()
    wanted = {str(today - timedelta(days=i)) for i in range(days)}
    out = []
    for t in tenancies(rt):
        months = sorted({d[:7] for d in wanted})
        counts = [c for c in data.audit_daily_counts(gen, t.ocid, months) if c["day"] in wanted]
        ctx = context(rt, t)
        try:
            regions = sorted(
                str(r["region_name"])
                for r in ctx.current("identity.region_subscriptions")
                if r.get("status") == "READY"
            )
        except DependencyMissing:
            regions = sorted({str(c["region"]) for c in counts})
        for region in regions:
            fw = data.get_watermark(gen, t.ocid, AUDIT_FORWARD, region)
            bf = data.get_watermark(gen, t.ocid, AUDIT_BACKFILL, region)
            ledger = data.ledger(gen, t.ocid, region)
            out.append(
                RegionActivity(
                    t,
                    region,
                    datetime.fromisoformat(fw.complete_through) if fw else None,
                    datetime.fromisoformat(bf.complete_through) if bf else None,
                    sum(1 for r in ledger if r["status"] == "gap"),
                    sorted((c["day"], int(c["events"])) for c in counts if c["region"] == region),
                )
            )
    return out
