"""The ``osc scheduler`` process (docs/collection.md §9; decision 2026-10-09: own process).

Jobs and default intervals:

* ``identity`` (6 h): identity collectors, then the parent's required-policy re-check (§7.1.9);
* ``governance`` (1 h): Cloud Guard, Security Zones, Cloud Advisor;
* ``audit`` (15 min): audit ingestion (forward, then backfill);
* ``reconcile`` (daily): audit reconciliation over the retained window;
* ``retention`` (daily): the retention purge;
* every tick: finish/roll back an interrupted organization switch.

Every job runs right after start, then on its interval. A failing job is logged and retried on its
next interval; it never stops the others. Nothing runs while OSC is in maintenance. Several
scheduler processes are safe: scope leases serialize the actual work.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from oci_security_center.collection.audit import AuditIngestor
from oci_security_center.collection.registry import GROUPS, collectors_for_tier
from oci_security_center.collection.runner import ScanRunner
from oci_security_center.control_plane.service import Actor
from oci_security_center.logging import get_logger
from oci_security_center.runtime import Runtime
from oci_security_center.storage.sqlite.reset import recover_interrupted_switch
from oci_security_center.storage.sqlite.retention import purge

log = get_logger(__name__)
SCHEDULER = Actor("scheduler", "system")


@dataclass
class Job:
    name: str
    interval_s: float
    action: Callable[[], object]
    next_at: float = 0.0  # due immediately
    failures: int = 0


def build_jobs(rt: Runtime) -> list[Job]:
    s = rt.settings
    collectors = collectors_for_tier(s.collection_tier)

    def scan(group: str) -> Callable[[], object]:
        def go() -> object:
            runner = ScanRunner(s, rt.stores, rt.scan_clients(), collectors, holder="scheduler")
            summary = runner.scan(only=set(GROUPS[group]), trigger=f"scheduler:{group}")
            if group == "identity":
                rt.control_plane.refresh_parent_checks(rt.scan_clients(), SCHEDULER)
            return summary

        return go

    def audit(reconcile: bool) -> Callable[[], object]:
        return lambda: AuditIngestor(s, rt.stores, rt.scan_clients()).ingest(reconcile=reconcile)

    minute, day = 60.0, 86_400.0
    return [
        Job("identity", s.schedule_identity_minutes * minute, scan("identity")),
        Job("governance", s.schedule_governance_minutes * minute, scan("governance")),
        Job("audit", s.schedule_audit_minutes * minute, audit(False)),
        Job("reconcile", day, audit(True)),
        Job("retention", day, lambda: purge(s, rt.stores.db, rt.stores.data)),
    ]


class Scheduler:
    def __init__(
        self,
        rt: Runtime,
        jobs: list[Job] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rt = rt
        self.jobs = jobs if jobs is not None else build_jobs(rt)
        self.clock = clock
        self.stop_event = threading.Event()

    def tick(self) -> list[str]:
        """Run every due job once. Returns the names of jobs that ran."""
        stores = self.rt.stores
        done = recover_interrupted_switch(stores.db, stores.state, stores.data)
        if done:
            log.warning("scheduler: %s", done)
        if stores.state.organization().state != "active":
            return []
        ran = []
        for job in self.jobs:
            now = self.clock()
            if now < job.next_at:
                continue
            job.next_at = now + job.interval_s
            try:
                job.action()
                job.failures = 0
            except Exception as exc:  # one job failing must not stop the scheduler
                job.failures += 1
                log.error("scheduler job %s failed (%d in a row): %s", job.name, job.failures, exc)
            ran.append(job.name)
        return ran

    def serve_forever(self, poll_s: float = 30.0) -> None:
        log.info("scheduler started with %d jobs", len(self.jobs))
        while not self.stop_event.is_set():
            self.tick()
            self.stop_event.wait(poll_s)
        log.info("scheduler stopped")
