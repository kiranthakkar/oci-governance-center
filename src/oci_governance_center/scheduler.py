"""Dedicated scan worker: web requests only queue jobs; OCI calls run in this process."""

from __future__ import annotations

import logging
import secrets
import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import timedelta
from typing import Any

from .diagnostics import PublicFailure, safe_reason
from .models import now
from .scans import ScanControl
from .service import Service
from .storage import StaleWork

logger = logging.getLogger(__name__)


class ScanWorker:
    """Execute one organization job at a time while maintaining an independent heartbeat."""

    def __init__(self, service: Service) -> None:
        self.service = service
        self.control = ScanControl(service.store)
        self.owner = secrets.token_hex(16)
        service.worker = self.owner

    def execute(self, job: dict[str, Any]) -> None:
        """Collect every enabled target, including Audit, then report complete/partial coverage."""
        generation = int(job["generation"])
        logger.info("Scan %s started (trigger=%s)", job["id"], job["source"])
        status, message = "completed", ""
        try:
            self.service.scan("all", expected_generation=generation)
            logger.info("Scan %s: inventory and governance finished; collecting Audit", job["id"])
            self.service.scan("audit", expected_generation=generation)
            current, parent, blocked = self.service.store.state()
            if current != generation or parent is None:
                raise StaleWork("Organization changed")
            if blocked:
                raise PublicFailure("Parent scanner credentials failed; collection is stopped.")
            coverage = self.service.store.rows("coverage", generation)
            failed = [row for row in coverage if row["status"] == "failed"]
            if failed:
                status = "partial"
                message = f"{len(failed)} collection scopes have incomplete coverage; see Coverage."
        except StaleWork:
            logger.info("Scan %s stopped because the organization changed", job["id"])
            return  # Replaced organizations cannot finish or publish jobs in the new generation.
        except Exception as error:
            status, message = "failed", safe_reason(error)
            logger.warning("Scan failed: %s", message)
        try:
            self.control.finish(generation, job["id"], self.owner, status, message)
            logger.info("Scan %s finished (status=%s)", job["id"], status)
        except StaleWork:
            return

    def run_once(self) -> bool:
        """Drain one queued or due job; useful for one-shot execution and deterministic tests."""
        self.control.heartbeat()
        generation, parent, _ = self.service.store.state()
        if parent is None:
            return False
        self.control.enqueue_due(generation)
        job = self.control.claim(generation, self.owner)
        if not job:
            return False
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.execute, job)
            while not wait([future], timeout=5).done:
                self.control.heartbeat()
                self.control.renew(generation, job["id"], self.owner)
            future.result()
        return True

    def run(self, stop: threading.Event) -> None:
        """Poll the durable queue/schedule every five seconds, renewing active work leases."""
        logger.info("Scan worker started; checking queued and scheduled scans every five seconds")
        active: Future[None] | None = None
        job: dict[str, Any] | None = None
        last_signature: tuple[Any, ...] | None = None
        purge_due = now()
        with ThreadPoolExecutor(max_workers=1) as pool:
            while not stop.is_set() or active is not None:
                try:
                    self.control.heartbeat()
                    generation, parent, blocked = self.service.store.state()
                    if parent is not None and not stop.is_set():
                        configured = tuple(
                            (child.ocid, child.revision, child.status == "paused")
                            for child in self.service.store.children(generation)
                            if child.domain is not None
                        )
                        signature = (generation, configured)
                        if signature != last_signature and not blocked:
                            if last_signature is not None or not self.control.jobs(generation):
                                self.control.enqueue(
                                    generation, "system", "configuration", followup=True
                                )
                            last_signature = signature
                        self.control.enqueue_due(generation)
                    if active is not None and active.done():
                        active.result()
                        active, job = None, None
                    if active is not None and job is not None:
                        self.control.renew(int(job["generation"]), job["id"], self.owner)
                    elif parent is not None and not blocked and not stop.is_set():
                        job = self.control.claim(generation, self.owner)
                        if job:
                            active = pool.submit(self.execute, job)
                    if now() >= purge_due:
                        self.service.store.purge(self.service.settings.retention_days)
                        purge_due = now() + timedelta(days=1)
                except StaleWork:
                    pass
                except Exception as error:
                    logger.warning("Scan worker check failed: %s", safe_reason(error))
                if stop.is_set():
                    if active is not None:
                        threading.Event().wait(5)
                else:
                    stop.wait(5)
