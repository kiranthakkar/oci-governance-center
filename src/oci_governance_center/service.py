"""Application operations connecting verified identities, fenced storage and collection."""

from __future__ import annotations

import json
import logging
import secrets
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any

import oci

from .analyzers import governance
from .auth.scanner import Exchange, ScanAccessFailure, api_signer, bind_identity, verify_parent
from .collectors.audit import read_interval
from .collectors.inventory import discover, inventory, public_error
from .config import Settings
from .diagnostics import verification_step
from .models import (
    Batch,
    Child,
    ChildCredentials,
    Domain,
    Finding,
    Parent,
    Scope,
    domain_origin,
    now,
)
from .oci_clients import all_items, client
from .storage import StaleWork, Store

logger = logging.getLogger(__name__)

# Tenancy collection leases expire quickly after a crash but are renewed while a scan is alive.
LEASE_SECONDS = 600
LEASE_RENEW_SECONDS = 60


class Service:
    """Read-only tenancy operations; only local application state is modified."""

    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings, self.store = settings, store

    def candidate(self, owner: str, parent: Parent, expected_generation: int | None = None) -> str:
        """Verify candidate credentials; activation also requires human admin OIDC."""
        generation, _, _ = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed")
        verified = verify_parent(parent)
        # Discovery establishes that this is actually an organization parent before installation.
        with verification_step("parent organization ownership validation"):
            discover(api_signer(verified), verified.domain)
        with verification_step("saving encrypted enrollment candidate"):
            return self.store.candidate(owner, generation, verified)

    def discover(self, expected_generation: int | None = None) -> None:
        """Reconcile only complete organization discovery; failure never marks children departed."""
        generation, parent, blocked = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed before discovery")
        if parent is None or blocked:
            return
        scope = Scope(
            tenancy=parent.domain.tenancy_ocid,
            dataset="organization.children",
            region=parent.domain.home_region,
        )
        try:
            children = discover(api_signer(parent), parent.domain)
        except Exception as error:
            self.store.publish(
                generation, Batch(scope=scope, complete=False, error=public_error(error))
            )
            return
        with self.store.db() as db:
            self.store.fence(db, generation)
            saved = {child.ocid: child for child in self.store_children(db)}
            seen = {child.ocid for child in children}
            for child in children:
                previous = saved.get(child.ocid)
                if previous is None:
                    db.execute(
                        "INSERT INTO children VALUES(?,?)", (child.ocid, child.model_dump_json())
                    )
                elif previous.status == "departed":
                    # A rejoined child keeps its history but must be configured and verified again.
                    rejoined = previous.model_copy(
                        update={
                            "name": child.name,
                            "status": "not_configured",
                            "revision": previous.revision + 1,
                            "error": "",
                        }
                    )
                    db.execute(
                        "UPDATE children SET data=? WHERE ocid=?",
                        (rejoined.model_dump_json(), child.ocid),
                    )
            for old in saved.values():
                if old.ocid not in seen and old.status != "departed":
                    departed = old.model_copy(
                        update={"status": "departed", "revision": old.revision + 1}
                    )
                    db.execute(
                        "UPDATE children SET data=? WHERE ocid=?",
                        (departed.model_dump_json(), old.ocid),
                    )
                    # Confirmed departure: monitoring stops, so its exchange secret is not kept.
                    db.execute("DELETE FROM child_credentials WHERE ocid=?", (old.ocid,))
        self.store.publish(generation, Batch(scope=scope))

    @staticmethod
    def store_children(db: Any) -> list[Child]:
        """Read child records inside an existing transaction."""
        return [
            Child.model_validate_json(r[0])
            for r in db.execute("SELECT data FROM children").fetchall()
        ]

    def configure_child(
        self,
        child_id: str,
        url: str,
        expected_generation: int | None = None,
        client_id: str = "",
        client_secret: str = "",
    ) -> Child:
        """Verify a configured child UPST then begin accessible datasets automatically."""
        generation, parent, blocked = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed")
        if parent is None or blocked:
            raise ValueError("Verify the parent scanner credentials first")
        child = next((c for c in self.store.children(generation) if c.ocid == child_id), None)
        if child is None or child.status == "departed":
            raise ValueError("Child is not in the discovered organization")
        url = domain_origin(url)
        saved = self.store.child_credentials(generation, child_id)
        same_domain = child.domain is not None and child.domain.url == url
        if not client_id and saved and same_domain:
            client_id = saved.client_id
        if not client_secret and saved and same_domain and client_id == saved.client_id:
            client_secret = saved.client_secret.get_secret_value()
        if not client_id or not client_secret:
            raise ScanAccessFailure(
                "Enter the child confidential application's client ID and secret. "
                "A changed client ID or domain URL requires a new secret."
            )
        credentials = ChildCredentials.model_validate(
            {"client_id": client_id, "client_secret": client_secret}
        )
        exchange = Exchange(parent, credentials)
        try:
            domain, user_ocid = exchange.discover_child(child_id, url)
        finally:
            exchange.close()
        candidate = child.model_copy(
            update={
                "domain": domain,
                "user_ocid": user_ocid,
                "home_region": domain.home_region,
                "revision": child.revision + 1,
                "status": "error",
            }
        )
        with self.store.db() as db:
            self.store.fence(db, generation)
            current = db.execute("SELECT data FROM children WHERE ocid=?", (child_id,)).fetchone()
            if not current or Child.model_validate_json(current[0]).revision != child.revision:
                raise StaleWork("Child changed during verification")
            candidate = candidate.model_copy(update={"status": "active", "error": ""})
            db.execute(
                "UPDATE children SET data=? WHERE ocid=?", (candidate.model_dump_json(), child_id)
            )
            db.execute(
                "INSERT OR REPLACE INTO child_credentials VALUES(?,?)",
                (
                    child_id,
                    self.store.encrypt(
                        {
                            "client_id": credentials.client_id,
                            "client_secret": credentials.client_secret.get_secret_value(),
                        }
                    ),
                ),
            )
        return next(c for c in self.store.children() if c.ocid == child_id)

    def pause(self, child_id: str, expected_generation: int | None = None) -> None:
        """Pause a discovered child and fence in-flight collection without deleting history."""
        generation, _, _ = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed")
        with self.store.db() as db:
            self.store.fence(db, generation)
            row = db.execute("SELECT data FROM children WHERE ocid=?", (child_id,)).fetchone()
            if not row:
                raise ValueError("Child not found")
            child = Child.model_validate_json(row[0])
            if child.status == "departed":
                raise ValueError("Child left the organization")
            paused = child.model_copy(update={"status": "paused", "revision": child.revision + 1})
            db.execute(
                "UPDATE children SET data=? WHERE ocid=?", (paused.model_dump_json(), child_id)
            )

    def repair(
        self, key: str, fingerprint: str, user: str, expected_generation: int | None = None
    ) -> None:
        """Verify replacement parent API credentials; keep human login independent."""
        generation, parent, _ = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed")
        if parent is None:
            raise ValueError("No enrolled parent")
        candidate = verify_parent(
            Parent.model_validate(
                {
                    **self.store.parent_data(parent),
                    "private_key": key,
                    "fingerprint": fingerprint,
                    "user_ocid": user,
                }
            )
        )
        # model_copy does not validate; serialize/revalidate before calling verify_parent elsewhere.
        candidate = Parent.model_validate(candidate.model_dump())
        with self.store.db() as db:
            self.store.fence(db, generation)
            # Advance generation so in-flight workers using old credentials cannot publish.
            db.execute(
                "UPDATE state SET generation=generation+1,parent=?,blocked=0 WHERE id=1",
                (self.store.encrypt(self.store.parent_data(candidate)),),
            )
            db.execute("DELETE FROM sessions")
            db.execute("DELETE FROM leases")
            db.execute("DELETE FROM candidates")
            db.execute("UPDATE scan_schedule SET generation=generation+1")
            db.execute(
                "UPDATE scan_jobs SET status='interrupted',finished_at=?,error=? "
                "WHERE status='running'",
                (now().isoformat(), "Credentials changed during scan; retry the scan."),
            )
            db.execute("UPDATE scan_jobs SET generation=generation+1")
        # Existing history is retained. Audit files remain in their source generation; new work
        # writes into the new generation and interval replay remains deduplicated per active file.

    def confirm_key(self, generation: int, parent: Parent) -> bool:
        """Confirm an invalid key only using the parent's GetTenancy, never a child's denial."""
        try:
            actual = (
                client("identity", api_signer(parent), parent.domain.home_region)
                .get_tenancy(parent.domain.tenancy_ocid)
                .data
            )
            if actual.id != parent.domain.tenancy_ocid:
                raise ValueError("Parent identity changed")
            return True
        except oci.exceptions.ServiceError as error:
            if error.status == 401:
                self.store.block(generation, True)
            raise

    def scan_one(self, generation: int, parent: Parent, child: Child | None, family: str) -> None:
        """Collect a tenancy with its own signer and scoped publication."""
        domain = child.domain if child else parent.domain
        if domain is None:
            return
        scope = Scope(
            tenancy=domain.tenancy_ocid, dataset="authentication", region=domain.home_region
        )
        # Failures after authentication are recorded here and cleared by the next success.
        runner = scope.model_copy(update={"dataset": family + ".runner"})
        owner = secrets.token_hex(16)
        lease_key = json.dumps([generation, domain.tenancy_ocid])
        if not self.store.lease(generation, lease_key, owner, seconds=LEASE_SECONDS):
            return
        lease = (lease_key, owner)
        exchange: Exchange | None = None
        revision = child.revision if child else None
        authenticated = False
        try:
            with self.kept_lease(lease_key, owner):
                _, _, blocked = self.store.state()
                if blocked:
                    return
                self.confirm_key(generation, parent)
                if child:
                    credentials = self.store.child_credentials(generation, child.ocid)
                    exchange = Exchange(parent, credentials)
                    signer = exchange.child_signer(domain, child.user_ocid)
                else:
                    signer = api_signer(parent)
                    bind_identity(signer, parent.domain, parent.user_ocid)
                self.store.publish(generation, Batch(scope=scope), revision, lease)
                authenticated = True
                failed = False
                if family == "audit":
                    self.audit(generation, signer, domain, revision, lease)
                else:
                    for batch in inventory(signer, domain, family):
                        self.store.publish(generation, batch, revision, lease)
                        if batch.complete:
                            self.findings(generation, batch, revision, lease)
                        failed |= not batch.complete
                if self.store.has_coverage(runner):
                    self.store.publish(generation, Batch(scope=runner), revision, lease)
                if child:
                    self.child_status(
                        generation, child, "partial" if failed else "active", "", lease
                    )
        except StaleWork as error:
            # Expected after pause, reconfiguration, replacement or lease loss; never silent.
            logger.info("Collection stopped for a changed scope: %s", error)
        except Exception as error:
            try:
                _, _, blocked = self.store.state()
                if not blocked:
                    self.store.publish(
                        generation,
                        Batch(
                            scope=runner if authenticated else scope,
                            complete=False,
                            error=public_error(error),
                        ),
                        revision,
                        lease,
                    )
                if child:
                    self.child_status(
                        generation,
                        child,
                        "partial" if authenticated else "error",
                        "Collection failed" if authenticated else "Authentication failed",
                    )
            except StaleWork:
                pass
        finally:
            if exchange:
                exchange.close()
            self.store.release(lease_key, owner)

    @contextmanager
    def kept_lease(self, lease_key: str, owner: str) -> Iterator[None]:
        """Renew a tenancy lease in the background for as long as its collection runs."""
        stop = threading.Event()

        def keep() -> None:
            while not stop.wait(LEASE_RENEW_SECONDS):
                try:
                    if not self.store.renew(lease_key, owner, LEASE_SECONDS):
                        logger.warning("Collection lease was lost; further publication is fenced")
                        return
                except Exception:
                    logger.warning("Collection lease renewal failed; retrying")

        thread = threading.Thread(target=keep, name="ogc-lease", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join()

    def child_status(
        self,
        generation: int,
        child: Child,
        status: str,
        error: str,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Update runtime status only if child revision and active state are still current."""
        with self.store.db() as db:
            self.store.collection_fence(db, generation, child.ocid, child.revision, lease)
            if status == "active":
                scopes = db.execute("SELECT scope,status FROM coverage").fetchall()
                if any(
                    json.loads(row[0])["tenancy"] == child.ocid and row[1] != "complete"
                    for row in scopes
                ):
                    status = "partial"
            updated = child.model_copy(update={"status": status, "error": error})
            db.execute(
                "UPDATE children SET data=? WHERE ocid=?", (updated.model_dump_json(), child.ocid)
            )

    def scan(self, family: str = "all", expected_generation: int | None = None) -> None:
        """Run bounded tenancy reads outside the web process; requires local read grants."""
        if family not in {"all", "identity", "governance", "audit"}:
            raise ValueError("Unsupported collection family")
        generation, parent, blocked = self.store.state()
        if expected_generation is not None and generation != expected_generation:
            raise StaleWork("Organization changed before collection")
        if parent is None or blocked:
            return
        if family in {"all", "identity"}:
            self.discover(expected_generation=generation)
        targets: list[Child | None] = [None] + [
            c
            for c in self.store.children(generation)
            if c.domain is not None and c.status not in {"paused", "departed", "not_configured"}
        ]
        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as pool:
            futures = [
                pool.submit(self.scan_one, generation, parent, target, family) for target in targets
            ]
            for future in futures:
                future.result()

    def audit(
        self,
        generation: int,
        signer: Any,
        domain: Domain,
        revision: int | None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Collect bounded Audit intervals; commit events before checkpoints."""
        identity = client("identity", signer, domain.home_region)
        compartments = [domain.tenancy_ocid] + [
            c.id
            for c in all_items(
                identity.list_compartments,
                domain.tenancy_ocid,
                compartment_id_in_subtree=True,
                access_level="ACCESSIBLE",
            )
            if c.lifecycle_state == "ACTIVE"
        ]
        regions = all_items(identity.list_region_subscriptions, domain.tenancy_ocid)
        end = now() - timedelta(minutes=5)
        cutoff = end - timedelta(days=self.settings.retention_days)
        for region in regions:
            if region.status != "READY":
                continue

            def scope_for(dataset: str, region_name: str = region.region_name) -> Scope:
                return Scope(tenancy=domain.tenancy_ocid, dataset=dataset, region=region_name)

            forward = scope_for("audit.events")
            previous = self.store.checkpoint(forward)
            # Backfill ends where forward collection began. Fixing that target once lets it finish
            # even though every daily/weekly scan moves "now" further than any per-scan budget.
            target_scope = scope_for("audit.backfill.target")
            backfill_target = self.store.checkpoint(target_scope)
            if backfill_target is None:
                backfill_target = previous or (end - timedelta(hours=1)).isoformat()
                self.store.set_checkpoint(
                    generation, target_scope, backfill_target, revision, lease
                )
            backfill = scope_for("audit.backfill")
            plans: list[tuple[Scope, datetime, datetime, int | None]] = [
                # Forward reads always catch up to now (bounded by retention), recent first.
                (
                    forward,
                    datetime.fromisoformat(previous) - timedelta(minutes=15)
                    if previous
                    else end - timedelta(hours=1),
                    end,
                    None,
                ),
            ]
            if previous:
                # Re-read the 24 hours before the last forward checkpoint for late deliveries.
                last = datetime.fromisoformat(previous)
                plans.append((scope_for("audit.reconcile"), last - timedelta(hours=24), last, None))
            backfill_progress = self.store.checkpoint(backfill)
            plans.append(
                (
                    backfill,
                    datetime.fromisoformat(backfill_progress) if backfill_progress else cutoff,
                    datetime.fromisoformat(backfill_target),
                    self.settings.audit_backfill_hours,
                )
            )
            for scope, start, target, budget in plans:
                start = max(start, cutoff)
                try:
                    reached = self.audit_range(
                        generation,
                        signer,
                        domain,
                        compartments,
                        scope,
                        start,
                        target,
                        budget,
                        revision,
                        lease,
                    )
                    complete = reached >= target
                    message = (
                        ""
                        if complete
                        else "Audit history is still being collected through " + reached.isoformat()
                    )
                    self.store.publish(
                        generation,
                        Batch(scope=scope, complete=complete, error=message),
                        revision,
                        lease,
                    )
                except StaleWork:
                    raise
                except Exception as error:
                    self.store.publish(
                        generation,
                        Batch(scope=scope, complete=False, error=public_error(error)),
                        revision,
                        lease,
                    )

    def audit_range(
        self,
        generation: int,
        signer: Any,
        domain: Domain,
        compartments: list[str],
        scope: Scope,
        start: datetime,
        target: datetime,
        budget: int | None,
        revision: int | None,
        lease: tuple[str, str] | None,
    ) -> datetime:
        """Read hourly Audit intervals toward target, committing each before moving on."""
        intervals = 0
        while start < target and (budget is None or intervals < budget):
            interval_end = min(start + timedelta(hours=1), target)
            events = read_interval(signer, domain, scope.region, compartments, start, interval_end)
            self.store.audit_commit(
                generation,
                scope,
                start.isoformat(),
                interval_end.isoformat(),
                events,
                revision,
                lease,
            )
            start = interval_end
            intervals += 1
        return start

    def findings(
        self,
        generation: int,
        batch: Batch,
        revision: int | None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Derive governance findings from complete scopes without calling OCI."""
        if not batch.complete:
            return
        findings = governance(batch)
        timestamp = now().isoformat()
        with self.store.db() as db:
            self.store.collection_fence(db, generation, batch.scope.tenancy, revision, lease)
            stored = [
                Finding.model_validate_json(row["data"])
                for row in db.execute(
                    "SELECT data FROM findings WHERE scope=?", (batch.scope.key,)
                ).fetchall()
            ]
            existing = {f.id: f for f in stored if f.source != "coverage"}
            for item in findings:
                previous = existing.get(item.id)
                item = item.model_copy(
                    update={
                        "first_seen": previous.first_seen if previous else timestamp,
                        "last_seen": timestamp,
                        "resolved_at": None,
                        "status": "open",
                    }
                )
                db.execute(
                    "INSERT OR REPLACE INTO findings VALUES(?,?,?)",
                    (item.id, batch.scope.key, item.model_dump_json()),
                )
            present = {item.id for item in findings}
            for ident, old in existing.items():
                if ident not in present and old.status == "open":
                    resolved = old.model_copy(
                        update={"status": "resolved", "resolved_at": timestamp}
                    )
                    db.execute(
                        "UPDATE findings SET data=? WHERE id=?", (resolved.model_dump_json(), ident)
                    )
