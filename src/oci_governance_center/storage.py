"""SQLite state, encrypted secrets, scoped publication and generation fencing."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from .models import Batch, Child, ChildCredentials, Finding, Parent, Scope, now


class StaleWork(RuntimeError):
    """An organization or child changed while work was in progress."""


class Store:
    """SQLite-only store. Secrets, candidates and server sessions are encrypted."""

    def __init__(self, root: Path, key: str) -> None:
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.path = root / "ogc.db"
        self.cipher = Fernet(key.encode())
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),
                  generation INTEGER NOT NULL, parent BLOB, blocked INTEGER NOT NULL DEFAULT 0,
                  cleanup INTEGER);
                INSERT OR IGNORE INTO state(id,generation) VALUES(1,0);
                CREATE TABLE IF NOT EXISTS children(ocid TEXT PRIMARY KEY,data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS child_credentials(ocid TEXT PRIMARY KEY,
                  data BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY,owner TEXT NOT NULL,
                  generation INTEGER NOT NULL,data BLOB NOT NULL,expires TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,data BLOB NOT NULL,
                  expires TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS records(scope TEXT NOT NULL,key TEXT NOT NULL,
                  data TEXT NOT NULL,collected TEXT NOT NULL,PRIMARY KEY(scope,key));
                CREATE TABLE IF NOT EXISTS coverage(scope TEXT PRIMARY KEY,status TEXT NOT NULL,
                  error TEXT NOT NULL,attempted TEXT NOT NULL,succeeded TEXT);
                CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,scope TEXT NOT NULL,
                  data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS leases(scope TEXT PRIMARY KEY,owner TEXT NOT NULL,
                  expires TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_receipts(id TEXT PRIMARY KEY,tenancy TEXT,
                  region TEXT,start TEXT,end TEXT);
                CREATE TABLE IF NOT EXISTS checkpoints(scope TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS changes(id TEXT PRIMARY KEY,scope TEXT NOT NULL,
                  record_key TEXT NOT NULL,kind TEXT NOT NULL,time TEXT NOT NULL,
                  data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scan_schedule(id INTEGER PRIMARY KEY CHECK(id=1),
                  generation INTEGER NOT NULL,data TEXT NOT NULL,next_run TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scan_jobs(id TEXT PRIMARY KEY,
                  generation INTEGER NOT NULL,
                  source TEXT NOT NULL,actor TEXT NOT NULL,status TEXT NOT NULL,
                  requested_at TEXT NOT NULL,started_at TEXT,finished_at TEXT,
                  owner TEXT,lease_expires TEXT,error TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS scan_jobs_status ON scan_jobs(status,requested_at);
                CREATE TABLE IF NOT EXISTS scan_scope_results(job_id TEXT NOT NULL,
                  scope TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(job_id,scope));
                CREATE TABLE IF NOT EXISTS scan_worker(id INTEGER PRIMARY KEY CHECK(id=1),
                  heartbeat TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS control_events(id TEXT PRIMARY KEY,time TEXT,action TEXT,
                  actor TEXT,generation INTEGER);
            """)
        self.path.chmod(0o600)
        self.cleanup()

    @contextmanager
    def db(self) -> Iterator[sqlite3.Connection]:
        """Open a bounded transaction with secure deletion and no shared thread connection."""
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def encrypt(self, data: dict[str, Any]) -> bytes:
        """Encrypt structured credential/session data before persistence."""
        return self.cipher.encrypt(json.dumps(data).encode())

    def decrypt(self, data: bytes) -> dict[str, Any]:
        """Read authenticated encrypted data."""
        value: dict[str, Any] = json.loads(self.cipher.decrypt(data))
        return value

    def state(self) -> tuple[int, Parent | None, bool]:
        """Return current generation, parent and scanner suspension state."""
        with self.db() as db:
            row = db.execute("SELECT * FROM state WHERE id=1").fetchone()
        return (
            row["generation"],
            (Parent.model_validate(self.decrypt(row["parent"])) if row["parent"] else None),
            bool(row["blocked"]),
        )

    def fence(self, db: sqlite3.Connection, generation: int) -> None:
        """Reject stale generations, including publication during pending cleanup."""
        row = db.execute("SELECT generation,cleanup FROM state WHERE id=1").fetchone()
        if row[0] != generation or row[1] is not None:
            raise StaleWork("Organization changed or cleanup is pending")

    @staticmethod
    def parent_data(parent: Parent) -> dict[str, Any]:
        """Serialize secrets only for immediate encryption, never for logs or responses."""
        data = parent.model_dump(mode="json")
        data["private_key"] = parent.private_key.get_secret_value()
        data["client_secret"] = parent.client_secret.get_secret_value()
        return data

    def candidate(self, owner: str, generation: int, parent: Parent) -> str:
        """Save a short-lived enrollment candidate bound to an authorized session."""
        ident = secrets.token_urlsafe(32)
        with self.db() as db:
            self.fence(db, generation)
            db.execute(
                "DELETE FROM candidates WHERE owner=? OR expires<?", (owner, now().isoformat())
            )
            db.execute(
                "INSERT INTO candidates VALUES(?,?,?,?,?)",
                (
                    ident,
                    owner,
                    generation,
                    self.encrypt(self.parent_data(parent)),
                    (now() + timedelta(minutes=30)).isoformat(),
                ),
            )
        return ident

    def get_candidate(self, ident: str, owner: str) -> tuple[int, Parent]:
        """Load only the initiating session's unexpired candidate."""
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM candidates WHERE id=? AND owner=? AND expires>?",
                (ident, owner, now().isoformat()),
            ).fetchone()
        if row is None:
            raise ValueError("Enrollment expired; start again")
        return row["generation"], Parent.model_validate(self.decrypt(row["data"]))

    def install(self, ident: str, owner: str, actor: str) -> int:
        """Atomically switch a verified candidate; callers must establish new-parent admin login."""
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM candidates WHERE id=? AND owner=? AND expires>?",
                (ident, owner, now().isoformat()),
            ).fetchone()
            if row is None:
                raise ValueError("Enrollment expired")
            self.fence(db, row["generation"])
            generation = row["generation"] + 1
            for table in (
                "children",
                "child_credentials",
                "candidates",
                "sessions",
                "records",
                "coverage",
                "findings",
                "leases",
                "audit_receipts",
                "checkpoints",
                "control_events",
                "changes",
                "scan_schedule",
                "scan_jobs",
                "scan_scope_results",
            ):
                db.execute(f"DELETE FROM {table}")  # noqa: S608 - static local table allow-list  # static local table list, not OCI
            db.execute(
                "UPDATE state SET generation=?,parent=?,blocked=0,cleanup=? WHERE id=1",
                (generation, row["data"], row["generation"]),
            )
            db.execute(
                "INSERT INTO control_events VALUES(?,?,?,?,?)",
                (secrets.token_hex(16), now().isoformat(), "parent_installed", actor, generation),
            )
        self.cleanup()
        return int(generation)

    def cleanup(self) -> None:
        """Finish journaled deletion of old audit, backup and export directories."""
        with self.db() as db:
            row = db.execute("SELECT generation,cleanup FROM state WHERE id=1").fetchone()
            if row["cleanup"] is None:
                return
            generation = row["generation"]
            # Keep the switch locked against all local writers until deletion finishes.
            for category in ("audit", "backups", "exports"):
                base = self.root / category
                if base.is_symlink():
                    raise RuntimeError("Unsafe managed data directory")
                if base.exists():
                    for child in base.iterdir():
                        if child.name != f"g{generation}":
                            if child.is_symlink() or child.is_file():
                                child.unlink()
                            else:
                                shutil.rmtree(child)
            db.execute("UPDATE state SET cleanup=NULL WHERE id=1")
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def save_session(self, ident: str, data: dict[str, Any], seconds: int) -> None:
        """Store encrypted server-side session state; browser receives only a random identifier."""
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (now().isoformat(),))
            db.execute(
                "INSERT OR REPLACE INTO sessions VALUES(?,?,?)",
                (ident, self.encrypt(data), (now() + timedelta(seconds=seconds)).isoformat()),
            )

    def session(self, ident: str) -> dict[str, Any] | None:
        """Load a live session without extending its absolute lifetime."""
        with self.db() as db:
            row = db.execute(
                "SELECT data FROM sessions WHERE id=? AND expires>?", (ident, now().isoformat())
            ).fetchone()
        return self.decrypt(row[0]) if row else None

    def drop_session(self, ident: str) -> None:
        """Invalidate a browser session locally."""
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (ident,))

    def child_credentials(self, generation: int, child_id: str) -> ChildCredentials | None:
        """Read encrypted credentials for the current organization's selected child only."""
        with self.db() as db:
            self.fence(db, generation)
            row = db.execute(
                "SELECT data FROM child_credentials WHERE ocid=?", (child_id,)
            ).fetchone()
        return ChildCredentials.model_validate(self.decrypt(row[0])) if row else None

    def children(self, generation: int | None = None) -> list[Child]:
        """List children in the active organization."""
        with self.db() as db:
            if generation is not None:
                self.fence(db, generation)
            rows = db.execute("SELECT data FROM children ORDER BY ocid").fetchall()
        return [Child.model_validate_json(r[0]) for r in rows]

    def save_child(self, generation: int, child: Child) -> None:
        """Save child settings and invalidate previous work via revision."""
        with self.db() as db:
            self.fence(db, generation)
            db.execute(
                "INSERT OR REPLACE INTO children VALUES(?,?)", (child.ocid, child.model_dump_json())
            )

    def check_child(self, db: sqlite3.Connection, child_id: str, revision: int) -> None:
        """Fence paused, removed, or reconfigured child collection."""
        row = db.execute("SELECT data FROM children WHERE ocid=?", (child_id,)).fetchone()
        if row is None:
            raise StaleWork("Child no longer configured")
        child = Child.model_validate_json(row[0])
        if child.revision != revision or child.status in {"paused", "departed"}:
            raise StaleWork("Child changed")

    def collection_fence(
        self,
        db: sqlite3.Connection,
        generation: int,
        tenancy: str,
        revision: int | None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Fence credential suspension, child changes and expired/replaced worker leases."""
        self.fence(db, generation)
        if db.execute("SELECT blocked FROM state WHERE id=1").fetchone()[0]:
            raise StaleWork("Scanner authentication is suspended")
        if revision is not None:
            self.check_child(db, tenancy, revision)
        if (
            lease is not None
            and db.execute(
                "SELECT 1 FROM leases WHERE scope=? AND owner=? AND expires>?",
                (*lease, now().isoformat()),
            ).fetchone()
            is None
        ):
            raise StaleWork("Collection lease expired or changed")

    def publish(
        self,
        generation: int,
        batch: Batch,
        revision: int | None = None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Replace only complete same-scope snapshots; failures preserve previous good data."""
        timestamp = now().isoformat()
        with self.db() as db:
            self.collection_fence(db, generation, batch.scope.tenancy, revision, lease)
            key = batch.scope.key
            if batch.complete:
                previous_records = {
                    r[0]: json.loads(r[1])
                    for r in db.execute(
                        "SELECT key,data FROM records WHERE scope=?", (key,)
                    ).fetchall()
                }
                incoming_records = {r.key: r.data for r in batch.records}
                for record_key in previous_records.keys() | incoming_records.keys():
                    old, new = previous_records.get(record_key), incoming_records.get(record_key)
                    if old != new:
                        kind = "added" if old is None else "removed" if new is None else "modified"
                        db.execute(
                            "INSERT INTO changes VALUES(?,?,?,?,?,?)",
                            (
                                secrets.token_hex(16),
                                key,
                                record_key,
                                kind,
                                timestamp,
                                json.dumps({"before": old, "after": new}),
                            ),
                        )
                db.execute("DELETE FROM records WHERE scope=?", (key,))
                db.executemany(
                    "INSERT INTO records VALUES(?,?,?,?)",
                    [(key, r.key, json.dumps(r.data), timestamp) for r in batch.records],
                )
            db.execute(
                "INSERT INTO coverage VALUES(?,?,?,?,?) ON CONFLICT(scope) DO UPDATE SET "
                "status=excluded.status,error=excluded.error,attempted=excluded.attempted,"
                "succeeded=COALESCE(excluded.succeeded,coverage.succeeded)",
                (
                    key,
                    "complete" if batch.complete else "failed",
                    batch.error,
                    timestamp,
                    timestamp if batch.complete else None,
                ),
            )
            finding_id = hashlib.sha256(("coverage-v1:" + key).encode()).hexdigest()
            row = db.execute("SELECT data FROM findings WHERE id=?", (finding_id,)).fetchone()
            previous = Finding.model_validate_json(row[0]) if row else None
            if not batch.complete:
                finding = Finding(
                    id=finding_id,
                    scope=key,
                    tenancy=batch.scope.tenancy,
                    source="coverage",
                    severity="HIGH",
                    title=batch.error,
                    rule_id="OGC-ACCESS-002",
                    first_seen=previous.first_seen if previous else timestamp,
                    last_seen=timestamp,
                )
                db.execute(
                    "INSERT OR REPLACE INTO findings VALUES(?,?,?)",
                    (finding_id, key, finding.model_dump_json()),
                )
            elif previous:
                resolved = previous.model_copy(
                    update={"status": "resolved", "resolved_at": timestamp}
                )
                db.execute(
                    "UPDATE findings SET data=? WHERE id=?",
                    (resolved.model_dump_json(), finding_id),
                )

    def rows(self, table: str, generation: int | None = None) -> list[dict[str, Any]]:
        """Read the public dashboard tables using a static table allow-list."""
        if table not in {"coverage", "records", "findings", "control_events", "changes"}:
            raise ValueError("Unsupported table")
        with self.db() as db:
            if generation is not None:
                self.fence(db, generation)
            cursor = db.execute(f"SELECT * FROM {table}")  # noqa: S608 - table allow-list above
            rows = [dict(row) for row in cursor.fetchall()]
        if table == "findings":
            # Every reader (dashboard, data pages, exports) sees only contract-valid findings.
            for row in rows:
                row["data"] = Finding.model_validate_json(row["data"]).model_dump_json()
        return rows

    def block(self, generation: int, blocked: bool) -> None:
        """Suspend/resume the organization after confirmed key failure or verified repair."""
        with self.db() as db:
            self.fence(db, generation)
            db.execute("UPDATE state SET blocked=? WHERE id=1", (int(blocked),))

    def lease(self, generation: int, scope: str, owner: str, seconds: int = 600) -> bool:
        """Acquire an expiring cross-process collection lease."""
        with self.db() as db:
            self.fence(db, generation)
            db.execute("DELETE FROM leases WHERE expires<?", (now().isoformat(),))
            cursor = db.execute(
                "INSERT OR IGNORE INTO leases VALUES(?,?,?)",
                (scope, owner, (now() + timedelta(seconds=seconds)).isoformat()),
            )
            return cursor.rowcount == 1

    def renew(self, scope: str, owner: str, seconds: int) -> bool:
        """Extend a live lease still held by this owner; an expired or taken lease is lost."""
        with self.db() as db:
            cursor = db.execute(
                "UPDATE leases SET expires=? WHERE scope=? AND owner=? AND expires>?",
                (
                    (now() + timedelta(seconds=seconds)).isoformat(),
                    scope,
                    owner,
                    now().isoformat(),
                ),
            )
            return cursor.rowcount == 1

    def has_coverage(self, scope: Scope) -> bool:
        """Return whether any collection outcome was ever recorded for this exact scope."""
        with self.db() as db:
            return (
                db.execute("SELECT 1 FROM coverage WHERE scope=?", (scope.key,)).fetchone()
                is not None
            )

    def release(self, scope: str, owner: str) -> None:
        """Release only a lease owned by the finishing worker."""
        with self.db() as db:
            db.execute("DELETE FROM leases WHERE scope=? AND owner=?", (scope, owner))

    def checkpoint(self, scope: Scope) -> str | None:
        """Read durable audit interval progress."""
        with self.db() as db:
            row = db.execute("SELECT value FROM checkpoints WHERE scope=?", (scope.key,)).fetchone()
        return row[0] if row else None

    def audit_commit(
        self,
        generation: int,
        scope: Scope,
        start: str,
        end: str,
        records: list[dict[str, Any]],
        revision: int | None = None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Commit events before receipt/checkpoint; replay deduplicates event IDs."""
        with self.db() as db:
            self.collection_fence(db, generation, scope.tenancy, revision, lease)
            # Hold organization transaction while committing separate event files: a switch cannot
            # delete files underneath this commit; failed checkpoint writes are safely replayed.
            groups: dict[str, list[dict[str, Any]]] = {}
            for record in records:
                groups.setdefault(record["time"][:7], []).append(record)
            safe_tenancy = hashlib.sha256(scope.tenancy.encode()).hexdigest()
            for month, events in groups.items():
                directory = self.root / "audit" / f"g{generation}" / safe_tenancy
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                path = directory / f"{month}.db"
                with sqlite3.connect(path) as audit:
                    audit.execute(
                        "CREATE TABLE IF NOT EXISTS events(region TEXT,id TEXT,data TEXT,"
                        "PRIMARY KEY(region,id))"
                    )
                    audit.executemany(
                        "INSERT OR IGNORE INTO events VALUES(?,?,?)",
                        [(scope.region, event["id"], json.dumps(event)) for event in events],
                    )
                os.chmod(path, 0o600)
            receipt = hashlib.sha256(
                json.dumps([generation, scope.key, start, end]).encode()
            ).hexdigest()
            db.execute(
                "INSERT OR IGNORE INTO audit_receipts VALUES(?,?,?,?,?)",
                (receipt, scope.tenancy, scope.region, start, end),
            )
            db.execute(
                "INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(scope) DO UPDATE "
                "SET value=MAX(value,excluded.value)",
                (scope.key, end),
            )

    def event(self, generation: int, action: str, actor: str) -> None:
        """Record a local control action without form values or credential material."""
        with self.db() as db:
            self.fence(db, generation)
            db.execute(
                "INSERT INTO control_events VALUES(?,?,?,?,?)",
                (secrets.token_hex(16), now().isoformat(), action, actor, generation),
            )

    def purge(self, days: int = 90) -> None:
        """Apply retention to normalized history, audit events, and expired local auth state."""
        cutoff = (now() - timedelta(days=days)).isoformat()
        with self.db() as db:
            for path in (self.root / "audit").glob("g*/*/*.db"):
                if path.is_symlink():
                    raise RuntimeError("Unsafe audit database path")
                with sqlite3.connect(path) as audit:
                    audit.execute("PRAGMA secure_delete=ON")
                    audit.execute(
                        "DELETE FROM events WHERE json_extract(data,'$.time')<?", (cutoff,)
                    )
            db.execute("DELETE FROM scan_jobs WHERE finished_at<?", (cutoff,))
            db.execute(
                "DELETE FROM scan_scope_results WHERE job_id NOT IN (SELECT id FROM scan_jobs)"
            )
            db.execute("DELETE FROM changes WHERE time<?", (cutoff,))
            db.execute("DELETE FROM records WHERE collected<?", (cutoff,))
            db.execute("DELETE FROM findings WHERE json_extract(data,'$.last_seen')<?", (cutoff,))
            db.execute("DELETE FROM audit_receipts WHERE end<?", (cutoff,))
            db.execute(
                "DELETE FROM control_events WHERE time<?",
                ((now() - timedelta(days=365)).isoformat(),),
            )
            db.execute("DELETE FROM candidates WHERE expires<?", (now().isoformat(),))
            db.execute("DELETE FROM sessions WHERE expires<?", (now().isoformat(),))
            db.execute("DELETE FROM leases WHERE expires<?", (now().isoformat(),))

    def set_checkpoint(
        self,
        generation: int,
        scope: Scope,
        value: str,
        revision: int | None = None,
        lease: tuple[str, str] | None = None,
    ) -> None:
        """Durably set a checkpoint value, such as the fixed Audit backfill target."""
        with self.db() as db:
            self.collection_fence(db, generation, scope.tenancy, revision, lease)
            db.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?)", (scope.key, value))

    def audit_events(self, generation: int, limit: int = 200) -> list[dict[str, Any]]:
        """Read latest normalized events, deduplicating overlap/key-rotation files in this org."""
        with self.db() as db:
            self.fence(db, generation)
            row = db.execute("SELECT parent FROM state WHERE id=1").fetchone()
            if not row[0]:
                return []
            parent = Parent.model_validate(self.decrypt(row[0]))
            tenancies = [parent.domain.tenancy_ocid] + [
                Child.model_validate_json(r[0]).ocid
                for r in db.execute("SELECT data FROM children").fetchall()
            ]
            mapping = {hashlib.sha256(t.encode()).hexdigest(): t for t in tenancies}
            events: dict[tuple[str, str, str], dict[str, Any]] = {}
            for path in (self.root / "audit").glob("g*/*/*.db"):
                if path.is_symlink() or path.parent.name not in mapping:
                    continue
                tenancy = mapping[path.parent.name]
                with sqlite3.connect(path) as audit:
                    rows = audit.execute(
                        "SELECT region,id,data FROM events ORDER BY "
                        "json_extract(data,'$.time') DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                for region, ident, payload in rows:
                    events[(tenancy, region, ident)] = {
                        **json.loads(payload),
                        "tenancy": tenancy,
                        "region": region,
                    }
            return sorted(events.values(), key=lambda event: event["time"], reverse=True)[:limit]
