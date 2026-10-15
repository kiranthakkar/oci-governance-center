"""SQLite implementation of :class:`DataStore` (docs/storage.md §2-§4).

* Dataset snapshots live in ``osc.db``, one table per dataset, keyed by
  ``(generation, tenancy, scope, record)``. A snapshot replaces only its declared scope, only with a
  complete manifest, under the caller's generation and scope lease, in one transaction that also
  writes ``record_changes``, the manifest and the scan-run item.
* Audit events live in ``audit/g<generation>/<tenancy_ocid>/<YYYY-MM>.db``; inserts are idempotent
  on event ID. A stale worker can only reach its own (quarantined) generation folder.
* Findings use the versioned identity from :class:`Finding` (storage §3.4).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oci_security_center.models import (
    CollectionManifest,
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    FindingStatus,
    Severity,
    is_ocid,
)
from oci_security_center.models.common import canonical_json, iso, utcnow
from oci_security_center.models.findings import IDENTITY_NAMESPACE
from oci_security_center.storage.base import SnapshotResult, Watermark
from oci_security_center.storage.datasets import get_dataset
from oci_security_center.storage.errors import (
    IncompleteSnapshotError,
    ScopeError,
    StaleRunError,
)
from oci_security_center.storage.sqlite.db import SqliteDatabase
from oci_security_center.storage.sqlite.fence import check_fence, check_lease
from oci_security_center.storage.sqlite.schema import AUDIT_SCHEMA

_AUDIT_COLUMNS = (
    "event_type",
    "source",
    "principal_id",
    "principal_name",
    "auth_type",
    "ip_address",
    "user_agent",
    "action",
    "response_status",
    "resource_id",
)
_MONTH = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
AUDIT_FORWARD = "audit.events"  # forward cursor: complete_through
AUDIT_RECONCILE = "audit.events#reconcile"  # position within the retained-window sweep
AUDIT_BACKFILL = "audit.events#backfill"  # backfill cursor: earliest complete start


def generation_folder(generation: int) -> str:
    return f"g{generation}"


def current_generation(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT generation FROM organization_state WHERE id=1").fetchone()[0])


def write_finding(conn: sqlite3.Connection, f: Finding, table: str = "findings") -> None:
    """Insert or fully replace one finding row (the caller decides merged values)."""
    conn.execute(
        f"INSERT INTO {table} (finding_id, identity_version, generation, namespace, source, "  # noqa: S608
        "tenancy_ocid, rule_id, scope_key, source_record_id, occurrence_key, severity, status, "
        "title, resource_ocid, region, first_seen, last_seen, resolved_at, identity, data) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(finding_id) DO UPDATE SET source=excluded.source, "
        "rule_id=excluded.rule_id, source_record_id=excluded.source_record_id, "
        "occurrence_key=excluded.occurrence_key, severity=excluded.severity, "
        "status=excluded.status, title=excluded.title, resource_ocid=excluded.resource_ocid, "
        "region=excluded.region, first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
        "resolved_at=excluded.resolved_at, data=excluded.data",
        (
            f.finding_id,
            f.identity_version,
            f.generation,
            f.namespace,
            f.source.value,
            f.tenancy_ocid,
            f.rule_id,
            f.scope_key,
            f.source_record_id,
            f.occurrence_key,
            f.severity.value,
            f.status.value,
            f.title,
            f.resource_ocid,
            f.region,
            iso(f.first_seen),
            iso(f.last_seen),
            iso(f.resolved_at) if f.resolved_at else None,
            canonical_json(f.identity),
            f.model_dump_json(),
        ),
    )


class SqliteDataStore:
    def __init__(self, db: SqliteDatabase, audit_root: Path) -> None:
        self.db = db
        self.audit_root = audit_root
        self._audit_dbs: dict[Path, SqliteDatabase] = {}

    def current_generation(self) -> int:
        with self.db.read() as conn:
            return current_generation(conn)

    # --- scan runs ------------------------------------------------------------------------
    def begin_scan_run(self, run_id: str, trigger: str, generation: int) -> None:
        with self.db.write() as conn:
            check_fence(conn, generation)
            conn.execute(
                "INSERT INTO scan_runs (run_id, trigger, started_at, status, generation) "
                "VALUES (?,?,?, 'running', ?) ON CONFLICT(run_id) DO NOTHING",
                (run_id, trigger, iso(utcnow()), generation),
            )

    def finish_scan_run(self, run_id: str, status: str, summary: dict[str, Any]) -> None:
        with self.db.write() as conn:
            conn.execute(
                "UPDATE scan_runs SET finished_at=?, status=?, summary=? WHERE run_id=?",
                (iso(utcnow()), status, json.dumps(summary), run_id),
            )

    def scan_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            gen = current_generation(conn)
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM scan_runs WHERE generation=? ORDER BY started_at DESC LIMIT ?",
                    (gen, limit),
                )
            ]

    def scope_status(self, generation: int | None = None) -> list[dict[str, Any]]:
        """Latest outcome and last success for every collected scope (coverage dashboards)."""
        with self.db.read() as conn:
            gen = current_generation(conn) if generation is None else generation
            rows = conn.execute(
                """
                SELECT m.tenancy_ocid, m.dataset, m.scope_key,
                  MAX(CASE WHEN m.applied=1 THEN m.finished_at END) AS last_success,
                  (SELECT i.status FROM scan_run_items i
                    WHERE i.generation=m.generation AND i.tenancy_ocid=m.tenancy_ocid
                      AND i.dataset=m.dataset AND i.scope_key=m.scope_key
                    ORDER BY i.finished_at DESC LIMIT 1) AS last_status,
                  (SELECT i.error FROM scan_run_items i
                    WHERE i.generation=m.generation AND i.tenancy_ocid=m.tenancy_ocid
                      AND i.dataset=m.dataset AND i.scope_key=m.scope_key
                    ORDER BY i.finished_at DESC LIMIT 1) AS last_error,
                  MAX(m.finished_at) AS last_attempt
                FROM scope_manifests m WHERE m.generation=?
                GROUP BY m.tenancy_ocid, m.dataset, m.scope_key
                ORDER BY m.tenancy_ocid, m.dataset, m.scope_key
                """,
                (gen,),
            ).fetchall()
            return [dict(r) for r in rows]

    # --- dataset snapshots ----------------------------------------------------------------
    def apply_snapshot(
        self,
        scope: CollectionScope,
        records: Iterable[Envelope],
        manifest: CollectionManifest,
    ) -> SnapshotResult:
        """Publish a *complete* snapshot of one declared scope.

        Rows of this scope missing from ``records`` are soft-deleted; rows of other scopes are
        untouched. Refused (nothing written) when the manifest is incomplete or for another scope,
        a record is outside the scope or conflicts with another, the generation or lease is stale,
        or a newer run already published this scope.
        """
        spec = get_dataset(scope.dataset)
        spec.check_scope(scope)
        if manifest.scope != scope:
            raise ScopeError("manifest is for a different scope")
        if not manifest.complete:
            raise IncompleteSnapshotError(
                "incomplete collection can't replace current rows: "
                + "; ".join([*manifest.errors, *(f"missed {c}" for c in manifest.missing_children)])
                if manifest.errors or manifest.missing_children
                else "incomplete collection can't replace current rows: pages not exhausted"
            )
        incoming = self._validated_records(scope, records)

        table = spec.table
        now = iso(utcnow())
        gen, tenancy, scope_key = scope.generation, scope.tenancy_ocid, scope.scope_key
        added = modified = removed = unchanged = 0
        changes: list[tuple[Any, ...]] = []
        cols = [
            "generation",
            "tenancy_ocid",
            "scope_key",
            "record_key",
            "region",
            "compartment_ocid",
            "resource_ocid",
            "content_hash",
            "first_seen_run",
            "last_seen_run",
            "collected_at",
            "is_deleted",
            "deleted_at",
            *spec.columns,
            "data",
        ]
        update_set = ", ".join(
            f"{c}=excluded.{c}"
            for c in cols
            if c not in ("generation", "tenancy_ocid", "scope_key", "record_key", "first_seen_run")
        )
        upsert_sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({','.join('?' * len(cols))}) "  # noqa: S608
            "ON CONFLICT(generation, tenancy_ocid, scope_key, record_key) "
            f"DO UPDATE SET {update_set}"
        )

        def change(key: str, kind: str, old: str | None, new: str | None, data: str) -> None:
            changes.append(
                (
                    gen,
                    scope.dataset,
                    tenancy,
                    scope_key,
                    manifest.schema_version,
                    *(key, kind, old, new, manifest.run_id, now, data),
                )
            )

        with self.db.write() as conn:
            check_fence(conn, gen)
            check_lease(conn, scope.lease_key, manifest.lease_token, gen)
            newer = conn.execute(
                "SELECT run_id FROM scope_manifests WHERE generation=? AND tenancy_ocid=? AND "
                "dataset=? AND scope_key=? AND applied=1 AND started_at > ? LIMIT 1",
                (gen, tenancy, scope.dataset, scope_key, iso(manifest.started_at)),
            ).fetchone()
            if newer is not None:
                raise StaleRunError(f"run {newer['run_id']} already published a newer snapshot")
            existing = {
                r["record_key"]: (r["content_hash"], r["is_deleted"], r["data"])
                for r in conn.execute(
                    f"SELECT record_key, content_hash, is_deleted, data FROM {table} "  # noqa: S608
                    "WHERE generation=? AND tenancy_ocid=? AND scope_key=?",
                    (gen, tenancy, scope_key),
                )
            }
            rows: list[tuple[Any, ...]] = []
            for key, env in incoming.items():
                new_hash = spec.content_hash(env.data)
                prev = existing.get(key)
                data_json = canonical_json(env.data)
                if prev is None or prev[1] == 1:
                    added += 1
                    change(key, "added", prev[0] if prev else None, new_hash, data_json)
                elif prev[0] != new_hash:
                    modified += 1
                    change(key, "modified", prev[0], new_hash, data_json)
                else:
                    unchanged += 1
                rows.append(
                    (
                        gen,
                        tenancy,
                        scope_key,
                        key,
                        env.region or scope.region or "",
                        env.compartment_ocid,
                        env.resource_ocid,
                        new_hash,
                        manifest.run_id,
                        manifest.run_id,
                        iso(env.collected_at),
                        0,
                        None,
                        *(_as_text(env.data.get(src)) for src in spec.columns.values()),
                        data_json,
                    )
                )
            conn.executemany(upsert_sql, rows)
            gone = [k for k, v in existing.items() if k not in incoming and v[1] == 0]
            for key in gone:
                removed += 1
                old_hash, _, old_data = existing[key]
                change(key, "removed", old_hash, None, old_data)
            if gone:
                conn.executemany(
                    f"UPDATE {table} SET is_deleted=1, deleted_at=?, last_seen_run=? "  # noqa: S608
                    "WHERE generation=? AND tenancy_ocid=? AND scope_key=? AND record_key=?",
                    [(now, manifest.run_id, gen, tenancy, scope_key, k) for k in gone],
                )
            conn.executemany(
                "INSERT INTO record_changes (generation, dataset, tenancy_ocid, scope_key, "
                "schema_version, record_key, change_type, old_hash, new_hash, run_id, "
                "changed_at, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                changes,
            )
            self._record_manifest(conn, manifest, applied=True)
            self._record_run_item(
                conn, manifest, "ok", len(incoming), added, modified, removed, error=None
            )
        return SnapshotResult(
            scope.dataset, tenancy, len(incoming), added, modified, removed, unchanged
        )

    def record_partial(self, manifest: CollectionManifest, status: str = "partial") -> None:
        """Record a failed/partial collection. Current rows are never touched (storage §4)."""
        problems = [*manifest.errors, *(f"missed {c}" for c in manifest.missing_children)]
        if not manifest.pages_complete:
            problems.append("pages not exhausted")
        with self.db.write() as conn:
            check_fence(conn, manifest.scope.generation)
            self._record_manifest(conn, manifest, applied=False)
            self._record_run_item(
                conn,
                manifest,
                status,
                manifest.record_count,
                0,
                0,
                0,
                error="; ".join(problems) or "incomplete",
            )

    def last_success(self, scope: CollectionScope) -> datetime | None:
        """When this scope last published a complete snapshot (shown next to stale data)."""
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT MAX(finished_at) AS t FROM scope_manifests WHERE generation=? AND "
                "tenancy_ocid=? AND dataset=? AND scope_key=? AND applied=1",
                (scope.generation, scope.tenancy_ocid, scope.dataset, scope.scope_key),
            ).fetchone()
        return datetime.fromisoformat(row["t"]) if row and row["t"] else None

    def dependency_ready(self, scope: CollectionScope) -> bool:
        """Whether the latest scope discovery published complete coverage."""
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT applied FROM scope_manifests WHERE generation=? AND tenancy_ocid=? "
                "AND dataset=? AND scope_key=? "
                "ORDER BY started_at DESC, recorded_at DESC, rowid DESC LIMIT 1",
                (scope.generation, scope.tenancy_ocid, scope.dataset, scope.scope_key),
            ).fetchone()
        return bool(row and row["applied"])

    def read_current(
        self, scope: CollectionScope, include_deleted: bool = False
    ) -> Iterator[Envelope]:
        spec = get_dataset(scope.dataset)
        spec.check_scope(scope)
        sql = (
            f"SELECT * FROM {spec.table} "  # noqa: S608
            "WHERE generation=? AND tenancy_ocid=? AND scope_key=?"
        )
        if not include_deleted:
            sql += " AND is_deleted=0"
        with self.db.read() as conn:
            rows = conn.execute(
                sql + " ORDER BY record_key",
                (scope.generation, scope.tenancy_ocid, scope.scope_key),
            ).fetchall()
        for r in rows:
            yield Envelope(
                schema_id=spec.schema_id,
                tenancy_ocid=r["tenancy_ocid"],
                record_key=r["record_key"],
                data=json.loads(r["data"]),
                run_id=r["last_seen_run"],
                collected_at=datetime.fromisoformat(r["collected_at"]),
                region=r["region"] or None,
                domain=scope.domain,
                compartment_ocid=r["compartment_ocid"],
                resource_ocid=r["resource_ocid"],
            )

    def list_changes(
        self,
        tenancy_ocid: str,
        dataset: str | None = None,
        limit: int = 200,
        generation: int | None = None,
    ) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            gen = current_generation(conn) if generation is None else generation
            sql = "SELECT * FROM record_changes WHERE generation=? AND tenancy_ocid=?"
            params: list[Any] = [gen, tenancy_ocid]
            if dataset:
                sql += " AND dataset=?"
                params.append(dataset)
            sql += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    @staticmethod
    def _validated_records(
        scope: CollectionScope, records: Iterable[Envelope]
    ) -> dict[str, Envelope]:
        incoming: dict[str, Envelope] = {}
        for env in records:
            if env.tenancy_ocid != scope.tenancy_ocid:
                raise ScopeError("record belongs to another tenancy")
            for dim, value in scope.dimensions().items():
                actual = env.compartment_ocid if dim == "compartment" else getattr(env, dim)
                if actual != value:
                    raise ScopeError(f"record {env.record_key} is outside the {dim} scope")
            prev = incoming.get(env.record_key)
            if prev is not None and prev.data != env.data:
                raise ScopeError(f"conflicting duplicate record {env.record_key}")
            incoming[env.record_key] = env
        return incoming

    @staticmethod
    def _record_manifest(
        conn: sqlite3.Connection, manifest: CollectionManifest, applied: bool
    ) -> None:
        s = manifest.scope
        conn.execute(
            "INSERT INTO scope_manifests (generation, tenancy_ocid, dataset, scope_key, run_id, "
            "started_at, finished_at, complete, applied, manifest, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(generation, tenancy_ocid, dataset, "
            "scope_key, run_id) DO UPDATE SET finished_at=excluded.finished_at, "
            "complete=excluded.complete, applied=excluded.applied, manifest=excluded.manifest, "
            "recorded_at=excluded.recorded_at",
            (
                s.generation,
                s.tenancy_ocid,
                s.dataset,
                s.scope_key,
                manifest.run_id,
                iso(manifest.started_at),
                iso(manifest.finished_at),
                int(manifest.complete),
                int(applied),
                manifest.model_dump_json(exclude={"lease_token"}),
                iso(utcnow()),
            ),
        )

    @staticmethod
    def _record_run_item(
        conn: sqlite3.Connection,
        manifest: CollectionManifest,
        status: str,
        count: int,
        added: int,
        modified: int,
        removed: int,
        error: str | None,
    ) -> None:
        s = manifest.scope
        conn.execute(
            "INSERT INTO scan_runs (run_id, trigger, started_at, status, generation) "
            "VALUES (?, 'collector', ?, 'running', ?) ON CONFLICT(run_id) DO NOTHING",
            (manifest.run_id, iso(manifest.started_at), s.generation),
        )
        conn.execute(
            "INSERT INTO scan_run_items (run_id, generation, tenancy_ocid, dataset, scope_key, "
            "region, status, complete, record_count, added, modified, removed, error, "
            "started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(run_id, tenancy_ocid, dataset, scope_key) DO UPDATE SET "
            "status=excluded.status, complete=excluded.complete, "
            "record_count=excluded.record_count, added=excluded.added, "
            "modified=excluded.modified, removed=excluded.removed, error=excluded.error, "
            "finished_at=excluded.finished_at",
            (
                manifest.run_id,
                s.generation,
                s.tenancy_ocid,
                s.dataset,
                s.scope_key,
                s.region or "",
                status,
                int(status == "ok"),
                count,
                added,
                modified,
                removed,
                error,
                iso(manifest.started_at),
                iso(manifest.finished_at),
            ),
        )

    # --- audit events ---------------------------------------------------------------------
    def audit_db_path(self, generation: int, tenancy_ocid: str, month: str) -> Path:
        if not is_ocid(tenancy_ocid):
            raise ValueError("tenancy_ocid must be an OCID (used as a folder name)")
        if not _MONTH.match(month):
            raise ValueError("month must be YYYY-MM")
        return self.audit_root / generation_folder(generation) / tenancy_ocid / f"{month}.db"

    def _audit_db(self, path: Path) -> SqliteDatabase:
        db = self._audit_dbs.get(path)
        if db is None:
            db = SqliteDatabase(path, AUDIT_SCHEMA)
            self._audit_dbs[path] = db
        return db

    def forget_audit_dbs(self, under: Path) -> None:
        """Drop cached handles for files below ``under`` (before moving/deleting it)."""
        resolved = under.resolve()
        for path in [p for p in self._audit_dbs if resolved in p.resolve().parents]:
            del self._audit_dbs[path]

    def append_events(
        self,
        generation: int,
        tenancy_ocid: str,
        events: Iterable[Envelope],
        run_id: str,
        *,
        scope: CollectionScope | None = None,
        lease_token: str | None = None,
    ) -> int:
        """Durably insert audit events into monthly files. Idempotent on event ID.

        Events are partitioned by their own event time in UTC. The main database writer
        transaction fences generation/maintenance for every monthly commit. Ingestion callers
        supply their scope and lease so revoked/expired workers cannot write events.
        """
        by_month: dict[str, list[tuple[Any, ...]]] = defaultdict(list)
        for env in events:
            if env.tenancy_ocid != tenancy_ocid:
                raise ValueError("envelope tenancy does not match")
            raw_time = env.data.get("event_time")
            if not isinstance(raw_time, str):
                raise ValueError(f"audit event {env.record_key} has no event_time")
            when = datetime.fromisoformat(raw_time)
            if when.tzinfo is None:
                raise ValueError(f"audit event {env.record_key} has a naive event_time")
            event_time = when.astimezone(UTC).isoformat()
            by_month[event_time[:7]].append(
                (
                    env.record_key,
                    event_time,
                    env.region or "",
                    env.compartment_ocid,
                    *[_audit_value(env.data.get(c)) for c in _AUDIT_COLUMNS],
                    run_id,
                    canonical_json({**env.data, "event_time": event_time}),
                )
            )
        inserted = 0
        cols = (
            "event_id",
            "event_time",
            "region",
            "compartment_ocid",
            *_AUDIT_COLUMNS,
            "run_id",
            "data",
        )
        sql = (
            f"INSERT OR IGNORE INTO audit_events ({', '.join(cols)}) "  # noqa: S608
            f"VALUES ({','.join('?' * len(cols))})"
        )
        # Hold osc.db's cross-process writer lock until all monthly commits finish. A
        # maintenance holder cannot begin (or switch generations) between the check and write.
        with self.db.write(durable=True) as barrier:
            check_fence(barrier, generation)
            if scope is not None:
                if (
                    scope.generation != generation
                    or scope.tenancy_ocid != tenancy_ocid
                    or lease_token is None
                ):
                    raise ScopeError("audit batch scope or lease does not match")
                check_lease(barrier, scope.lease_key, lease_token, generation)
            for month, rows in sorted(by_month.items()):
                db = self._audit_db(self.audit_db_path(generation, tenancy_ocid, month))
                with db.write(durable=True) as conn:
                    before = conn.total_changes
                    conn.executemany(sql, rows)
                    inserted += conn.total_changes - before
        return inserted

    def query_audit(
        self,
        generation: int,
        tenancy_ocid: str,
        month: str,
        where: str = "1=1",
        params: tuple[Any, ...] = (),
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Read-only helper for analyzers/UI. ``where`` must use bound parameters only."""
        path = self.audit_db_path(generation, tenancy_ocid, month)
        if not path.exists():
            return []
        with self._audit_db(path).read() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events WHERE {where} "  # noqa: S608
                "ORDER BY event_time DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    # --- audit ingestion ledger and checkpoints (delta-fetching §1-§3) ---------------------
    def commit_interval(
        self,
        scope: CollectionScope,
        lease_token: str,
        cursor: str,
        start: datetime,
        end: datetime,
        run_id: str,
        source: str,
        query_version: str,
        events: int = 0,
        inserted: int = 0,
        status: str = "complete",
        detail: str | None = None,
    ) -> None:
        """Record one fetched interval and (if complete) move its checkpoint, atomically.

        Call only after every event batch of the interval is durable (``append_events``). Under the
        generation and scope-lease fence, in one durable transaction: a ledger row, the cursor's
        checkpoint (forward ``complete_through`` only moves forward; the backfill cursor only moves
        back) and the scan-run item. A ``gap`` records the interval without moving any checkpoint.
        """
        if scope.region is None:
            raise ScopeError("audit intervals are per region")
        if cursor not in ("forward", "backfill", "reconcile"):
            raise ValueError(f"unknown cursor {cursor!r}")
        gen, tenancy, region = scope.generation, scope.tenancy_ocid, scope.region
        now = iso(utcnow())
        with self.db.write(durable=True) as conn:
            check_fence(conn, gen)
            check_lease(conn, scope.lease_key, lease_token, gen)
            conn.execute(
                "INSERT INTO ingestion_ledger (generation, tenancy_ocid, region, cursor, "
                "interval_start, interval_end, status, events, inserted, source, query_version, "
                "run_id, detail, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    gen,
                    tenancy,
                    region,
                    cursor,
                    iso(start),
                    iso(end),
                    status,
                    events,
                    inserted,
                    source,
                    query_version,
                    run_id,
                    detail,
                    now,
                ),
            )
            if status == "complete":
                dataset = {
                    "forward": AUDIT_FORWARD,
                    "backfill": AUDIT_BACKFILL,
                    "reconcile": AUDIT_RECONCILE,
                }[cursor]
                value = iso(end) if cursor == "forward" else iso(start)
                # forward only moves forward, backfill only moves back
                conn.execute(
                    "INSERT INTO watermarks (generation, tenancy_ocid, dataset, region, "
                    "complete_through, run_id, query_version, lease_token, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(generation, tenancy_ocid, dataset, "
                    "region) DO UPDATE SET complete_through=excluded.complete_through, "
                    "run_id=excluded.run_id, query_version=excluded.query_version, "
                    "lease_token=excluded.lease_token, updated_at=excluded.updated_at "
                    "WHERE (?='forward' AND "
                    "excluded.complete_through > watermarks.complete_through) "
                    "OR (?='backfill' AND "
                    "excluded.complete_through < watermarks.complete_through) OR ?='reconcile'",
                    (
                        *(gen, tenancy, dataset, region, value, run_id, query_version),
                        *(lease_token, now, cursor, cursor, cursor),
                    ),
                )
            conn.execute(
                "INSERT INTO scan_runs (run_id, trigger, started_at, status, generation) "
                "VALUES (?, 'audit', ?, 'running', ?) ON CONFLICT(run_id) DO NOTHING",
                (run_id, now, gen),
            )
            conn.execute(
                "INSERT INTO scan_run_items (run_id, generation, tenancy_ocid, dataset, scope_key, "
                "region, status, complete, record_count, added, error, started_at, finished_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id, tenancy_ocid, dataset, "
                "scope_key) DO UPDATE SET status=CASE WHEN scan_run_items.status='ok' "
                "THEN excluded.status ELSE scan_run_items.status END, "
                "complete=MIN(scan_run_items.complete, excluded.complete), "
                "record_count=scan_run_items.record_count+excluded.record_count, "
                "added=scan_run_items.added+excluded.added, "
                "error=COALESCE(excluded.error, scan_run_items.error), "
                "finished_at=excluded.finished_at",
                (
                    run_id,
                    gen,
                    tenancy,
                    AUDIT_FORWARD,
                    scope.scope_key,
                    region,
                    "ok" if status == "complete" else "partial",
                    int(status == "complete"),
                    events,
                    inserted,
                    detail,
                    now,
                    now,
                ),
            )

    def ledger(
        self, generation: int, tenancy_ocid: str, region: str, cursor: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM ingestion_ledger WHERE generation=? AND tenancy_ocid=? AND region=?"
        params: list[Any] = [generation, tenancy_ocid, region]
        if cursor:
            sql += " AND cursor=?"
            params.append(cursor)
        with self.db.read() as conn:
            return [dict(r) for r in conn.execute(sql + " ORDER BY interval_start", params)]

    def invalidate_audit_coverage(
        self, generation: int, tenancy_ocid: str, region: str, since: datetime, reason: str
    ) -> None:
        """A month file was lost: forget coverage from ``since`` so it is fetched again."""
        with self.db.write(durable=True) as conn:
            check_fence(conn, generation)
            conn.execute(
                "UPDATE ingestion_ledger SET status='gap', detail=? WHERE generation=? AND "
                "tenancy_ocid=? AND region=? AND interval_end > ? AND status='complete'",
                (reason, generation, tenancy_ocid, region, iso(since)),
            )
            conn.execute(
                "UPDATE watermarks SET complete_through=?, updated_at=? WHERE generation=? AND "
                "tenancy_ocid=? AND region=? AND dataset=? AND complete_through > ?",
                (
                    iso(since),
                    iso(utcnow()),
                    generation,
                    tenancy_ocid,
                    region,
                    AUDIT_FORWARD,
                    iso(since),
                ),
            )
            conn.execute(
                "DELETE FROM watermarks WHERE generation=? AND tenancy_ocid=? AND region=? AND "
                "dataset=? AND complete_through < ?",
                (generation, tenancy_ocid, region, AUDIT_BACKFILL, iso(since)),
            )

    def audit_months(self, generation: int, tenancy_ocid: str) -> set[str]:
        folder = self.audit_root / generation_folder(generation) / tenancy_ocid
        if not folder.exists():
            return set()
        return {p.stem for p in folder.glob("*.db") if _MONTH.match(p.stem)}

    def audit_daily_counts(
        self, generation: int, tenancy_ocid: str, months: list[str]
    ) -> list[dict[str, Any]]:
        """Events per UTC day and region (activity-volume dashboard)."""
        out: list[dict[str, Any]] = []
        for month in months:
            path = self.audit_db_path(generation, tenancy_ocid, month)
            if not path.exists():
                continue
            with self._audit_db(path).read() as conn:
                out += [
                    dict(r)
                    for r in conn.execute(
                        "SELECT substr(event_time, 1, 10) AS day, region, COUNT(*) AS events "
                        "FROM audit_events GROUP BY day, region ORDER BY day"
                    )
                ]
        return out

    # --- watermarks (low-level; the audit coordinator commits intervals, delta-fetching §2) --
    def get_watermark(
        self, generation: int, tenancy_ocid: str, dataset: str, region: str | None = None
    ) -> Watermark | None:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT complete_through, run_id, updated_at FROM watermarks "
                "WHERE generation=? AND tenancy_ocid=? AND dataset=? AND region=?",
                (generation, tenancy_ocid, dataset, region or ""),
            ).fetchone()
        if not row:
            return None
        return Watermark(
            row["complete_through"], row["run_id"], datetime.fromisoformat(row["updated_at"])
        )

    def set_watermark(
        self,
        generation: int,
        tenancy_ocid: str,
        dataset: str,
        complete_through: str,
        run_id: str | None,
        region: str | None = None,
    ) -> None:
        with self.db.write(durable=True) as conn:
            check_fence(conn, generation)
            conn.execute(
                "INSERT INTO watermarks(generation, tenancy_ocid, dataset, region, "
                "complete_through, run_id, updated_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(generation, tenancy_ocid, dataset, region) DO UPDATE SET "
                "complete_through=excluded.complete_through, run_id=excluded.run_id, "
                "updated_at=excluded.updated_at",
                (
                    generation,
                    tenancy_ocid,
                    dataset,
                    region or "",
                    complete_through,
                    run_id,
                    iso(utcnow()),
                ),
            )

    # --- findings -------------------------------------------------------------------------
    def upsert_findings(self, findings: Iterable[Finding]) -> int:
        """Insert or update findings by identity.

        Keeps ``first_seen``; a reopened finding keeps its identity and clears ``resolved_at``;
        a locally suppressed finding stays suppressed. Every finding must belong to the current
        generation (checked in the committing transaction).
        """
        items = list(findings)
        if not items:
            return 0
        with self.db.write() as conn:
            for gen in {f.generation for f in items}:
                check_fence(conn, gen)
            for f in items:
                row = conn.execute(
                    "SELECT status, first_seen FROM findings WHERE finding_id=?", (f.finding_id,)
                ).fetchone()
                merged = f
                if row is not None:
                    status = (
                        FindingStatus.SUPPRESSED
                        if row["status"] == FindingStatus.SUPPRESSED.value
                        else f.status
                    )
                    merged = f.model_copy(
                        update={
                            "first_seen": datetime.fromisoformat(row["first_seen"]),
                            "status": status,
                            "resolved_at": f.resolved_at
                            if status is FindingStatus.RESOLVED
                            else None,
                        }
                    )
                write_finding(conn, merged)
        return len(items)

    def resolve_absent(
        self,
        generation: int,
        source: FindingSource,
        tenancy_ocid: str,
        rule_id: str,
        scope_key: str,
        seen_ids: set[str],
    ) -> int:
        """Resolve open findings of one *completely evaluated* scope that this run didn't emit.

        Callers must only use this after a complete evaluation of exactly that scope and rule;
        findings of other scopes, rules or failed evaluations are never touched.
        """
        now = iso(utcnow())
        with self.db.write() as conn:
            check_fence(conn, generation)
            rows = conn.execute(
                "SELECT finding_id FROM findings WHERE generation=? AND namespace=? AND "
                "tenancy_ocid=? AND rule_id=? AND scope_key=? AND status=?",
                (
                    generation,
                    IDENTITY_NAMESPACE[source],
                    tenancy_ocid,
                    rule_id,
                    scope_key,
                    FindingStatus.OPEN.value,
                ),
            ).fetchall()
            stale = [r["finding_id"] for r in rows if r["finding_id"] not in seen_ids]
            conn.executemany(
                "UPDATE findings SET status=?, resolved_at=?, "
                "data=json_set(data, '$.status', ?, '$.resolved_at', ?) WHERE finding_id=?",
                [
                    (FindingStatus.RESOLVED.value, now, FindingStatus.RESOLVED.value, now, k)
                    for k in stale
                ],
            )
        return len(stale)

    def list_findings(self, generation: int | None = None, **filters: Any) -> list[Finding]:
        allowed = {"source", "tenancy_ocid", "severity", "status", "rule_id", "scope_key"}
        clauses, params = ["generation=?"], []
        for key, value in filters.items():
            if key not in allowed:
                raise ValueError(f"unsupported filter {key!r}")
            if value is not None:
                clauses.append(f"{key}=?")
                params.append(value.value if hasattr(value, "value") else value)
        with self.db.read() as conn:
            gen = current_generation(conn) if generation is None else generation
            sql = "SELECT data FROM findings WHERE " + " AND ".join(clauses)  # noqa: S608
            sql += " ORDER BY last_seen DESC"
            return [
                Finding.model_validate_json(r["data"]) for r in conn.execute(sql, [gen, *params])
            ]

    def count_findings_by_severity(self, generation: int | None = None) -> dict[Severity, int]:
        with self.db.read() as conn:
            gen = current_generation(conn) if generation is None else generation
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE generation=? AND "
                "status='open' GROUP BY severity",
                (gen,),
            ).fetchall()
        return {Severity(r["severity"]): int(r["n"]) for r in rows}


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(value, default=str)


def _audit_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int)):
        return value
    return json.dumps(value, default=str)
