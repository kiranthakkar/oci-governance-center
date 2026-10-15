"""Retention purge (docs/storage.md §5). Default 90 days, per-dataset overrides.

Only ever deletes rows in OSC's own databases and files under ``OSC_DATA_ROOT``.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from oci_security_center.config import Settings
from oci_security_center.models.common import iso, utcnow
from oci_security_center.storage.base import PurgeResult
from oci_security_center.storage.datasets import AUDIT_DATASET, DATASETS
from oci_security_center.storage.errors import MaintenanceError
from oci_security_center.storage.sqlite.app_state import SqliteAppStateStore
from oci_security_center.storage.sqlite.data_store import SqliteDataStore
from oci_security_center.storage.sqlite.db import SqliteDatabase
from oci_security_center.storage.sqlite.reset import _drain

_MONTH_FILE = re.compile(r"^(\d{4})-(\d{2})\.db$")
_GEN_DIR = re.compile(r"^g\d+$")  # skips .quarantine (handled by the switch cleanup)


def _month_end(year: int, month: int) -> datetime:
    if month == 12:
        return datetime(year + 1, 1, 1, tzinfo=UTC)
    return datetime(year, month + 1, 1, tzinfo=UTC)


def purge(
    settings: Settings,
    db: SqliteDatabase,
    data_store: SqliteDataStore,
    now: datetime | None = None,
) -> PurgeResult:
    """Purge under the exclusive maintenance barrier, serialized with backup and switching."""
    state = SqliteAppStateStore(db)
    token = state.begin_maintenance("retention")
    try:
        _drain(state, settings.switch_drain_seconds, 0.05)
        with db.write(durable=True) as conn:
            row = conn.execute(
                "SELECT state, maintenance_token FROM organization_state WHERE id=1"
            ).fetchone()
            if row["state"] != "maintenance" or row["maintenance_token"] != token:
                raise MaintenanceError("retention maintenance lease was lost")
            result = _purge(settings, conn, data_store, now or utcnow())
        db.incremental_vacuum()
        return result
    finally:
        state.end_maintenance(token)


def _purge(
    settings: Settings, conn: sqlite3.Connection, data_store: SqliteDataStore, now: datetime
) -> PurgeResult:
    result = PurgeResult()

    def cutoff(days: int) -> str:
        return iso(now - timedelta(days=days))

    for spec in DATASETS.values():
        n = conn.execute(
            f"DELETE FROM {spec.table} WHERE is_deleted=1 AND deleted_at < ?",  # noqa: S608
            (cutoff(settings.retention_for(spec.id)),),
        ).rowcount
        result.rows_deleted[spec.table] = n
    result.rows_deleted["record_changes"] = conn.execute(
        "DELETE FROM record_changes WHERE changed_at < ?",
        (cutoff(settings.retention_for("record_changes")),),
    ).rowcount
    result.rows_deleted["findings"] = conn.execute(
        "DELETE FROM findings WHERE status = 'resolved' AND resolved_at < ?",
        (cutoff(settings.retention_for("findings")),),
    ).rowcount
    result.rows_deleted["scan_runs"] = conn.execute(
        "DELETE FROM scan_runs WHERE started_at < ?",
        (cutoff(settings.retention_for("scan_runs")),),
    ).rowcount
    result.rows_deleted["control_plane_events"] = conn.execute(
        "DELETE FROM control_plane_events WHERE at < ?",
        (cutoff(settings.control_plane_event_retention_days),),
    ).rowcount
    result.rows_deleted["sessions"] = conn.execute(
        "DELETE FROM sessions WHERE expires_at < ?", (iso(now),)
    ).rowcount

    audit_cutoff = now - timedelta(days=settings.retention_for(AUDIT_DATASET))
    root = data_store.audit_root.resolve()
    if root.exists():
        result.rows_deleted["audit_events"] = 0
        # audit/g<generation>/<tenancy>/<YYYY-MM>.db
        tenancy_dirs = [
            t
            for g in sorted(p for p in root.iterdir() if p.is_dir() and _GEN_DIR.match(p.name))
            for t in sorted(p for p in g.iterdir() if p.is_dir())
        ]
        for tenancy_dir in tenancy_dirs:
            for f in sorted(tenancy_dir.iterdir()):
                m = _MONTH_FILE.match(f.name)
                if not m:
                    continue
                if _month_end(int(m.group(1)), int(m.group(2))) <= audit_cutoff:
                    data_store.forget_audit_dbs(f.parent)
                    _delete_db_files(f, root, result)
                elif f.name[:7] <= iso(audit_cutoff)[:7]:
                    # boundary month: delete rows older than the cutoff
                    adb = data_store._audit_db(f)
                    with adb.write() as conn:
                        result.rows_deleted["audit_events"] += conn.execute(
                            "DELETE FROM audit_events WHERE event_time < ?", (iso(audit_cutoff),)
                        ).rowcount
                    adb.incremental_vacuum()
    return result


def _delete_db_files(path: Path, root: Path, result: PurgeResult) -> None:
    resolved = path.resolve()
    if root not in resolved.parents:
        raise RuntimeError(f"refusing to delete outside data root: {resolved}")
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(resolved) + suffix)
        if candidate.exists():
            candidate.unlink()
            result.files_deleted.append(str(candidate))
