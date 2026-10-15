"""Coordinated organization replacement (docs/control-plane.md R5, §6.1).

Phases, recorded in ``switch_journal``:

1. Preflight happens in the caller (configuration, secrets, connection test) before this runs.
2. Take the exclusive maintenance barrier: fenced writes and new scope leases are refused. Drain
   in-flight collection (wait for its leases to finish) up to a timeout; on timeout abort with
   nothing changed.
3. ``prepared``: journal row written durably.
4. ``committed``: one durable transaction deletes the previous organization's app state for
   tenancies outside ``keep``, **all** collected data of the old generation, every session and
   lease, advances the generation and records the new parent — while staying in maintenance.
5. Old generations' audit folders are moved into ``audit/.quarantine/`` (renames, idempotent).
   If that fails OSC stays in maintenance with the error journaled, so no old files can be seen.
6. ``active``: maintenance ends under the new generation.
7. ``cleaned``: quarantined folders are deleted. Failures are journaled and retried on startup;
   they never block the new organization. Deletion is not secure erasure.

``recover_interrupted_switch`` finishes or rolls back a switch whose holder died (its maintenance
lease expired): ``prepared`` rolls back, ``committed`` resumes at step 5, ``active`` retries
cleanup.
The control-plane audit trail and historic backups are kept.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from collections.abc import Callable, Collection, Iterable

from oci_security_center.logging import get_logger
from oci_security_center.models.common import iso, utcnow
from oci_security_center.storage.base import PurgeResult
from oci_security_center.storage.datasets import DATASETS
from oci_security_center.storage.errors import MaintenanceError
from oci_security_center.storage.sqlite.app_state import SqliteAppStateStore
from oci_security_center.storage.sqlite.data_store import SqliteDataStore, generation_folder
from oci_security_center.storage.sqlite.db import SqliteDatabase

log = get_logger(__name__)

QUARANTINE = ".quarantine"

# Collected data: every row belongs to one organization generation.
_GENERATION_TABLES = (
    "findings",
    "watermarks",
    "record_changes",
    "scope_manifests",
    "scan_run_items",
    "scan_runs",
    "capabilities",
    "ingestion_ledger",
)


class SwitchIncomplete(RuntimeError):
    """Switch committed, but old audit files couldn't be quarantined; OSC stays in maintenance."""


def _journal(conn: sqlite3.Connection, journal_id: int, phase: str, error: str | None) -> None:
    row = conn.execute("SELECT errors FROM switch_journal WHERE id=?", (journal_id,)).fetchone()
    errors = json.loads(row["errors"]) + ([error] if error else [])
    conn.execute(
        "UPDATE switch_journal SET phase=?, errors=?, updated_at=? WHERE id=?",
        (phase, json.dumps(errors), iso(utcnow()), journal_id),
    )


def _set_phase(db: SqliteDatabase, journal_id: int, phase: str, error: str | None = None) -> None:
    with db.write(durable=True) as conn:
        _journal(conn, journal_id, phase, error)


def _drain(state: SqliteAppStateStore, timeout_s: float, poll_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while state.active_leases():
        if time.monotonic() >= deadline:
            raise MaintenanceError(
                "in-flight collection did not finish in time; the organization was not changed"
            )
        time.sleep(poll_s)


def replace_organization(
    db: SqliteDatabase,
    state: SqliteAppStateStore,
    data: SqliteDataStore,
    keep: Collection[str],
    parent_ocid: str,
    holder: str,
    drop_settings: Iterable[str] = (),
    drain_timeout_s: float = 120.0,
    poll_s: float = 0.5,
    install_candidate: Callable[[sqlite3.Connection, int], None] | None = None,
) -> tuple[int, PurgeResult]:
    """Replace the organization; return (new generation, what was removed)."""
    result = PurgeResult()
    keep_list = sorted(keep)
    marks = ",".join("?" * len(keep_list))
    not_kept = f"NOT IN ({marks})"
    token = state.begin_maintenance(holder)
    journal_id: int | None = None
    try:
        _drain(state, drain_timeout_s, poll_s)
        org = state.organization()
        with db.write(durable=True) as conn:
            journal_id = conn.execute(
                "INSERT INTO switch_journal (old_generation, new_generation, old_parent, "
                "new_parent, phase, holder, started_at, updated_at) "
                "VALUES (?,?,?,?, 'prepared', ?,?,?)",
                (
                    org.generation,
                    org.generation + 1,
                    org.parent_tenancy_ocid,
                    parent_ocid,
                    holder,
                    iso(utcnow()),
                    iso(utcnow()),
                ),
            ).lastrowid
        with db.write(durable=True) as conn:
            removed = [
                r["ocid"]
                for r in conn.execute(
                    f"SELECT ocid FROM tenancies WHERE ocid {not_kept}",  # noqa: S608
                    keep_list,
                )
            ]
            refs = [
                r["secret_ref"]
                for r in conn.execute(
                    f"SELECT secret_ref FROM connections WHERE tenancy_ocid {not_kept} "  # noqa: S608
                    "AND secret_ref LIKE 'local:%'",
                    keep_list,
                )
            ]

            def delete(table: str, where: str, params: Iterable[object]) -> None:
                n = conn.execute(f"DELETE FROM {table} WHERE {where}", list(params)).rowcount  # noqa: S608
                result.rows_deleted[table] = result.rows_deleted.get(table, 0) + n

            delete("tenancies", f"ocid {not_kept}", keep_list)
            delete("connections", f"tenancy_ocid {not_kept}", keep_list)
            for ref in refs:
                delete("local_secrets", "id=?", [ref.partition(":")[2]])
            delete(
                "requirement_checks",
                f"tenancy_ocid {not_kept} OR target_tenancy_ocid {not_kept}",
                keep_list + keep_list,
            )
            for ocid in removed:
                delete("settings_kv", "key=?", [f"verify:{ocid}"])
            for key in drop_settings:
                delete("settings_kv", "key=?", [key])
            for table in _GENERATION_TABLES + tuple(s.table for s in DATASETS.values()):
                delete(table, "generation=?", [org.generation])
            delete("findings_quarantine", "1=1", [])
            conn.execute(  # the parent setting moves with the generation, atomically
                "INSERT INTO settings_kv(key, value, updated_at) "
                "VALUES ('parent_tenancy_ocid', ?, ?) ON CONFLICT(key) DO UPDATE SET "
                "value=excluded.value, updated_at=excluded.updated_at",
                (parent_ocid, iso(utcnow())),
            )
            delete("sessions", "1=1", [])
            generation = state.advance_generation_in(conn, token, parent_ocid)
            if install_candidate is not None:
                install_candidate(conn, generation)
            assert journal_id is not None
            _journal(conn, journal_id, "committed", None)
    except BaseException:
        state.end_maintenance(token)  # nothing was committed; reopen the old generation
        if journal_id is not None:
            _set_phase(db, journal_id, "aborted", "switch aborted before commit")
        raise
    db.incremental_vacuum()
    _finish(db, state, data, journal_id, token, generation, result)
    return generation, result


def _finish(
    db: SqliteDatabase,
    state: SqliteAppStateStore,
    data: SqliteDataStore,
    journal_id: int,
    token: str,
    generation: int,
    result: PurgeResult,
) -> None:
    """Steps 5-7: quarantine old audit folders, go active, then clean up."""
    root = data.audit_root
    quarantine = root / QUARANTINE
    current = generation_folder(generation)
    if root.exists():
        for folder in sorted(
            p for p in root.iterdir() if p.is_dir() and p.name not in (current, QUARANTINE)
        ):
            target = quarantine / f"{folder.name}-switch{journal_id}"
            try:
                quarantine.mkdir(mode=0o700, exist_ok=True)
                data.forget_audit_dbs(folder)
                folder.rename(target)
            except OSError as exc:
                error = f"could not quarantine {folder.name}: {type(exc).__name__}"
                _set_phase(db, journal_id, "committed", error)
                result.errors.append(error)
                raise SwitchIncomplete(
                    f"{error}. OSC stays in maintenance; fix the folder permissions and run "
                    "`osc admin recover`."
                ) from exc
    with db.write(durable=True) as conn:
        state.end_maintenance_in(conn, token)
        _journal(conn, journal_id, "active", None)
    _cleanup(db, data, journal_id, result)


def _cleanup(
    db: SqliteDatabase, data: SqliteDataStore, journal_id: int, result: PurgeResult
) -> None:
    quarantine = data.audit_root / QUARANTINE
    failures: list[str] = []
    if quarantine.exists():
        root = data.audit_root.resolve()
        for folder in sorted(p for p in quarantine.iterdir()):
            resolved = folder.resolve()
            if root not in resolved.parents:
                failures.append(f"skipped {folder.name}: it points outside the data root")
                continue
            files = [str(f) for f in sorted(resolved.rglob("*")) if f.is_file()]
            try:
                if resolved.is_dir():
                    shutil.rmtree(resolved)
                else:
                    resolved.unlink()
            except OSError as exc:
                failures.append(f"could not delete {folder.name}: {type(exc).__name__}")
                continue
            result.files_deleted += files
    for failure in failures:
        log.warning("organization switch cleanup: %s", failure)
    result.errors += failures
    _set_phase(db, journal_id, "active" if failures else "cleaned", "; ".join(failures) or None)


def recover_interrupted_switch(
    db: SqliteDatabase, state: SqliteAppStateStore, data: SqliteDataStore
) -> str | None:
    """Finish or roll back a switch whose holder died. Returns what was done, if anything.

    Does nothing while another process holds an unexpired maintenance lease.
    """
    with db.read() as conn:
        row = conn.execute(
            "SELECT * FROM switch_journal WHERE phase IN ('prepared','committed','active') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    journal_id, phase = int(row["id"]), row["phase"]
    result = PurgeResult()
    if phase == "active":
        _cleanup(db, data, journal_id, result)
        return f"retried cleanup of switch {journal_id}"
    org = state.organization()
    if org.state != "maintenance":
        # Inconsistent journal (e.g. restored database); record it, don't guess.
        _set_phase(db, journal_id, "aborted", "journal found while OSC was active")
        return f"closed stale switch journal {journal_id}"
    try:
        token = state.begin_maintenance("recovery")  # only succeeds if the holder's lease expired
    except MaintenanceError:
        return None
    if phase == "prepared":
        state.end_maintenance(token)
        _set_phase(db, journal_id, "aborted", "holder stopped before commit; rolled back")
        return f"rolled back switch {journal_id}"
    _finish(db, state, data, journal_id, token, org.generation, result)
    return f"completed switch {journal_id}"
