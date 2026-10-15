"""Full backup and restore (docs/storage.md §6.1).

Backup (OSC may keep running; read-only pages continue):

1. Take the exclusive maintenance barrier and drain in-flight collection (fenced writes, scope
   leases and checkpoints pause). A drain timeout aborts without a backup.
2. In a private temporary directory, copy ``osc.db`` and every audit file of the current generation
   with SQLite's online backup API (never a raw file copy of a live database), files 0600.
3. Write ``manifest.json``: backup ID/time, parent and generation, schema and finding-identity
   versions, every file with size and SHA-256, audit checkpoints and ledger coverage, retention
   settings, an identifier of the encryption key (never the key) and a value encrypted with it.
   ``quick_check`` every copied database; fsync; publish by renaming the directory. A directory
   without a manifest is never restorable.
4. Expire published backups older than ``OSC_BACKUP_RETENTION_DAYS``.

Restore (offline — stop ``osc web`` and ``osc scheduler`` first):

1. Validate the manifest, file list, sizes and checksums, database integrity, schema support,
   expected parent, and that the supplied key decrypts the verification value. Any failure stops
   before anything changes.
2. Stage into a private directory next to the data root, migrate explicitly if the backup is older,
   move the data to a **new generation** (rows re-keyed, audit folder renamed), end every session
   and lease, apply current retention.
3. Reconcile audit checkpoints with the restored files. ``main_db_only`` (a partial restore) drops
   audit checkpoints and ledger so the retained window is fetched again, and says so.
4. Swap: the current data root is kept as ``<root>.pre-restore-<time>``; the staged copy becomes the
   data root.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from oci_security_center.config import Settings
from oci_security_center.logging import get_logger
from oci_security_center.models import Finding
from oci_security_center.models.common import iso, utcnow
from oci_security_center.models.findings import FINDING_IDENTITY_VERSION
from oci_security_center.storage.datasets import DATASETS
from oci_security_center.storage.errors import MaintenanceError, StorageError
from oci_security_center.storage.sqlite.data_store import generation_folder, write_finding
from oci_security_center.storage.sqlite.db import SqliteDatabase, ensure_private_dir
from oci_security_center.storage.sqlite.schema import SCHEMA_VERSION

log = get_logger(__name__)

FORMAT = 1
MANIFEST = "manifest.json"
PREFIX = "osc-backup-"
_VERIFY = b"osc-backup-verification:"
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


class BackupError(StorageError):
    """Backup or restore refused; nothing was published or changed."""


@dataclass
class RestoreResult:
    data_root: Path
    previous: Path | None
    generation: int
    notes: list[str] = field(default_factory=list)


def key_id(fernet_key: bytes) -> str:
    """Identifies which key a backup needs, without revealing it."""
    return hashlib.sha256(b"osc-key-id:" + fernet_key).hexdigest()[:16]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sqlite_copy(src: Path, dest: Path) -> None:
    """Online, consistent copy of a SQLite database (WAL included) to a new 0600 file."""
    ensure_private_dir(dest.parent)
    fd = os.open(dest, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    os.close(fd)
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    target = sqlite3.connect(dest)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    with dest.open("rb") as fh:
        os.fsync(fh.fileno())


def _quick_check(path: Path) -> bool:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = conn.execute("PRAGMA quick_check").fetchone()
        return bool(row and row[0] == "ok")
    finally:
        conn.close()


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# --- backup --------------------------------------------------------------------------------------
def create_backup(
    settings: Settings,
    db: SqliteDatabase,
    state: Any,
    fernet_key: bytes,
    dest_root: Path,
    holder: str = "backup",
    poll_s: float = 0.5,
) -> Path:
    """Write a complete, verified backup set under ``dest_root``; return its directory."""
    from oci_security_center.storage.sqlite.reset import _drain

    ensure_private_dir(dest_root)
    cipher = Fernet(fernet_key)
    backup_id = f"{PREFIX}{utcnow():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"
    tmp = dest_root / f".tmp-{backup_id}"
    token = state.begin_maintenance(holder)
    try:
        _drain(state, settings.switch_drain_seconds, poll_s)
        org = state.organization()
        # Hold the cross-process barrier across the whole backup set. Even an expired
        # maintenance lease cannot be taken over while files and checkpoints are copied.
        with db.write(durable=True) as barrier:
            row = barrier.execute(
                "SELECT state, maintenance_token FROM organization_state WHERE id=1"
            ).fetchone()
            if row["state"] != "maintenance" or row["maintenance_token"] != token:
                raise MaintenanceError("backup maintenance lease was lost")
            ensure_private_dir(tmp)
            files: list[dict[str, Any]] = []
            _sqlite_copy(db.path, tmp / "osc.db")
            audit_src = settings.audit_root / generation_folder(org.generation)
            if audit_src.exists():
                for f in sorted(audit_src.rglob("*.db")):
                    _sqlite_copy(f, tmp / "audit" / f.relative_to(audit_src))
            for f in sorted(p for p in tmp.rglob("*") if p.is_file()):
                if not _quick_check(f):
                    raise BackupError(f"backup copy {f.name} failed its integrity check")
                files.append(
                    {
                        "path": f.relative_to(tmp).as_posix(),
                        "size": f.stat().st_size,
                        "sha256": _sha256(f),
                    }
                )
            with sqlite3.connect(f"file:{tmp / 'osc.db'}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row
                watermarks = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT tenancy_ocid, dataset, region, complete_through FROM watermarks "
                        "WHERE generation=?",
                        (org.generation,),
                    )
                ]
            manifest = {
                "format": FORMAT,
                "backup_id": backup_id,
                "created_at": iso(utcnow()),
                "parent_tenancy_ocid": org.parent_tenancy_ocid,
                "generation": org.generation,
                "schema_version": SCHEMA_VERSION,
                "finding_identity_version": FINDING_IDENTITY_VERSION,
                "files": files,
                "audit_checkpoints": watermarks,
                "retention_days": settings.retention_days,
                "retention_overrides": settings.retention_overrides,
                "key_id": key_id(fernet_key),
                "verification": cipher.encrypt(_VERIFY + backup_id.encode()).decode(),
            }
            mpath = tmp / MANIFEST
            fd = os.open(mpath, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(manifest, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            _fsync_dir(tmp)
            final = dest_root / backup_id
            tmp.rename(final)  # atomic publish
            _fsync_dir(dest_root)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    finally:
        state.end_maintenance(token)
    expire_backups(dest_root, settings.backup_retention_days)
    return final


def list_backups(dest_root: Path) -> list[Path]:
    if not dest_root.exists():
        return []
    return sorted(
        p for p in dest_root.iterdir() if p.name.startswith(PREFIX) and (p / MANIFEST).exists()
    )


def expire_backups(dest_root: Path, retention_days: int) -> list[str]:
    cutoff = time.time() - retention_days * 86_400
    removed = []
    for p in list_backups(dest_root):
        if (p / MANIFEST).stat().st_mtime < cutoff:
            shutil.rmtree(p)
            removed.append(p.name)
    for p in dest_root.glob(f".tmp-{PREFIX}*") if dest_root.exists() else []:
        if p.stat().st_mtime < time.time() - 86_400:  # abandoned, never published
            shutil.rmtree(p, ignore_errors=True)
    return removed


# --- restore -------------------------------------------------------------------------------------
def validate_backup(
    backup_dir: Path, fernet_key: bytes, main_db_only: bool = False
) -> dict[str, Any]:
    """Check everything a restore depends on. Raises BackupError; changes nothing."""
    mpath = backup_dir / MANIFEST
    if not mpath.exists():
        raise BackupError("not a complete backup (no manifest; possibly interrupted)")
    manifest: dict[str, Any] = json.loads(mpath.read_text())
    if manifest.get("format") != FORMAT:
        raise BackupError(f"unsupported backup format {manifest.get('format')}")
    if int(manifest["schema_version"]) > SCHEMA_VERSION:
        raise BackupError(
            f"backup schema v{manifest['schema_version']} is newer than this OSC "
            f"(v{SCHEMA_VERSION})"
        )
    if manifest.get("key_id") != key_id(fernet_key):
        raise BackupError("the supplied encryption key is not the key this backup was made with")
    cipher = Fernet(fernet_key)
    try:
        value = cipher.decrypt(manifest["verification"].encode())
    except InvalidToken as exc:
        raise BackupError("the supplied encryption key can't decrypt this backup") from exc
    if value != _VERIFY + manifest["backup_id"].encode():
        raise BackupError("backup verification value doesn't match")
    for f in manifest["files"]:
        path = backup_dir / f["path"]
        if main_db_only and f["path"] != "osc.db":
            continue
        if not path.is_file():
            raise BackupError(f"backup file missing: {f['path']}")
        if path.stat().st_size != f["size"] or _sha256(path) != f["sha256"]:
            raise BackupError(f"backup file changed or corrupt: {f['path']}")
        if not _quick_check(path):
            raise BackupError(f"backup database failed its integrity check: {f['path']}")
    if not any(f["path"] == "osc.db" for f in manifest["files"]):
        raise BackupError("backup has no osc.db")
    return manifest


def restore_backup(
    settings: Settings,
    backup_dir: Path,
    fernet_key: bytes,
    expect_parent: str | None = None,
    main_db_only: bool = False,
) -> RestoreResult:
    """Restore offline into ``settings.data_root`` (see module docstring)."""
    from oci_security_center.storage.sqlite import open_stores
    from oci_security_center.storage.sqlite.retention import purge

    manifest = validate_backup(backup_dir, fernet_key, main_db_only)
    if expect_parent and manifest.get("parent_tenancy_ocid") != expect_parent:
        raise BackupError(
            f"backup is of parent {manifest.get('parent_tenancy_ocid')}, not {expect_parent}"
        )
    root = settings.data_root
    live_generation = 0
    if (root / "osc.db").exists():
        with sqlite3.connect(f"file:{root / 'osc.db'}?mode=ro", uri=True) as live:
            live_generation = int(
                live.execute("SELECT generation FROM organization_state WHERE id=1").fetchone()[0]
            )
    stamp = f"{utcnow():%Y%m%dT%H%M%SZ}"
    staging = root.parent / f".{root.name}.restore-{stamp}"
    notes: list[str] = []
    try:
        ensure_private_dir(staging)
        for f in manifest["files"]:
            if main_db_only and f["path"] != "osc.db":
                continue
            src = backup_dir / f["path"]
            if f["path"] == "osc.db":
                dest = staging / "osc.db"
            else:  # backup "audit/<tenancy>/<month>.db" -> "audit/g<generation>/<tenancy>/..."
                relative = Path(f["path"]).relative_to("audit")
                dest = staging / "audit" / generation_folder(manifest["generation"]) / relative
            ensure_private_dir(dest.parent)
            shutil.copyfile(src, dest)
            os.chmod(dest, 0o600)
        key_file = root / ".secret_key"
        if key_file.exists():
            shutil.copyfile(key_file, staging / ".secret_key")
            os.chmod(staging / ".secret_key", 0o600)

        staged = settings.model_copy(update={"data_root": staging})
        stores = open_stores(staged)  # explicit migrations if the backup is older
        old_gen = int(manifest["generation"])
        with stores.db.write(durable=True) as conn:
            current = int(conn.execute("SELECT generation FROM organization_state").fetchone()[0])
            new_gen = max(current, old_gen, live_generation) + 1
            findings = [
                Finding.model_validate_json(r["data"])
                for r in conn.execute("SELECT data FROM findings WHERE generation=?", (old_gen,))
            ]
            conn.execute("DELETE FROM findings WHERE generation=?", (old_gen,))
            for finding in findings:
                write_finding(conn, finding.model_copy(update={"generation": new_gen}))
            for table in tuple(t for t in _GENERATION_TABLES if t != "findings") + tuple(
                s.table for s in DATASETS.values()
            ):
                sql = f"UPDATE {table} SET generation=? WHERE generation=?"  # noqa: S608
                conn.execute(sql, (new_gen, old_gen))
            conn.execute(
                "UPDATE scope_manifests SET manifest=json_set(manifest, '$.scope.generation', ?) "
                "WHERE generation=?",
                (new_gen, new_gen),
            )
            conn.execute(
                "UPDATE organization_state SET generation=?, state='active', "
                "maintenance_token=NULL, "
                "maintenance_holder=NULL, maintenance_expires_at=NULL, updated_at=? WHERE id=1",
                (new_gen, iso(utcnow())),
            )
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM scope_leases")
            if main_db_only:
                conn.execute("DELETE FROM watermarks WHERE dataset LIKE 'audit.events%'")
                conn.execute("DELETE FROM ingestion_ledger")
                notes.append(
                    "partial restore: audit events were not restored; audit checkpoints were reset "
                    "and the retained window will be fetched again (OCI keeps 365 days)"
                )
        old_dir = staging / "audit" / generation_folder(old_gen)
        if old_dir.exists():
            old_dir.rename(staging / "audit" / generation_folder(new_gen))
        stores.data._audit_dbs.clear()
        result = purge(staged, stores.db, stores.data)
        if result.files_deleted:
            notes.append(f"retention removed {len(result.files_deleted)} expired audit files")
        _reconcile_audit(stores, new_gen, notes)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    previous: Path | None = None
    if root.exists():
        previous = root.parent / f"{root.name}.pre-restore-{stamp}"
        root.rename(previous)
    staging.rename(root)
    log.warning("restored backup %s into %s (generation %d)", manifest["backup_id"], root, new_gen)
    return RestoreResult(root, previous, new_gen, notes)


def _reconcile_audit(stores: Any, generation: int, notes: list[str]) -> None:
    """Checkpoints must not claim coverage for audit files that aren't there (§6.1 step 7)."""
    from datetime import datetime

    with stores.db.read() as conn:
        rows = conn.execute(
            "SELECT DISTINCT tenancy_ocid, region FROM ingestion_ledger WHERE generation=?",
            (generation,),
        ).fetchall()
    for r in rows:
        present = stores.data.audit_months(generation, r["tenancy_ocid"])
        for row in stores.data.ledger(generation, r["tenancy_ocid"], r["region"]):
            month = row["interval_start"][:7]
            if row["status"] == "complete" and row["events"] and month not in present:
                since = datetime.fromisoformat(f"{month}-01T00:00:00+00:00")
                stores.data.invalidate_audit_coverage(
                    generation, r["tenancy_ocid"], r["region"], since, "missing after restore"
                )
                notes.append(
                    f"audit coverage for {r['tenancy_ocid']} {r['region']} from {month} "
                    "will be refetched"
                )
                break
