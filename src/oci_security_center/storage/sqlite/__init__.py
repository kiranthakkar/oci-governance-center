"""SQLite backend (Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oci_security_center.config import Settings
from oci_security_center.logging import get_logger
from oci_security_center.models import is_ocid
from oci_security_center.storage.errors import SchemaError
from oci_security_center.storage.sqlite.app_state import SqliteAppStateStore
from oci_security_center.storage.sqlite.data_store import SqliteDataStore, generation_folder
from oci_security_center.storage.sqlite.db import SqliteDatabase, ensure_private_dir
from oci_security_center.storage.sqlite.migrations import MigrationResult, migrate
from oci_security_center.storage.sqlite.reset import recover_interrupted_switch

log = get_logger(__name__)


@dataclass
class SqliteStores:
    db: SqliteDatabase
    state: SqliteAppStateStore
    data: SqliteDataStore
    migration: MigrationResult


def open_stores(settings: Settings) -> SqliteStores:
    """Open ``osc.db``, applying pending migrations first (backed up beforehand)."""
    ensure_private_dir(settings.data_root)
    db = SqliteDatabase(settings.db_path)
    if not db.quick_check():  # storage §6: integrity check at startup
        raise SchemaError(
            f"{settings.db_path} failed its integrity check; restore it with `osc db restore`"
        )
    result = migrate(db, settings.data_root / "backups")
    if result.backup is not None:
        log.warning(
            "migrated osc.db v%d -> v%d; pre-migration backup: %s",
            result.from_version,
            result.to_version,
            result.backup,
        )
    state = SqliteAppStateStore(db)
    data = SqliteDataStore(db, settings.audit_root)
    recovered = recover_interrupted_switch(db, state, data)
    if recovered:
        log.warning("organization switch recovery: %s", recovered)
    if state.organization().state == "active":
        _adopt_legacy_audit_folders(settings.audit_root, state.current_generation())
    return SqliteStores(db, state, data, result)


def _adopt_legacy_audit_folders(audit_root: Path, generation: int) -> None:
    """v0.1 kept ``audit/<tenancy>/``; move those under the current ``audit/g<N>/``. Idempotent."""
    if not audit_root.exists():
        return
    target_root = audit_root / generation_folder(generation)
    for folder in sorted(p for p in audit_root.iterdir() if p.is_dir() and is_ocid(p.name)):
        target = target_root / folder.name
        if target.exists():
            log.warning("not adopting legacy audit folder %s: %s exists", folder.name, target)
            continue
        ensure_private_dir(target_root)
        folder.rename(target)


__all__ = [
    "SqliteAppStateStore",
    "SqliteDataStore",
    "SqliteDatabase",
    "SqliteStores",
    "open_stores",
]
