"""Explicit, numbered schema migrations for ``osc.db`` (docs/architecture.md §5).

* A new database is created from the frozen ``BASELINE_V1`` and then migrated like any other.
* Before migrating an existing database, a full online backup is written to
  ``<data_root>/backups/osc-pre-v<N>-<timestamp>.db`` (0600). To roll back, stop OSC and restore
  that file over ``osc.db`` with the matching (older) OSC version.
* Each migration runs in one durable transaction and records its version in ``schema_versions``.
* A database newer than this OSC is refused, never "downgraded".
* After migrating, ``ensure_dataset_tables`` adds tables for newly registered datasets and refuses
  to run when an existing dataset table no longer matches the registry (that needs a migration).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from oci_security_center.models.common import canonical_json, iso, utcnow
from oci_security_center.models.findings import Finding
from oci_security_center.storage.datasets import DATASETS
from oci_security_center.storage.errors import SchemaError
from oci_security_center.storage.sqlite.data_store import write_finding
from oci_security_center.storage.sqlite.db import SqliteDatabase
from oci_security_center.storage.sqlite.schema import (
    BASELINE_V1,
    SCHEMA_VERSION,
    dataset_table_columns,
    dataset_table_ddl,
)

COMPONENT = "osc_db"

# Evaluation scopes used by control-plane coverage findings (shared with the control plane).
SCOPE_PARENT_POLICIES = canonical_json({"evaluation": "parent_policies"})
SCOPE_CHILD_ACCESS = canonical_json({"evaluation": "child_access"})


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


# --- migration 2: generations, leases, scoped snapshots, versioned finding identity ---------------
_V2_NEW_TABLES = [
    """CREATE TABLE organization_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL,
  parent_tenancy_ocid TEXT,
  state TEXT NOT NULL CHECK (state IN ('active', 'maintenance')),
  maintenance_token TEXT,
  maintenance_holder TEXT,
  maintenance_expires_at TEXT,
  updated_at TEXT NOT NULL
) STRICT""",
    """CREATE TABLE scope_leases (
  lease_key TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  token TEXT NOT NULL,
  holder TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT""",
    """CREATE TABLE scope_manifests (
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  dataset TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  run_id TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  complete INTEGER NOT NULL,
  applied INTEGER NOT NULL,
  manifest TEXT NOT NULL CHECK (json_valid(manifest)),
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (generation, tenancy_ocid, dataset, scope_key, run_id)
) STRICT""",
    "CREATE INDEX ix_manifests_applied ON scope_manifests "
    "(generation, tenancy_ocid, dataset, scope_key, applied, started_at)",
    """CREATE TABLE findings_quarantine (
  legacy_key TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  data TEXT NOT NULL CHECK (json_valid(data)),
  quarantined_at TEXT NOT NULL
) STRICT""",
]

_V2_FINDINGS = [
    """CREATE TABLE findings_v2 (
  finding_id TEXT PRIMARY KEY,
  identity_version INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  namespace TEXT NOT NULL,
  source TEXT NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  source_record_id TEXT,
  occurrence_key TEXT,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  resource_ocid TEXT,
  region TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  resolved_at TEXT,
  identity TEXT NOT NULL CHECK (json_valid(identity)),
  data TEXT NOT NULL CHECK (json_valid(data))
) STRICT""",
]
_V2_FINDINGS_INDEXES = [
    "CREATE INDEX ix_findings_sev ON findings (generation, severity, status, last_seen)",
    "CREATE INDEX ix_findings_tenancy ON findings (generation, tenancy_ocid, status)",
    "CREATE INDEX ix_findings_eval ON findings "
    "(generation, namespace, tenancy_ocid, rule_id, scope_key, status)",
]

_V2_REBUILDS: dict[str, tuple[str, str, list[str]]] = {
    # table: (new DDL, INSERT ... SELECT from <table>__v1, indexes)
    "record_changes": (
        """CREATE TABLE record_changes (
  id INTEGER PRIMARY KEY,
  generation INTEGER NOT NULL,
  dataset TEXT NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  record_key TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('added','modified','removed')),
  old_hash TEXT, new_hash TEXT,
  run_id TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  data TEXT CHECK (data IS NULL OR json_valid(data))
) STRICT""",
        "INSERT INTO record_changes (id, generation, dataset, tenancy_ocid, scope_key, "
        "schema_version, record_key, change_type, old_hash, new_hash, run_id, changed_at, data) "
        "SELECT id, :gen, dataset, tenancy_ocid, '{}', 1, record_key, change_type, old_hash, "
        "new_hash, run_id, changed_at, data FROM record_changes__v1",
        [
            "CREATE INDEX ix_changes ON record_changes "
            "(generation, tenancy_ocid, dataset, changed_at)"
        ],
    ),
    "watermarks": (
        """CREATE TABLE watermarks (
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  dataset TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  complete_through TEXT NOT NULL,
  run_id TEXT,
  query_version TEXT,
  lease_token TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (generation, tenancy_ocid, dataset, region)
) STRICT""",
        "INSERT INTO watermarks (generation, tenancy_ocid, dataset, region, complete_through, "
        "run_id, updated_at) SELECT :gen, tenancy_ocid, dataset, region, value, run_id, "
        "updated_at FROM watermarks__v1",
        [],
    ),
    "scan_run_items": (
        """CREATE TABLE scan_run_items (
  run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  dataset TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  complete INTEGER NOT NULL DEFAULT 1,
  record_count INTEGER NOT NULL DEFAULT 0,
  added INTEGER NOT NULL DEFAULT 0,
  modified INTEGER NOT NULL DEFAULT 0,
  removed INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  started_at TEXT, finished_at TEXT,
  PRIMARY KEY (run_id, tenancy_ocid, dataset, scope_key)
) STRICT""",
        "INSERT INTO scan_run_items (run_id, generation, tenancy_ocid, dataset, scope_key, region, "
        "status, complete, record_count, added, modified, removed, error, started_at, "
        "finished_at) SELECT run_id, :gen, tenancy_ocid, dataset, "
        "CASE region WHEN '' THEN '{}' ELSE json_object('region', region) END, region, status, "
        "complete, record_count, added, modified, removed, error, started_at, finished_at "
        "FROM scan_run_items__v1",
        [],
    ),
}


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]


def _drop_indexes(conn: sqlite3.Connection, table: str) -> None:
    """Indexes follow a renamed table; drop them so the rebuilt table can reuse the names."""
    for idx in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
        (table,),
    ).fetchall():
        conn.execute(f"DROP INDEX {idx['name']}")


def _is_v1_dataset_table(conn: sqlite3.Connection, table: str) -> bool:
    cols = set(_table_columns(conn, table))
    return {"tenancy_ocid", "record_key", "content_hash", "first_seen_run"} <= cols and (
        "generation" not in cols
    )


def _legacy_finding_identity(
    rule_id: str, tenancy: str, parent: str | None
) -> tuple[str, dict[str, str], str] | None:
    """Map a v1 OSC-ACCESS-001 coverage rule to (rule, identity, scope); None = ambiguous."""
    base, _, suffix = rule_id.partition(":")
    if base != "OSC-ACCESS-001" or not suffix:
        return None
    scope = SCOPE_PARENT_POLICIES if tenancy == parent else SCOPE_CHILD_ACCESS
    if suffix == "check":
        identity = {"rule": base, "subject": "policy_read", "stage": "policy_read"}
    elif suffix == "verify":
        identity = {"rule": base, "subject": "smoke_test", "stage": "verify"}
    else:
        identity = {"rule": base, "subject": suffix, "stage": "missing_grant"}
    return base, identity, scope


def _migrate_findings(conn: sqlite3.Connection, generation: int, parent: str | None) -> None:
    for stmt in _V2_FINDINGS:
        conn.execute(stmt)
    now = iso(utcnow())
    for row in conn.execute("SELECT * FROM findings").fetchall():
        legacy = json.loads(row["data"])
        mapped = (
            _legacy_finding_identity(row["rule_id"], row["tenancy_ocid"], parent)
            if row["source"] == "coverage"
            else None
        )
        if mapped is None:
            conn.execute(
                "INSERT INTO findings_quarantine (legacy_key, reason, data, quarantined_at) "
                "VALUES (?,?,?,?)",
                (row["dedup_key"], "no unambiguous v2 identity; re-evaluate", row["data"], now),
            )
            continue
        rule, identity, scope = mapped
        resolved_at = row["last_seen"] if row["status"] == "resolved" else None
        finding = Finding.model_validate(
            {
                **legacy,
                "rule_id": rule,
                "identity": identity,
                "generation": generation,
                "scope_key": scope,
                "resolved_at": resolved_at,
            }
        )
        write_finding(conn, finding, table="findings_v2")
    conn.execute("DROP TABLE findings")
    conn.execute("ALTER TABLE findings_v2 RENAME TO findings")
    for stmt in _V2_FINDINGS_INDEXES:
        conn.execute(stmt)


def _migrate_dataset_table(conn: sqlite3.Connection, table: str, generation: int) -> None:
    """Rebuild a v1 dataset table with generation + scope_key and the new primary key."""
    old_cols = _table_columns(conn, table)
    extra = [
        c
        for c in old_cols
        if c
        not in {
            "tenancy_ocid",
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
            "data",
        }
    ]
    _drop_indexes(conn, table)
    conn.execute(f"ALTER TABLE {table} RENAME TO {table}__v1")
    extra_ddl = "".join(f"  {c} TEXT,\n" for c in extra)
    conn.execute(
        f"""CREATE TABLE {table} (
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  record_key TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  compartment_ocid TEXT,
  resource_ocid TEXT,
  content_hash TEXT NOT NULL,
  first_seen_run TEXT NOT NULL,
  last_seen_run TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
{extra_ddl}  data TEXT NOT NULL CHECK (json_valid(data)),
  PRIMARY KEY (generation, tenancy_ocid, scope_key, record_key)
) STRICT"""
    )
    conn.execute(
        f"INSERT INTO {table} (generation, scope_key, {', '.join(old_cols)}) "  # noqa: S608
        f"SELECT ?, CASE region WHEN '' THEN '{{}}' ELSE json_object('region', region) END, "
        f"{', '.join(old_cols)} FROM {table}__v1",
        (generation,),
    )
    conn.execute(f"DROP TABLE {table}__v1")


def _v2(conn: sqlite3.Connection) -> None:
    now = iso(utcnow())
    parent_row = conn.execute(
        "SELECT value FROM settings_kv WHERE key='parent_tenancy_ocid'"
    ).fetchone()
    parent = parent_row["value"] if parent_row else None
    generation = 1
    for stmt in _V2_NEW_TABLES:
        conn.execute(stmt)
    conn.execute(
        "INSERT INTO organization_state (id, generation, parent_tenancy_ocid, state, updated_at) "
        "VALUES (1, ?, ?, 'active', ?)",
        (generation, parent, now),
    )
    conn.execute("ALTER TABLE scan_runs ADD COLUMN generation INTEGER NOT NULL DEFAULT 1")
    for table, (ddl, copy, indexes) in _V2_REBUILDS.items():
        _drop_indexes(conn, table)
        conn.execute(f"ALTER TABLE {table} RENAME TO {table}__v1")
        conn.execute(ddl)
        conn.execute(copy, {"gen": generation})
        conn.execute(f"DROP TABLE {table}__v1")
        for stmt in indexes:
            conn.execute(stmt)
    _migrate_findings(conn, generation, parent)

    registered = {spec.table for spec in DATASETS.values()}
    tables = [
        r["name"]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    for table in tables:
        if not _is_v1_dataset_table(conn, table):
            continue
        if table in registered:
            _migrate_dataset_table(conn, table, generation)
            continue
        # A dataset dropped from the registry: keep its rows rather than lose data.
        if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:  # noqa: S608
            conn.execute(f"ALTER TABLE {table} RENAME TO legacy_{table}")
        else:
            conn.execute(f"DROP TABLE {table}")


# --- migration 3: switch journal, capability status, audit ingestion ledger ----------------------
_V3_TABLES = [
    """CREATE TABLE switch_journal (
  id INTEGER PRIMARY KEY,
  old_generation INTEGER NOT NULL,
  new_generation INTEGER NOT NULL,
  old_parent TEXT,
  new_parent TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('prepared','committed','active','cleaned','aborted')),
  holder TEXT NOT NULL,
  errors TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(errors)),
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT""",
    """CREATE TABLE capabilities (
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  capability TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('untested','supported','unsupported','error')),
  detail TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL,
  PRIMARY KEY (generation, tenancy_ocid, capability, scope_key)
) STRICT""",
    """CREATE TABLE ingestion_ledger (
  id INTEGER PRIMARY KEY,
  generation INTEGER NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  region TEXT NOT NULL,
  cursor TEXT NOT NULL CHECK (cursor IN ('forward','backfill','reconcile')),
  interval_start TEXT NOT NULL,
  interval_end TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('complete','gap')),
  events INTEGER NOT NULL DEFAULT 0,
  inserted INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL,
  query_version TEXT NOT NULL,
  run_id TEXT NOT NULL,
  detail TEXT,
  recorded_at TEXT NOT NULL
) STRICT""",
    "CREATE INDEX ix_ledger ON ingestion_ledger "
    "(generation, tenancy_ocid, region, cursor, interval_start)",
]


def _v3(conn: sqlite3.Connection) -> None:
    for stmt in _V3_TABLES:
        conn.execute(stmt)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(2, "generations, leases, scoped snapshots, finding identity v2", _v2),
    Migration(3, "switch journal, capability status, audit ingestion ledger", _v3),
)
assert MIGRATIONS[-1].version == SCHEMA_VERSION, "SCHEMA_VERSION must match the last migration"


# --- runner ---------------------------------------------------------------------------------------
@dataclass
class MigrationResult:
    from_version: int
    to_version: int
    created: bool
    backup: Path | None


def current_version(db: SqliteDatabase) -> int | None:
    with db.read() as conn:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_versions'"
        ).fetchone()
        if not exists:
            return None
        row = conn.execute(
            "SELECT version FROM schema_versions WHERE component=?", (COMPONENT,)
        ).fetchone()
        return int(row["version"]) if row else None


def migrate(db: SqliteDatabase, backup_dir: Path) -> MigrationResult:
    version = current_version(db)
    created = version is None
    if created:
        with db.write(durable=True) as conn:
            for stmt in _statements(BASELINE_V1):
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_versions(component, version, applied_at) VALUES (?, 1, ?)",
                (COMPONENT, iso(utcnow())),
            )
        version = 1
    assert version is not None
    if version > SCHEMA_VERSION:
        raise SchemaError(
            f"osc.db is at schema v{version}, newer than this OSC (v{SCHEMA_VERSION}); "
            "upgrade OSC or restore a matching backup"
        )
    pending = [m for m in MIGRATIONS if m.version > version]
    backup: Path | None = None
    if pending and not created:
        stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S")
        backup = backup_dir / f"osc-pre-v{pending[-1].version}-{stamp}.db"
        db.backup_to(backup)
    for m in pending:
        with db.write(durable=True) as conn:
            m.apply(conn)
            conn.execute(
                "UPDATE schema_versions SET version=?, applied_at=? WHERE component=?",
                (m.version, iso(utcnow()), COMPONENT),
            )
    ensure_dataset_tables(db)
    return MigrationResult(version, SCHEMA_VERSION, created, backup)


def ensure_dataset_tables(db: SqliteDatabase) -> None:
    """Create tables for newly registered datasets; refuse silent shape changes."""
    with db.write() as conn:
        for spec in DATASETS.values():
            cols = _table_columns(conn, spec.table)
            if not cols:
                for stmt in dataset_table_ddl(spec):
                    conn.execute(stmt)
                continue
            if cols != dataset_table_columns(spec):
                raise SchemaError(
                    f"table {spec.table} doesn't match the dataset registry; "
                    "changing a dataset's columns needs a migration"
                )


def _statements(script: str) -> list[str]:
    """Split a DDL script without triggers into single statements."""
    return [s.strip() for s in script.split(";") if s.strip()]
