"""Schema migrations: v0.1 databases upgrade with a backup and without losing data."""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest

from oci_security_center.config import Settings
from oci_security_center.models import FindingSource, FindingStatus
from oci_security_center.storage.errors import SchemaError
from oci_security_center.storage.sqlite import open_stores
from oci_security_center.storage.sqlite.migrations import (
    SCOPE_CHILD_ACCESS,
    SCOPE_PARENT_POLICIES,
    current_version,
)
from oci_security_center.storage.sqlite.schema import BASELINE_V1, SCHEMA_VERSION

PARENT = "ocid1.tenancy.oc1..aaaafakeparent"
CHILD = "ocid1.tenancy.oc1..aaaafakechild1"


def _v1_dataset_table(table: str, extra: tuple[str, ...]) -> str:
    """Frozen copy of the v0.1 dataset table DDL."""
    cols = "".join(f"  {c} TEXT,\n" for c in extra)
    return f"""CREATE TABLE {table} (
  tenancy_ocid TEXT NOT NULL,
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
{cols}  data TEXT NOT NULL CHECK (json_valid(data)),
  PRIMARY KEY (tenancy_ocid, record_key)
) STRICT;
CREATE INDEX ix_{table}_deleted ON {table} (is_deleted, deleted_at);"""


def _legacy_finding(
    rule: str, tenancy: str, status: str = "open", source: str = "coverage"
) -> dict:
    return {
        "source": source,
        "tenancy_ocid": tenancy,
        "rule_id": rule,
        "severity": "HIGH",
        "title": "t",
        "description": "",
        "status": status,
        "first_seen": "2026-10-01T00:00:00+00:00",
        "last_seen": "2026-10-02T00:00:00+00:00",
        "cis_refs": [],
    }


def _make_v1_db(settings: Settings) -> None:
    settings.data_root.mkdir(parents=True, mode=0o700)
    conn = sqlite3.connect(settings.db_path)
    conn.executescript(BASELINE_V1)
    conn.executescript(
        _v1_dataset_table("identity_policies", ("name", "lifecycle_state"))
        + _v1_dataset_table("identity_groups", ("name", "domain"))
        + _v1_dataset_table("identity_dynamic_groups", ("name", "domain", "matching_rule"))
    )
    conn.execute("INSERT INTO schema_versions VALUES ('osc_db', 1, '2026-10-07T00:00:00+00:00')")
    conn.execute(
        "INSERT INTO settings_kv VALUES ('parent_tenancy_ocid', ?, '2026-10-07T00:00:00+00:00')",
        (PARENT,),
    )
    findings = [
        ("OSC-ACCESS-001:parent_access:x:scanner-read-all", PARENT, "open", "coverage"),
        ("OSC-ACCESS-001:check", PARENT, "resolved", "coverage"),
        ("OSC-ACCESS-001:verify", CHILD, "open", "coverage"),
        ("SOMETHING-ELSE", CHILD, "open", "policy"),
    ]
    for rule, tenancy, status, source in findings:
        data = _legacy_finding(rule, tenancy, status, source)
        conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"{source}|{tenancy}|-|{rule}",
                source,
                tenancy,
                rule,
                "HIGH",
                status,
                "t",
                None,
                None,
                data["first_seen"],
                data["last_seen"],
                json.dumps(data),
            ),
        )
    conn.execute(
        "INSERT INTO identity_policies VALUES (?, 'p1', '', NULL, NULL, 'h', 'r1', 'r1', "
        "'2026-10-07T00:00:00+00:00', 0, NULL, 'pol', 'ACTIVE', '{}')",
        (PARENT,),
    )
    conn.execute(
        "INSERT INTO identity_groups VALUES (?, 'g1', '', NULL, NULL, 'h', 'r1', 'r1', "
        "'2026-10-07T00:00:00+00:00', 0, NULL, 'grp', 'Default', '{}')",
        (PARENT,),
    )
    conn.execute(
        "INSERT INTO watermarks VALUES (?, 'audit.events', 'us-ashburn-1', '2026-10-06', 'r1', "
        "'2026-10-07T00:00:00+00:00')",
        (CHILD,),
    )
    conn.execute(
        "INSERT INTO record_changes (dataset, tenancy_ocid, record_key, change_type, new_hash, "
        "run_id, changed_at) VALUES ('identity.policies', ?, 'p1', 'added', 'h', 'r1', "
        "'2026-10-07T00:00:00+00:00')",
        (PARENT,),
    )
    conn.execute(
        "INSERT INTO scan_runs (run_id, trigger, started_at, status) "
        "VALUES ('r1', 'manual', '2026-10-07T00:00:00+00:00', 'ok')"
    )
    conn.execute(
        "INSERT INTO scan_run_items (run_id, tenancy_ocid, dataset, region, status) "
        "VALUES ('r1', ?, 'identity.policies', '', 'ok')",
        (PARENT,),
    )
    conn.commit()
    conn.close()
    legacy_audit = settings.audit_root / CHILD
    legacy_audit.mkdir(parents=True)
    (legacy_audit / "2026-10.db").write_bytes(b"")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_root=tmp_path / "osc")


def test_new_database_starts_at_latest(settings: Settings) -> None:
    stores = open_stores(settings)
    assert stores.migration.created
    assert stores.migration.backup is None
    assert current_version(stores.db) == SCHEMA_VERSION
    org = stores.state.organization()
    assert (org.generation, org.state, org.parent_tenancy_ocid) == (1, "active", None)
    assert not (settings.data_root / "backups").exists()


def test_v1_database_migrates_with_backup(settings: Settings) -> None:
    _make_v1_db(settings)
    stores = open_stores(settings)
    m = stores.migration
    assert (m.from_version, m.to_version, m.created) == (1, SCHEMA_VERSION, False)
    assert m.backup is not None
    assert stat.S_IMODE(m.backup.stat().st_mode) == 0o600
    with sqlite3.connect(m.backup) as backup:  # the backup is the untouched v1 database
        assert backup.execute("SELECT version FROM schema_versions").fetchone()[0] == 1

    assert stores.state.organization().parent_tenancy_ocid == PARENT
    findings = {f.identity["subject"]: f for f in stores.data.list_findings()}
    assert set(findings) == {"parent_access:x:scanner-read-all", "policy_read", "smoke_test"}
    grant = findings["parent_access:x:scanner-read-all"]
    assert (grant.rule_id, grant.identity["stage"], grant.scope_key) == (
        "OSC-ACCESS-001",
        "missing_grant",
        SCOPE_PARENT_POLICIES,
    )
    assert findings["smoke_test"].scope_key == SCOPE_CHILD_ACCESS
    check = findings["policy_read"]
    assert check.status is FindingStatus.RESOLVED
    assert check.resolved_at is not None
    assert all(f.source is FindingSource.COVERAGE for f in findings.values())

    with stores.db.read() as conn:
        # ambiguous legacy rows are quarantined, not guessed
        assert conn.execute("SELECT COUNT(*) FROM findings_quarantine").fetchone()[0] == 1
        row = conn.execute("SELECT generation, scope_key, name FROM identity_policies").fetchone()
        assert tuple(row) == (1, "{}", "pol")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "legacy_identity_groups" in tables  # unregistered dataset with rows: kept
        assert "identity_dynamic_groups" not in tables  # unregistered and empty: dropped
        wm = conn.execute("SELECT generation, complete_through FROM watermarks").fetchone()
        assert tuple(wm) == (1, "2026-10-06")
        item = conn.execute("SELECT generation, scope_key FROM scan_run_items").fetchone()
        assert tuple(item) == (1, "{}")
        change = conn.execute("SELECT generation, scope_key FROM record_changes").fetchone()
        assert tuple(change) == (1, "{}")
    assert (settings.audit_root / "g1" / CHILD / "2026-10.db").exists()
    assert not (settings.audit_root / CHILD).exists()

    again = open_stores(settings)  # already migrated: no second backup
    assert again.migration.backup is None
    assert again.migration.from_version == SCHEMA_VERSION


def test_newer_database_is_refused(settings: Settings) -> None:
    stores = open_stores(settings)
    with stores.db.write() as conn:
        conn.execute("UPDATE schema_versions SET version=99")
    with pytest.raises(SchemaError, match="newer than this OSC"):
        open_stores(settings)


def test_dataset_shape_drift_needs_a_migration(settings: Settings) -> None:
    stores = open_stores(settings)
    with stores.db.write() as conn:
        conn.execute("ALTER TABLE identity_policies ADD COLUMN surprise TEXT")
    with pytest.raises(SchemaError, match="needs a migration"):
        open_stores(settings)


def test_damaged_database_is_refused_at_startup(settings: Settings) -> None:
    open_stores(settings)
    raw = bytearray(settings.db_path.read_bytes())
    for offset in range(4096, min(len(raw), 4096 * 3)):  # corrupt the first table pages
        raw[offset] = 0xFF
    settings.db_path.write_bytes(bytes(raw))
    for suffix in ("-wal", "-shm"):
        Path(str(settings.db_path) + suffix).unlink(missing_ok=True)
    with pytest.raises((SchemaError, sqlite3.DatabaseError)):
        open_stores(settings)
