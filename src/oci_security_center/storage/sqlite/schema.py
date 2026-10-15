"""DDL for ``osc.db`` and the monthly audit databases (docs/storage.md §3).

``BASELINE_V1`` is the frozen v0.1 app-state schema: a new database starts from it and then runs
every migration in ``migrations.py``, exactly like an upgraded one. Never edit the baseline; add a
migration. Dataset tables are generated from the registry in their *current* shape; an existing
table whose columns differ from the registry needs a migration (``ensure_dataset_tables``).
"""

from __future__ import annotations

from oci_security_center.storage.datasets import DatasetSpec

# Latest schema version; equals the highest migration in migrations.py.
SCHEMA_VERSION = 3

BASELINE_V1 = """
CREATE TABLE IF NOT EXISTS schema_versions (
  component TEXT PRIMARY KEY, version INTEGER NOT NULL, applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS settings_kv (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS tenancies (
  ocid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  alias TEXT NOT NULL,
  org_role TEXT NOT NULL,
  home_region TEXT,
  subscribed_regions TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(subscribed_regions)),
  organization_id TEXT,
  parent_tenancy_ocid TEXT,
  onboarding_status TEXT NOT NULL,
  status_detail TEXT,
  lifecycle_state TEXT,
  governance_status TEXT,
  last_verified_at TEXT,
  last_scanned_at TEXT,
  updated_at TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenancies_alias ON tenancies (alias);

CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  tenancy_ocid TEXT NOT NULL,
  method TEXT NOT NULL,
  purpose TEXT NOT NULL,
  region TEXT,
  domain_url TEXT, client_id TEXT,
  cli_config_path TEXT, cli_profile TEXT,
  user_ocid TEXT, fingerprint TEXT,
  secret_ref TEXT,
  created_by TEXT, created_at TEXT NOT NULL,
  last_tested_at TEXT, last_test_result TEXT,
  UNIQUE (tenancy_ocid, purpose)
) STRICT;

CREATE TABLE IF NOT EXISTS local_secrets (
  id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  data_enc BLOB NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS scan_runs (
  run_id TEXT PRIMARY KEY,
  trigger TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(summary))
) STRICT;

CREATE TABLE IF NOT EXISTS scan_run_items (
  run_id TEXT NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
  tenancy_ocid TEXT NOT NULL,
  dataset TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  complete INTEGER NOT NULL DEFAULT 1,
  record_count INTEGER NOT NULL DEFAULT 0,
  added INTEGER NOT NULL DEFAULT 0,
  modified INTEGER NOT NULL DEFAULT 0,
  removed INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  started_at TEXT, finished_at TEXT,
  PRIMARY KEY (run_id, tenancy_ocid, dataset, region)
) STRICT;

CREATE TABLE IF NOT EXISTS requirement_checks (
  requirement_id TEXT PRIMARY KEY,
  tenancy_ocid TEXT NOT NULL,
  target_tenancy_ocid TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  matched_policy_ocid TEXT,
  matched_statement TEXT,
  checked_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS control_plane_events (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  result TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
) STRICT;
CREATE INDEX IF NOT EXISTS ix_cpe_at ON control_plane_events (at);

CREATE TABLE IF NOT EXISTS watermarks (
  tenancy_ocid TEXT NOT NULL,
  dataset TEXT NOT NULL,
  region TEXT NOT NULL DEFAULT '',
  value TEXT NOT NULL,
  run_id TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenancy_ocid, dataset, region)
) STRICT;

CREATE TABLE IF NOT EXISTS record_changes (
  id INTEGER PRIMARY KEY,
  dataset TEXT NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  record_key TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('added','modified','removed')),
  old_hash TEXT, new_hash TEXT,
  run_id TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  data TEXT CHECK (data IS NULL OR json_valid(data))
) STRICT;
CREATE INDEX IF NOT EXISTS ix_changes ON record_changes (tenancy_ocid, dataset, changed_at);

CREATE TABLE IF NOT EXISTS findings (
  dedup_key TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  tenancy_ocid TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  resource_ocid TEXT,
  region TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  data TEXT NOT NULL CHECK (json_valid(data))
) STRICT;
CREATE INDEX IF NOT EXISTS ix_findings_sev ON findings (severity, status, last_seen);
CREATE INDEX IF NOT EXISTS ix_findings_tenancy ON findings (tenancy_ocid, status);
"""


def dataset_table_ddl(spec: DatasetSpec) -> list[str]:
    """Current dataset table shape: one row per (generation, tenancy, scope, record)."""
    extra = "".join(f"  {col} TEXT,\n" for col in spec.columns)
    t = spec.table
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS {t} (
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
{extra}  data TEXT NOT NULL CHECK (json_valid(data)),
  PRIMARY KEY (generation, tenancy_ocid, scope_key, record_key)
) STRICT""",
        f"CREATE INDEX IF NOT EXISTS ix_{t}_deleted ON {t} (is_deleted, deleted_at)",
    ]
    for i, cols in enumerate(spec.indexes):
        stmts.append(f"CREATE INDEX IF NOT EXISTS ix_{t}_{i} ON {t} ({', '.join(cols)})")
    return stmts


def dataset_table_columns(spec: DatasetSpec) -> list[str]:
    base = [
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
    ]
    return [*base, *spec.columns, "data"]


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY,
  event_time TEXT NOT NULL,
  region TEXT NOT NULL,
  compartment_ocid TEXT,
  event_type TEXT NOT NULL,
  source TEXT,
  principal_id TEXT,
  principal_name TEXT,
  auth_type TEXT,
  ip_address TEXT,
  user_agent TEXT,
  action TEXT,
  response_status INTEGER,
  resource_id TEXT,
  run_id TEXT NOT NULL,
  data TEXT NOT NULL CHECK (json_valid(data))
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ae_time ON audit_events (event_time);
CREATE INDEX IF NOT EXISTS ix_ae_principal ON audit_events (principal_id, event_time);
CREATE INDEX IF NOT EXISTS ix_ae_type ON audit_events (event_type, event_time);
"""
