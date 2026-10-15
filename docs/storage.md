# Data Storage — Design

Status: **Design v0.3** (2026-10-08) · Owner: Kiran Thakkar
Related: `AGENTS.md` §3–§5, [control plane](control-plane.md),
[audit recovery](delta-fetching.md), [architecture and implementation gates](architecture.md).
Schemas below are required target schemas; existing v0.1 databases need explicit migrations.

### Decisions recorded (2026-10-07)
| # | Decision |
|---|----------|
| S1 | **Phase 1 = SQLite only**, on the OSC server's local disk. No file/folder store and no Object Storage for now. |
| S2 | **Default retention = 90 days** (configurable per dataset). |
| S3 | **Future backends**, all behind the same interface: OCI Object Storage, MySQL, Autonomous Database, and a **DB MCP server used as a write path** (it saves OSC data into its storage). |
| S4 | Storage must stay **pluggable** so these can be added without touching collectors or analyzers. |

---

## 1. What we store

| Class | Examples | Volume | Changes |
|---|---|---|---|
| **App state** | connections, secret refs, roles, sessions, onboarding status, policy checks, scan runs | tiny | constant, concurrent (web UI + scanner) |
| **Inventory snapshots** | compartments, policies, groups, dynamic groups, Cloud Guard config/targets/recipes, security zones/recipes, region subscriptions | small–medium | slowly |
| **Stateful OCI findings** | Cloud Guard problems, Advisor recommendations | medium | status changes |
| **Event streams** | Audit events | **large** (can be millions/day across an Organization) | append-only |
| **Derived** | OSC `Finding`s, rule hits, anomaly hits, baselines | medium | every scan |
| **Delta state** | per-dataset watermarks, content hashes | tiny | every scan |

All of it is **Confidential** (IAM structure, usernames, IPs, user agents).

---

## 2. SQLite layout

Audit events are much larger than everything else, and SQLite allows one writer per database file. So
the data is split across a few files instead of one big database. This also keeps your original
"each tenancy and dataset separate" idea, using database files and tables instead of folders.

```
<OSC_DATA_ROOT>/                         # default ~/.osc; set /var/lib/osc explicitly on servers; dir 0700
├── osc.db                               # app state + inventory + OCI findings + OSC findings + watermarks
├── backups/                             # pre-migration backups (osc-pre-v<N>-<time>.db, 0600)
└── audit/
    └── g<generation>/                   # one folder per organization generation (fencing)
        └── <tenancy_ocid>/
            ├── 2026-08.db               # one file per tenancy per month
            ├── 2026-09.db
            └── 2026-10.db
```

Audit files live under the organization generation that wrote them (decision 2026-10-09). A worker
that started before an organization switch can only reach the old generation's folder, which the
switch removes; checkpoints in `osc.db` are fenced inside their transaction. v0.1 folders
(`audit/<tenancy>/`) are moved under `g1/` on first start.

| File | Why it's separate |
|---|---|
| `osc.db` | Everything the UI queries across tenancies lives here, so dashboards are plain SQL with no cross-file joins |
| `audit/g<N>/<tenancy>/<YYYY-MM>.db` | (1) Audit ingestion for different tenancies runs **in parallel** without fighting over SQLite's single write lock; (2) **retention is cheap**: months fully older than 90 days are removed by deleting the file, with no huge `DELETE` + `VACUUM`; (3) a noisy tenancy can't bloat the main DB |

Cross-tenancy audit analytics, such as "same principal active in several children", run per tenancy file and
write bounded candidate indexes into `osc.db`; correlation rules then fetch exact timestamps from
indexed event files. Daily summaries are for trends only (collection §7).

---

## 3. Schema (Phase 1)

"Every dataset has its own format" → **every dataset has its own table**, with typed key columns for what
we filter and join on, plus a `data` JSON column holding the full normalized pydantic model. The schema
version is recorded per table.

### 3.1 App state (`osc.db`)
`tenancies`, `connections`, `sessions`, `role_mappings`, `scan_runs`, `scan_run_items`
(tenancy × dataset × region status, counts, errors, `complete` flag), `policy_requirements`,
`requirement_checks`, `control_plane_events`, `schema_versions`. Schema v2 adds
`organization_state` (generation, maintenance barrier), `scope_leases`, `scope_manifests` and
`findings_quarantine` (legacy findings without an unambiguous v2 identity). Schema v3 adds
`switch_journal`, `capabilities` (status per tenancy/dataset/scope) and `ingestion_ledger` (every
fetched audit interval; it is also the audit coverage record). Backup manifests are files inside each
backup set (§6.1). Still planned: minute-level audit candidate indexes (Tier 5).

### 3.2 Dataset tables (`osc.db`) — one per dataset, same shape

Tables (one per dataset in `storage/datasets.py`; what each holds and its tier: `docs/collection.md`):
`identity_compartments`, `identity_policies`, `identity_domains`, `identity_domains_users`,
`identity_domains_groups`, `identity_domains_dynamic_groups`, `identity_region_subscriptions`,
`cloud_guard_configuration`, `cloud_guard_targets`, `cloud_guard_problems`, `security_zones_zones`,
`security_zones_recipes`, `optimizer_enrollment`, `optimizer_recommendations`. Tier 2 datasets are
added to the registry when their collectors are built.

```sql
CREATE TABLE cloud_guard_problems (
  tenancy_ocid      TEXT NOT NULL,
  record_key        TEXT NOT NULL,          -- stable ID (usually the OCI OCID)
  generation        INTEGER NOT NULL,       -- organization generation (fencing token)
  scope_key         TEXT NOT NULL,          -- canonical region/domain/compartment scope
  region            TEXT,
  compartment_ocid  TEXT,
  resource_ocid     TEXT,
  content_hash      TEXT NOT NULL,          -- sha256 of canonical JSON; drives delta detection
  first_seen_run    TEXT NOT NULL,
  last_seen_run     TEXT NOT NULL,
  collected_at      TEXT NOT NULL,          -- ISO-8601 UTC
  is_deleted        INTEGER NOT NULL DEFAULT 0,   -- gone from OCI since last scan (soft delete)
  -- dataset-specific typed columns for common filters, e.g.:
  risk_level        TEXT,
  lifecycle_state   TEXT,
  detector_id       TEXT,
  data              TEXT NOT NULL CHECK (json_valid(data)),
  PRIMARY KEY (generation, tenancy_ocid, scope_key, record_key)
) STRICT;
CREATE INDEX ix_cgp_risk ON cloud_guard_problems (risk_level, lifecycle_state);
```

### 3.3 Change history (`osc.db`)
One generic table keeps what changed between scans. The delta design and "what changed" views use it:

```sql
CREATE TABLE record_changes (
  id INTEGER PRIMARY KEY,
  dataset TEXT NOT NULL, tenancy_ocid TEXT NOT NULL, record_key TEXT NOT NULL,
  generation TEXT NOT NULL, scope_key TEXT NOT NULL, schema_version INTEGER NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('added','modified','removed')),
  old_hash TEXT, new_hash TEXT, run_id TEXT NOT NULL, changed_at TEXT NOT NULL,
  data TEXT CHECK (data IS NULL OR json_valid(data))     -- new version (or old one, for 'removed')
) STRICT;
CREATE INDEX ix_changes ON record_changes (tenancy_ocid, dataset, changed_at);
```

### 3.4 Findings and watermarks (`osc.db`)
- `findings` — OSC's normalized `Finding` (AGENTS.md §5) with typed columns for every filter the UI uses
  (`source`, `severity`, `status`, `tenancy_ocid`, `rule_id`, `first_seen`, `last_seen`) + `data` JSON.
  Use a versioned identity, not the legacy `(source, tenancy, resource, rule)` key. Required columns:
  `identity_version`, `source_record_id`, `scope_key`, `occurrence_key`, `generation`, `resolved_at`.
  The canonical identity is hashed from structured JSON (no ambiguous delimiter concatenation).
  Use a stable native-source namespace for Cloud Guard and Security Zone problems; presentation
  classification may change without changing that namespace or problem identity.

  | Source | Identity components in addition to generation, source and tenancy |
  |---|---|
  | Cloud Guard / Security Zone | Stable Cloud Guard namespace and original problem OCID; classification changes update the existing source problem rather than creating duplicates. |
  | Advisor | Recommendation OCID. |
  | Policy | Policy OCID, canonical statement identity, rule ID; repeated identical statements in one policy share a finding. |
  | Coverage | Rule ID, dataset/API or requirement ID, region, domain/compartment scope, failure stage. |
  | Audit anomaly | Rule ID, canonical subject (principal OCID or IP), resource where relevant, and occurrence identity. Single-event rules use event ID; window rules use deterministic UTC window boundaries. |

  Maintain `first_seen` on upsert, separate `last_seen` from `resolved_at`, and retain occurrence evidence
  references. Reopening a stateful finding retains its identity; a new anomaly episode gets a new
  occurrence. Resolve absent stateful findings only after a complete matching scope/rule evaluation;
  do not resolve findings from untouched regions, failed sources or disabled tiers. Suppression is an
  explicit local decision with actor, reason and expiry. Event anomalies retain their detection history;
  cessation of events is not evidence that an incident was remediated.

  Migration must recompute identities from retained source/evidence fields. Quarantine ambiguous
  legacy findings for re-evaluation; do not invent occurrences already lost through key collisions.
- `watermarks` — `(generation, tenancy_ocid, dataset, region)` → `complete_through`, `updated_at`,
  `run_id`, query version and lease token. Commit with the ingestion ledger only after event durability
  ([audit recovery](delta-fetching.md)).

### 3.5 Audit event files (`audit/g<generation>/<tenancy>/<YYYY-MM>.db`)

```sql
CREATE TABLE audit_events (
  event_id        TEXT PRIMARY KEY,        -- OCI eventId: makes re-ingestion idempotent
  event_time      TEXT NOT NULL,
  region          TEXT NOT NULL,
  compartment_ocid TEXT, event_type TEXT NOT NULL, source TEXT,
  principal_id    TEXT, principal_name TEXT, auth_type TEXT,
  ip_address      TEXT, user_agent TEXT,
  action          TEXT, response_status INTEGER, resource_id TEXT,
  data            TEXT NOT NULL CHECK (json_valid(data))
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_ae_time ON audit_events (event_time);
CREATE INDEX ix_ae_principal ON audit_events (principal_id, event_time);
CREATE INDEX ix_ae_type ON audit_events (event_type, event_time);
```

`INSERT OR IGNORE` on `event_id` means overlapping fetch windows (which the delta design will use for safety)
never create duplicates.

---

### 3.6 Migrations

`osc.db` changes only through numbered migrations (`storage/sqlite/migrations.py`). A new database
is created from the frozen v1 baseline and then runs every migration, exactly like an upgraded one.
Before migrating an existing database, OSC writes an online backup to
`<OSC_DATA_ROOT>/backups/osc-pre-v<N>-<time>.db`; to roll back, stop OSC and restore that file with
the matching older OSC. Each migration is one durable transaction. A database newer than the running
OSC is refused. Tables for newly registered datasets are created automatically, but an existing
dataset table whose columns differ from the registry stops startup until a migration handles it.
Migration v2 recomputes finding identities from retained fields and quarantines legacy rows it
cannot map unambiguously; it never invents occurrences.

## 4. SQLite operating rules

- **Pragmas on every connection:** `journal_mode=WAL`, `foreign_keys=ON`,
  `busy_timeout=5000`, `auto_vacuum=INCREMENTAL` (set at creation). `synchronous=FULL` is required for
  audit batches, checkpoints and organization switching; NORMAL may be used for replayable inventory.
  Implemented as `SqliteDatabase.write(durable=True)`: used for audit batches, watermarks,
  migrations and organization-state changes.
- **Single writer per file:** serialize writes per database file with a per-path in-process lock
  plus SQLite's own locking across processes. The audit coordinator writes each batch durably and
  only then commits the interval/checkpoint (delta-fetching §2); a dedicated writer queue remains an
  optimization if write latency requires it. Readers (UI) use separate read-only connections
  (`mode=ro` URI). WAL lets readers run while the writer is writing.
- **Batching:** `executemany` in transactions of about 1–5k rows. A complete declared scope is applied
  in **one transaction**, so the UI never sees a half-updated dataset.
- **A failed or partial collection never changes `current` rows.** It marks the `scan_run_items` row
  `complete=0`, which becomes a coverage finding (AGENTS.md §2.6).
- **Access layer (v0.1):** stdlib `sqlite3` behind the `AppStateStore`/`DataStore` interfaces (one fewer
  dependency). SQLAlchemy 2.x Core + Alembic are proposed with the MySQL/ADB backends, so the same schema can move to
  MySQL/ADB later. JSON stays in a `TEXT` column with `json_valid` in SQLite and maps to the native JSON type
  on other backends.
- Python's bundled `sqlite3` needs JSON functions (SQLite ≥ 3.38 has them built in) and `STRICT` tables
  (≥ 3.37). Check `sqlite3.sqlite_version` at startup and refuse to start below the minimum.

### 4.1 Scoped snapshots and completeness

`CollectionScope` contains generation, tenancy, dataset, region (or a tenancy-global marker), domain
and compartment dimensions as required by the dataset registry. `scope_key` is canonical structured
JSON. The registry declares which dimensions matter; callers cannot arbitrarily narrow a snapshot.
The existing `scope_region` parameter is the compatibility precursor, not the full contract.

Collectors stage records and return a manifest containing requested scope, query/schema version,
expected/visited compartments and domains, page completion, errors, run ID and lease token. Only a
complete manifest authorizes replacement. A successful empty scope removes rows in that scope only.
Reject duplicate conflicting record keys and any envelope outside the declared scope. Removal applies
to that scope, never all tenancy rows by default. Last-successful collection time remains visible.

For datasets walked across compartments/domains, use a tenancy-wide snapshot only when every required
child scope completes; otherwise retain that snapshot unchanged. Alternatively, a registry-declared
per-domain/region dataset may commit successful independent scopes while reporting failures separately.
Do not infer deletion of a domain or compartment from its failed enumeration. Older delayed runs and
stale lease/generation tokens are rejected. Snapshot rows, changes and successful scan status commit
in one transaction; partial/error status is recorded separately without replacing current rows.

Staging is bounded and may use temporary local tables for large snapshots. Publication is one atomic
transaction; batching must not expose intermediate current-state updates. Schedule retention,
backups and organization switching with the same lease/maintenance coordination.

---

## 5. Retention (S2: 90 days default)

| Data | Default | Mechanism |
|---|---|---|
| Audit events | 90 days | Delete month files fully older than the cutoff; `DELETE … WHERE event_time < cutoff` in the boundary month; `PRAGMA incremental_vacuum` |
| `record_changes` | 90 days | Daily `retention` job in `osc scheduler`; `osc db purge` on demand |
| Soft-deleted dataset rows (`is_deleted=1`) | 90 days after removal | Daily `retention` job in `osc scheduler`; `osc db purge` on demand |
| `findings` with status `resolved` | 90 days after `resolved_at` | Daily `retention` job in `osc scheduler`; `osc db purge` on demand |
| Current inventory / open findings | kept while they exist | — |
| `scan_runs`, `control_plane_events` | scan runs: 90 days; control-plane events: 365 days | Daily `retention` job in `osc scheduler`; `osc db purge` on demand |

Configured per dataset: `OSC_RETENTION_DAYS=90`, with overrides like `OSC_RETENTION_OVERRIDES__AUDIT_EVENTS=30`.
OCI keeps Audit for 365 days by default, so OSC's 90-day copy is an **analysis window**, not the record of
truth. A gap can be refilled from OCI within 365 days.

---

## 6. Security

- **Encryption at rest:** SQLite has no native encryption. Baseline: the OSC server's disk/volume is
  encrypted (OCI Block Volume or boot volume with a **Vault customer-managed key** in `oci` mode;
  FileVault/BitLocker/LUKS on a workstation). Operator verification is required; automated detection/warnings are planned and are not implemented.
  The deployment checklist must record encryption and key recovery without logging key material.
  *(Optional later: SQLCipher, decision S5.)*
- **Permissions:** data dir `0700`, DB files `0600`, owned by the OSC service account.
- **No secrets in data tables:** collectors keep an allow-listed set of fields per dataset; secrets live only
  as Vault references or Fernet-encrypted local secret records. The Fernet key is held separately;
  this is symmetric authenticated encryption, not a complete envelope-encryption key hierarchy.
- **Backups:** `osc db backup <dir>` / `osc db restore <backup>` implement §6.1
  (`storage/sqlite/backup.py`); `OSC_BACKUP_RETENTION_DAYS` (30) expires old sets.
- **Integrity:** `PRAGMA quick_check` runs at startup (a damaged `osc.db` is refused) and on every
  backup copy and restore input.

Retention acquires the exclusive maintenance lease and drains workers before purging. Audit batches
hold the main database writer transaction across monthly commits, so maintenance cannot begin
between their fence check and file write.

### 6.1 Full backup and restore contract

1. Acquire an exclusive maintenance lease that drains writers and pauses checkpoints, retention and
   organization switching. Wait for all commits to finish. Read-only dashboards may continue.
2. Create a private temporary backup directory; create destination files with 0600 before opening
   SQLite. Use `Connection.backup()` for osc.db and every retained audit file (including active months).
   Never copy only a live .db without its WAL through filesystem copy.
3. Record a manifest: backup ID/time, parent OCID and generation, schema/identity versions, complete
   relative file list, sizes/checksums, covered intervals/checkpoints, retention settings and encryption
   key identifier. Validate each backup database with quick_check; publish the completed directory
   atomically only after all files and manifest are durable. Incomplete directories are not restorable.
4. Protect backups like live data, encrypt any off-host transfer/storage, purge expired backup sets,
   and document restore-point frequency. Production automation targets nightly backups; the current
   CLI does not schedule them. Retain keys for every retained backup; do not store keys inside backups.
5. Restore offline into a separate private directory. Validate manifest completeness, checksums,
   database integrity, schema support, expected parent and ability to decrypt a synthetic verification
   value with the supplied key. Missing/wrong keys or audit files fail complete restore before switch.
6. Generate a new organization generation, invalidate all sessions/leases, apply current retention,
   and rebuild candidate indexes/derived summaries from restored events. Migrate schemas explicitly
   or refuse incompatible versions. Activate the directory only after validation succeeds.
   Restored finding IDs and serialized model generations are rebuilt together, retaining suppression,
   resolution and first/last-seen history. Serialized snapshot manifests use the restored generation.
7. Reconcile checkpoints against coverage intervals and restored files. A user-selected main-DB-only
   recovery is a partial restore: invalidate audit checkpoints and derived audit data, show coverage
   gaps, then replay the missing retained intervals. Unrecoverable source gaps stay visible.

Backup duration and temporary disk requirements must be measured in the volume POC. Report backup
failure and last successful restore drill; `quick_check` alone is not a recovery test. Organization
replacement removes active data but historical backups expire under their documented retention;
it does not promise secure erasure of backups, WAL remnants or underlying storage.

---

## 7. Storage interfaces (unchanged contract for future backends)

The current protocols in `storage/base.py` are implemented by v0.1. The following target API
requires a versioned adapter/migration; callers must not claim it is already available:

```python
class DataStore(Protocol):
    def apply_snapshot(
        self, scope: CollectionScope, records: Iterable[Envelope], manifest: CompleteManifest
    ) -> SnapshotResult: ...  # atomic publication, scope-only removal, lease/generation fence
    def read_current(self, scope: CollectionScope) -> Iterator[Envelope]: ...
    def append_events(
        self, scope: CollectionScope, events: Iterable[Envelope], run: RunId
    ) -> DurableBatchAck: ...  # acknowledgment after durable commit
    def commit_interval(
        self,
        scope: CollectionScope,
        interval: CompletedInterval,
        batches: Sequence[DurableBatchAck],
        lease: ScopeLease,
    ) -> Watermark: ...  # verify receipts; ledger + checkpoint + scan status atomically
    def get_watermark(self, scope: CollectionScope) -> Watermark | None: ...
    def purge(self, policy: RetentionPolicy) -> PurgeResult: ...


class Sink(Protocol):
    def publish(self, dataset: DatasetId, batch: Sequence[Envelope]) -> None: ...
```

AppStateStore additionally owns generation/maintenance leases and coordinated organization switch.
Loose `set_watermark` remains a low-level compatibility method; ingestion uses `commit_interval`.
Every state-changing storage operation validates generation and scope/maintenance lease as applicable.


Collectors and analyzers depend only on these protocols. `Envelope` = normalized model + `tenancy_ocid`,
`record_key`, `content_hash`, `collected_at`, `run_id`, `schema`, `scope_key`, `generation` — the same shape for every backend.

### 7.1 Future: DB MCP server as a write path (S3)
The MCP server is meant to **save OSC data into its storage**. To keep that safe and reliable:

- **Structured payloads, not SQL text.** OSC calls tools such as `upsert_records(dataset, schema_version,
  records[])` and `append_events(...)` with `Envelope` JSON. The MCP server owns the SQL and uses bind
  variables. OSC never builds SQL strings for another process to run (prevents injection).
- **Batched and idempotent.** Batches of N records; upsert key `(tenancy_ocid, dataset, record_key)` +
  `content_hash`; audit keyed by `event_id`. Retries are safe.
- **Least privilege.** The MCP server's DB account can only write OSC's schema. MCP auth uses a dedicated
  credential (from Vault), over TLS or a local transport only. Prefer a narrow, purpose-built tool set to a
  generic "run SQL" tool.
- **Source of truth.** While SQLite is the primary store, it owns **watermarks** and the MCP sink is a
  mirror (best-effort, with a retry queue in `osc.db`). If the MCP-backed DB later becomes primary, it must
  also implement `DataStore`, including watermarks.
- **Observability.** Every publish is recorded in `scan_run_items` (sent/acknowledged/failed counts).

---

## 8. Open decisions

| ID | Question | Proposal |
|---|---|---|
| S5 | SQLCipher for file-level encryption on top of disk encryption? | Defer; disk/volume encryption with a Vault CMK is the baseline |
| S6 | Audit file granularity: per tenancy per month | Yes; revisit if a single tenancy produces more than a few GB/month |
| S7 | Retention for `control_plane_events` | **Resolved:** 365 days; `OSC_CONTROL_PLANE_EVENT_RETENTION_DAYS`, already implemented |
| S8 | MCP tool contract (names, payload schema, auth) | Define when the MCP server design starts; must follow §7.1 |
| S9 | Order of future backends | Object Storage → ADB → MySQL → MCP sink (proposal) |

Implementation failure-path fixes and regression coverage: [review summaries](review-fixes.md).
