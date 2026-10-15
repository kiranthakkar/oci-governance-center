# OCI Security Center (OSC)

Read-only governance and observability tool for an **OCI Organization**: the parent tenancy and every child
tenancy. Design docs: [`AGENTS.md`](AGENTS.md), [`docs/control-plane.md`](docs/control-plane.md),
[`docs/storage.md`](docs/storage.md), [`docs/collection.md`](docs/collection.md),
[`docs/architecture.md`](docs/architecture.md), [`docs/delta-fetching.md`](docs/delta-fetching.md).

**Status (v0.1):** control plane is in place: parent connection (OIDC + token exchange, OCI CLI
profile, API key, instance/resource principal), Organization discovery, the Organization and Child
configuration screens with required policies and read-only status checks, Verify, SQLite storage
with 90-day data retention and 365-day control-plane audit retention. Pillars 2–4 (Cloud Guard / Security Zones / Advisor, policy review, audit
anomalies) are next. This is a POC implementation; the production gates in
[architecture §4](docs/architecture.md#4-review-closure-and-acceptance-criteria) remain outstanding.
They include policy-local alias matching, finding identity migration, collection completeness and
durable checkpoints, generation-fenced replacement, full backup/restore and SDK allow-list enforcement.
A passing smoke test does not certify Tier-1 collection or child identity-domain access.

> OSC never creates, updates or deletes anything in OCI. It **shows** the IAM statements it needs
> (copy / download / `oci iam policy create` command) and **checks** whether they are applied.

## Quick start (workstation mode)

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 1. Bootstrap with your OCI CLI profile as the scan identity
osc admin bootstrap --tenancy-ocid ocid1.tenancy.oc1..xxxx --scan-method cli_profile --profile DEFAULT
#    One organization per deployment: bootstrapping a different parent later replaces the
#    organization and deletes the previous one's local data (you are asked to confirm first).

# 2. See what to apply in the parent, then check it
osc policies parent --check

# 3. Pick a child, see its Endorse (parent) + Define/Admit (child) statements
osc org show
osc child select ocid1.tenancy.oc1..child
osc policies child ocid1.tenancy.oc1..child

# 4. After both IAM admins apply them
osc child verify ocid1.tenancy.oc1..child
osc child activate ocid1.tenancy.oc1..child

# 5. Collect (Tier 1, read-only) once, or run the scheduler as its own process
osc scan
osc scheduler            # identity 6 h, governance 1 h, audit 15 min, reconcile + retention daily

# Web UI (local sign-in is allowed from this machine in workstation mode)
osc web     # http://127.0.0.1:8000  — Coverage, Governance, Access, Compartments, Activity
```

## Target production deployment (`oci` mode)

After the production gates pass, run on OCI Compute with the **instance principal** as the scan identity and
OCI IAM sign-in for admins:

```bash
export OSC_DEPLOYMENT=oci
export OSC_SECRET_KEY=<Fernet key, injected from OCI Vault>
export OSC_PUBLIC_BASE_URL=https://osc.example.com
export OSC_DATA_ROOT=/var/lib/osc          # on an encrypted Block Volume

osc admin bootstrap --tenancy-ocid ocid1.tenancy.oc1..xxxx \
  --scan-method instance_principal \
  --admin-method oidc --domain-url https://idcs-xxxx.identity.oraclecloud.com \
  --client-id <app client id> --client-secret-ocid ocid1.vaultsecret.oc1..xxxx
osc web --host 0.0.0.0
```

In `oci` mode the CLI-profile method and local sign-in are disabled, `OSC_SECRET_KEY` is required,
`OSC_PUBLIC_BASE_URL` must be `https://`, and the web UI only accepts members of `OSC-Admins` /
`OSC-Viewers`. Put it behind TLS. The UI only answers to the host in `OSC_PUBLIC_BASE_URL` (plus
`OSC_TRUSTED_HOSTS`); add the load balancer's health-check host there if it uses a different one.
API-key scan connections in `oci` mode are unsupported by the design; the current signer needs
consistent enforcement. Container Instance resource-principal deployment needs a separate validated
matching rule and capability evidence. Identity-domain setup: [`docs/iam/parent-domain-setup.md`](docs/iam/parent-domain-setup.md).

## Configuration

All settings are environment variables prefixed `OSC_` (see `src/oci_security_center/config.py`):
`OSC_DEPLOYMENT`, `OSC_DATA_ROOT`, `OSC_RETENTION_DAYS` (90),
`OSC_RETENTION_OVERRIDES__AUDIT_EVENTS`, `OSC_CONTROL_PLANE_EVENT_RETENTION_DAYS` (365), `OSC_GROUP_ADMINS`, `OSC_GROUP_VIEWERS`,
`OSC_GROUP_SCANNERS`, `OSC_DYNAMIC_GROUP_SCANNER`, `OSC_IDENTITY_DOMAIN_NAME`, `OSC_PARENT_ALIAS`,
`OSC_PUBLIC_BASE_URL`, `OSC_TRUSTED_HOSTS` (extra Host names, JSON list),
`OSC_SESSION_IDLE_MINUTES` (30), `OSC_SESSION_MAX_HOURS` (12), `OSC_GROUPS_CLAIM`, `OSC_OIDC_SCOPES`,
`OSC_SECRET_KEY`, `OSC_MAX_WORKERS` (8).

Collection: `OSC_COLLECTION_TIER` (1; tiers 2–5 not built yet), `OSC_SCAN_LEASE_SECONDS` (900),
`OSC_SCHEDULE_AUDIT_MINUTES` (15), `OSC_SCHEDULE_GOVERNANCE_MINUTES` (60),
`OSC_SCHEDULE_IDENTITY_MINUTES` (360), `OSC_SCHEDULE_GUARDRAILS_MINUTES` (1440).
Audit ingestion (proposed defaults, tune in the POC): `OSC_AUDIT_SOURCE` (`logging_search` |
`audit_api`), `OSC_AUDIT_INGESTION_DELAY_MINUTES` (5), `OSC_AUDIT_OVERLAP_HOURS` (24),
`OSC_AUDIT_CHUNK_MINUTES` (60), `OSC_AUDIT_MIN_SPLIT_MINUTES` (1), `OSC_AUDIT_INITIAL_MINUTES` (60),
`OSC_AUDIT_FORWARD_CHUNKS_PER_RUN` (48), `OSC_AUDIT_BACKFILL_CHUNKS_PER_RUN` (24),
`OSC_AUDIT_RECONCILE_CHUNKS_PER_RUN` (24), `OSC_AUDIT_BACKFILL_DAYS` (= audit retention),
`OSC_AUDIT_SEARCH_RESULT_CAP` (unset until gate Q2 is known).
Operations: `OSC_SWITCH_DRAIN_SECONDS` (120), `OSC_BACKUP_RETENTION_DAYS` (30).

## Storage

SQLite only (Phase 1): `OSC_DATA_ROOT/osc.db` plus `audit/g<generation>/<tenancy_ocid>/<YYYY-MM>.db`. Schema
changes run as numbered migrations with a pre-migration backup. The directory is `0700` and
files are `0600`. Secrets are supported Vault references or Fernet-encrypted. Vault retrieval requires
a keyless scan identity; API-key-only scanning uses a local encrypted key. `osc db purge` applies retention.
`osc db backup <dir>` writes a complete, verified backup set (osc.db, audit files, manifest with
checksums); `osc db restore <backup>` restores it offline (stop `osc web` and `osc scheduler` first).
The encryption key is not in the backup — keep it separately. See
[storage §6.1](docs/storage.md#61-full-backup-and-restore-contract).

## Development

```bash
ruff format --check .
ruff check .
mypy src
pytest -m "not live"
```

`tests/unit/test_read_only.py` rejects known mutating names. It is a supplementary deny-list, not
complete SDK allow-list enforcement; the required boundary and bypass tests are in architecture §3.
Use synthetic fixtures; a recorded-response sanitizer is not yet implemented. Planned tier/backfill
settings in the collection design are not supported runtime settings until added to Settings.
