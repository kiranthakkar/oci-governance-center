# AGENTS.md — OCI Security Center

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) and humans working in this repository.
Keep this file current: when an architectural decision changes, update it in the same PR.

---

## 1. What we are building

**OCI Security Center** is a Python **governance and observability** tool that gives a team a single pane
of glass over an **Oracle Cloud Infrastructure (OCI) Organization** — the parent tenancy and every child
tenancy. It inventories what exists, shows observed access grants, checks that governance guardrails are in
place and makes activity observable. It is not a security scanner (see non-goals).

"Cloud" in this repo always means **Oracle Cloud Infrastructure**. Do not add AWS/Azure/GCP abstractions.

### Feature pillars

| # | Pillar | Summary |
|---|--------|---------|
| 1 | **Control plane** | Register/onboard tenancies (add a new tenant), store their metadata and auth method, verify access, generate the cross-tenancy policies the child admin must apply. |
| 2 | **Centralized governance** | Aggregate across all tenancies: **Cloud Guard problems**, **Security Zone violations**, and **Cloud Advisor (Optimizer) recommendations**. |
| 3 | **Policy review & scanning** | Pull every IAM policy in every compartment of every tenancy, parse statements, flag risky grants (CIS OCI Benchmark + our own rules). |
| 4 | **Audit log analytics** | Query Audit logs across all child tenancies and regions, normalize events, and detect anomalies. |

Data is collected in **tiers** (`docs/collection.md`): **1** inventory and oversight · **2** guardrail
coverage · **3** change over time · **4** policy analysis (pillar 3 rules) · **5** activity analytics
(pillar 4 anomaly rules). Each tier includes the lower ones; dashboards follow the tier collected.
Tiers describe data scope only. Tier 1 access views cover observed IAM statements and group membership;
identity-domain admin-role grants arrive at Tier 4. No tier claims a complete effective-permissions
evaluator. Dashboards show unsupported, partial and stale coverage explicitly. The required design and
current implementation gates are in `docs/architecture.md` §4.

### Non-goals (for now)
- Auto-remediation or **any** write action against any tenancy, parent or child. **OSC is strictly
  read-only.** It shows the IAM policies it needs; humans apply them.
- Multi-cloud support.
- Replacing Cloud Guard. We aggregate and correlate; Cloud Guard remains the detector of record.
- Security-scanner data: credential hygiene (MFA status, key/token age), expiring keys or certificates,
  network or bucket exposure, vulnerability scanning and Data Safe results.
- Workload, service and flow-log contents; metrics.
- Creating or enforcing Security Zones from the parent (a governance use case, deferred; OSC stays
  read-only).

---

## 2. Security principles (non-negotiable)

This is a security tool with read access to an entire Organization. Treat it like a privileged system.

1. **Read-only against tenancies.** Collectors must only call `get_*`, `list_*`, `summarize_*`, `search_*`
   resource APIs. Mutating OCI resource calls are prohibited throughout **all** of `src/`, including
   the control plane; moving one outside collectors does not make it permitted. A future write feature
   requires an explicit design change. SDK constructors/signers and OIDC credential issuance are
   separately reviewed infrastructure operations. Enforced by the explicit allow-list in
   `oci_clients/allowlist.py` (every factory client is a `ReadOnlyClient`) plus the static and bypass
   tests in `tests/unit/test_sdk_boundary.py`; the older deny-list test stays as a second guard
   (`docs/architecture.md` §3).
2. **Least privilege.** The IAM policies in `docs/iam/` are the source of truth for what the tool needs.
   If you add a collector that needs a new permission, update those policy templates in the same change.
3. **No secrets in the repo, logs, or test fixtures.** No API private keys, fingerprints paired with keys,
   auth tokens, or `~/.oci/config` contents. Prefer instance/resource principals; otherwise reference keys
   by path or by **OCI Vault** secret OCID.
4. **Redact before logging.** Never log full request/response bodies from the OCI SDK. Use the logging
   helpers in `oci_security_center/logging.py` (structured JSON, redaction filter).
5. **Sanitized fixtures only.** Recorded API responses under `tests/fixtures/` must have real OCIDs,
   tenancy names, IPs, user names and emails replaced with synthetic values
   (e.g. `ocid1.tenancy.oc1..aaaafake0001`).
6. **Fail closed on auth, fail open on coverage.** If auth to a tenancy fails, report it loudly as a
   finding ("tenancy not scanned"), never silently skip it. A partial scan must say what it missed.
7. **Dependencies are an attack surface.** Pin versions, keep the dependency list short, justify new ones
   in the PR description.

---

## 3. Tech stack

| Concern | Choice |
|---------|--------|
| Language | Python **3.11+** |
| OCI access | Official `oci` Python SDK (no hand-rolled request signing) |
| Data models | `pydantic` v2 |
| CLI | `typer` |
| Web admin UI + API | `FastAPI` + server-rendered Jinja2 templates, no JS framework (strict CSP) |
| OIDC client | `authlib` (Authorization Code + PKCE, ID-token validation) |
| Persistence | **SQLite only (Phase 1)** on the OSC server: `osc.db` + per-tenancy monthly audit DBs; stdlib `sqlite3` behind the storage interfaces (no ORM; SQLAlchemy/Alembic are proposed with the ADB/MySQL backends); 90-day default retention (`docs/storage.md`). Future backends behind the same `DataStore`/`Sink` interfaces: Object Storage, ADB, MySQL, DB MCP server (write path) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` (the OCI SDK is synchronous) |
| Testing | `pytest`, `pytest-mock`; no live OCI calls in unit tests |
| Lint/format/types | `ruff` (lint + format), `mypy --strict` on `src/` |
| Packaging | `pyproject.toml` (hatchling), `src/` layout |

---

## 4. Repository layout (target; ✓ = exists in v0.1)

```
.
├── AGENTS.md / CLAUDE.md
├── pyproject.toml
├── docs/
│   ├── architecture.md           # design contracts, implementation status and release gates
│   ├── delta-fetching.md         # audit durability, checkpoint and replay contract
│   ├── collection.md             # ✓ what is collected, by tier; APIs, regions, fields, findings
│   ├── iam/                      # catalog + parent/cross-tenancy/single-tenancy templates
│   └── detections/               # catalog; one specification per enabled rule; planned rules labeled
├── src/oci_security_center/
│   ├── cli.py                    # ✓ typer entry point: `osc ...`
│   ├── runtime.py                # ✓ wires settings, storage, secrets, control plane
│   ├── web/                      # ✓ FastAPI app, server-side sessions, OIDC, templates
│   ├── config.py                 # app settings (pydantic-settings), no secrets
│   ├── logging.py                # structured logging + redaction
│   ├── auth/                     # signer factory: config profile, instance/resource principal, session token
│   ├── control_plane/            # tenant registry, onboarding, access verification, org discovery
│   ├── oci_clients/              # thin client factory: region + signer -> SDK client, retries, pagination
│   ├── collection/               # ✓ collector contract, registry, scan runner, audit coordinator, scheduler
│   ├── collectors/               # READ-ONLY data collection, one module per service
│   │   ├── organization.py       # ✓ tenant_manager_control_plane: list child tenancies
│   │   ├── identity.py           # ✓ compartments, region subscriptions, policies, identity domains
│   │   ├── identity_domains.py   # ✓ users, groups, dynamic groups per domain (minimal fields)
│   │   ├── cloud_guard.py        # ✓ configuration, open problems, security zones (reporting region)
│   │   └── optimizer.py          # ✓ Cloud Advisor enrollment and recommendations
│   ├── models/                   # pydantic: Tenancy, Finding, PolicyStatement, AuditEvent, ScanRun...
│   ├── analyzers/
│   │   ├── policy/               # statement parser + rule engine
│   │   └── audit/                # anomaly rules + baselines
│   ├── storage/                  # AppStateStore + DataStore + Sink interfaces; SQLite backend (Phase 1)
│   └── reporting/                # JSON / CSV / HTML exports
└── tests/
    ├── unit/
    ├── fixtures/                 # sanitized recorded responses
    └── integration/              # opt-in, live OCI, marked `@pytest.mark.live`
```

Collectors return **pydantic models**, never raw SDK objects. Analyzers never call OCI.

---

## 5. Core domain model

- **Tenancy** — `ocid`, `name`, `alias`, `org_role`, `home_region`, `subscribed_regions`,
  `organization_id`, `parent_tenancy_ocid`, `onboarding_status`
  (`discovered` → `pending` → `verified` → `active`, or `error`), `last_verified_at`, `last_scanned_at`.
  Credentials are separate parent `Connection`s (`admin|scan`), not per-child auth profile fields.
- **ScanRun** — id, start/end, tenancies attempted/succeeded/failed, per-collector status and errors.
- **Finding** — the normalized unit every pillar emits:
  source-specific versioned identity (`docs/storage.md` §3.4),
  `source` (`cloud_guard` | `security_zone` | `advisor` | `policy` | `audit_anomaly` | `coverage` |
  `governance`),
  `tenancy_ocid`, `region`, `compartment_ocid`, `resource_ocid`, `resource_type`,
  `severity` (`CRITICAL|HIGH|MEDIUM|LOW|INFO`), `title`, `description`, `rule_id`,
  `first_seen`, `last_seen`, `resolved_at` (required addition), `status`, `raw_ref` (pointer to source record, not the raw blob), `cis_refs`.
- **PolicyStatement** — parsed form of one IAM statement (see §7.3); alias definitions are policy-local.
- **AuditEvent** — normalized audit record (event type, principal, source IP, user agent, compartment,
  resource, time, request action, response status).

The current severity enum lives in `models/findings.py`. Source-specific severity mappings belong in
a single `models/severity.py` module when governance collectors are implemented; that module is planned.
Required additions: `CollectionScope`, complete manifests, organization generation and leases, durable
audit batch receipts and interval checkpoints (`docs/storage.md`, `docs/delta-fetching.md`).

---

## 6. OCI integration conventions

### Authentication
Full design: `docs/control-plane.md`. One signer factory in `auth/`. The **parent** tenancy has an
**admin** connection (interactive) and a **scan** connection (non-interactive). Children have **no
connections of their own**: they are reached cross-tenancy only, through the parent's scan identity.

Deployment modes (`OSC_DEPLOYMENT`):
- `workstation` — dev/POC. Scan identity is a CLI profile (B) or a service user + API key (C). Admin sign-in
  is OIDC or the local CLI profile (localhost only).
- `oci` — target production on OCI Compute. Scan identity is the **instance principal**
  (dynamic group `OSC-Scanner-DG`). Admin sign-in is OIDC only. Methods B and C are unsupported;
  C rejection is a runtime release requirement. Container Instance resource-principal deployment
  requires validated authentication/matching rules before support is advertised (control-plane §2.3).

Roles: `OSC-Admins` (connections, onboarding, policy screens, verify) and `OSC-Viewers` (findings,
policy review, audit views and exports), mapped from identity-domain groups. Every route is
authorized server-side.

Connection methods:
- **A. OIDC + token exchange** — admin signs in to the parent's identity domain (Authorization Code +
  PKCE, confidential integrated app). The access token is exchanged for an OCI **UPST** using
  `oci.auth.signers.TokenExchangeSigner`. Needs an Identity Propagation Trust in the domain.
  **Admin/interactive use only; never used by the scheduler.**
- **B. OCI CLI settings** — `~/.oci/config` path + profile name (API-key or `security_token_file`
  profiles). Store only path + profile. Turned off by default in server deployments.
- **C. User + API key** — user OCID, fingerprint and locally Fernet-encrypted key reference in v1;
  Vault-backed API-key-only bootstrap is unsupported because it creates a credential dependency cycle
  (`docs/control-plane.md` §3.1). Vault references require an independently usable keyless scan identity.
- **Instance / resource principal** — preferred scan identity when OSC runs in OCI.
- **Cross-tenancy** — how a parent identity reaches each child (Endorse/Admit, below).

Rules: never store private keys or client secrets in plaintext; tokens/UPSTs stay server-side and are
never sent to the browser or logged; the OIDC console URL (`cloud.oracle.com/?tenant=...`) is **not** an
issuer — use the identity domain URL and its `/.well-known/openid-configuration`.

### Policy templates (displayed by the control plane, never applied by OSC)
The full statement sets and screen behavior are in `docs/control-plane.md` §5:
- **Organization configuration screen** → everything OSC needs in the **parent**: identity-domain
  prerequisites, the `osc-parent-access` policy (admins + scanner), and the combined
  `osc-endorse-children` roll-up.
- **Child configuration screen** → for one child: the **Endorse** statements for the parent and the
  **Define/Admit** statements for the child's IAM admin.

Each block has copy, download and an OCI CLI command, plus a read-only status check
(✅ detected / ❌ missing / ⚠️ can't check). Core cross-tenancy shape (`oci` mode, dynamic group):
```
# parent
Define tenancy <ChildAlias> as <child_tenancy_ocid>
Endorse dynamic-group <OSC-Scanner-DG> to read all-resources in tenancy <ChildAlias>
# child
Define tenancy <ParentAlias> as <parent_tenancy_ocid>
Define dynamic-group <OSC-Scanner-DG> as <scanner_dynamic_group_ocid>
Admit dynamic-group <OSC-Scanner-DG> of tenancy <ParentAlias> to read all-resources in tenancy
```
Start broad (`read all-resources`) for the MVP, then tighten to the specific families each collector needs
(e.g. `cloud-guard-family`, `audit-events`, `optimizer-api-family`, `policies`, `compartments`).
**Verify family/resource-type names against current OCI docs before shipping a template.**
Identity Domains change how groups are referenced — handle both default-domain and named-domain groups.

### Clients, regions, pagination, retries
- Build clients through `oci_clients/` only. Always pass `retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY`.
- A new SDK operation needs, in the same change: an entry for its exact client class in
  `oci_clients/allowlist.py` (reads only), a matching IAM template update if permissions change, and
  code that uses it (the boundary test fails on unused or unlisted operations). Local methods whose
  names collide with SDK operations are exempted per file + receiver in that test, never by name.
- Use `oci.pagination.list_call_get_all_results` (or the generator variants for large sets). Never
  hand-roll `opc-next-page` loops.
- Region awareness is mandatory:
  - IAM reads that must be authoritative → **home region**.
  - **Cloud Guard** → query the tenancy's **reporting region** (from `get_configuration`).
  - **Audit** → regional; iterate every **subscribed region** (`list_region_subscriptions`).
  - **Optimizer / Cloud Advisor** → home region; may be disabled per tenancy — detect and report.
- Prefer `compartment_id_in_subtree=True` + `access_level="ACCESSIBLE"` from the tenancy root where an
  API supports it; otherwise walk the compartment tree (cache it per scan run).
- Handle `oci.exceptions.ServiceError` explicitly: 401/404 on a child tenancy = access/onboarding
  problem → record as a coverage finding; 429 = back off (retry strategy); 5xx = retry then record.

### Concurrency
- Parallelize across `(tenancy, region, collector)` units with a bounded `ThreadPoolExecutor`
  (default 8 workers, configurable). Create SDK clients per worker; do not share a client across threads.
- Respect OCI API rate limits; never fan out unbounded.

---

## 7. Pillar notes

### 7.1 Control plane — "Add a new tenant"
Full design, sequence diagram and security requirements: **`docs/control-plane.md`**. Summary:
1. **Host bootstrap** registers the parent and non-interactive scan connection. Authenticated admins
   use **Organization configuration** to manage the separate admin connection (OIDC domain URL, client
   ID and secret reference, or supported local CLI profile). The screen lists every parent policy and
   prerequisite with a read-only status check. API-key method C is a workstation scan identity.
2. Authenticate and run a read-only connection test (get tenancy, list region subscriptions).
3. **Discover children**: `OrganizationClient.list_organizations(compartment_id=<parent>)` →
   `list_organization_tenancies(organization_id)` in the home region. If there's no Organization or
   access is denied, allow manual registration by OCID.
4. Admin **selects children**. All children are reached cross-tenancy only.
5. **Child configuration screen** shows the **Endorse** statements for the parent tenancy and the
   **Define/Admit** statements for the child's IAM admin. OSC applies neither. Status `pending`.
6. **Verify** = read-only smoke test (get tenancy, list compartments, get Cloud Guard config, list audit
   events for the last 5 min) → `verified` → `active`, or `error` with a reason.
7. Never write to any tenancy, and never call mutating Organization APIs (`create_child_tenancy`,
   `delete_organization_tenancy`, `approve_*`, `update_organization`, ...) — required enforcement
   is the explicit SDK boundary plus static checks in architecture §3.
8. Admin screens are limited to `OSC-Admins`; viewers read findings, policy review, audit views and
   exports. First-time setup goes through `osc admin bootstrap` on the host. Every control-plane action is written to a local audit trail.
   **One organization per deployment.** Bootstrapping a different parent replaces the organization:
   after full configuration preflight, an exclusive maintenance lease drains work; a journaled switch
   replaces local state and advances an organization generation. Stale requests/workers cannot commit.
   Sessions end, old audit directories are quarantined/cleaned, and the control-plane audit trail is
   kept (`docs/control-plane.md` §6.1). Historic backups follow their own retention. Re-bootstrapping
   the same parent keeps children/onboarding; connection changes still fence old work and reverify access.
   Replacement installs candidate parent/connections atomically; the six implementation review fixes
   and their regression coverage are summarized in `docs/review-fixes.md`.
9. Every scan re-checks the required statements. A missing one is a HIGH coverage finding
   (`OSC-ACCESS-001`). A broader grant than OSC needs counts as present but is flagged by policy review.
   Coverage findings fail closed: they are resolved only by a complete check. If the policy read or the
   verify smoke test fails, open findings stay open and `OSC-ACCESS-001:check` / `:verify` is raised.

### 7.2 Governance aggregation
- **Cloud Guard problems**: `CloudGuardClient.list_problems` scoped to tenancy root, subtree, open problems.
  Capture detector, risk level, labels, resource, target. Record whether Cloud Guard is enabled — a
  disabled Cloud Guard is itself a HIGH finding.
- **Security Zones**: list zones and recipes; violations surface through Cloud Guard problems —
  classify them by detector type into `source="security_zone"`. Also report compartments holding
  sensitive resources that are *not* in any security zone (later phase).
- **Recommendations**: `OptimizerClient` recommendations (filter to security-relevant categories first,
  include cost/perf as INFO). Report "Cloud Advisor not enabled" as a coverage finding.
- Deduplicate using source-specific identities (`docs/storage.md` §3.4): native problem/recommendation
  IDs, policy statement identities, scoped coverage failures, and anomaly occurrences. Maintain
  `first_seen/last_seen`; resolve stateful findings only after complete same-scope evaluation.

### 7.3 Policy review & scanning (Tier 4)
- Collect all policies in all compartments (`IdentityClient.list_policies` per compartment).
- Parse each statement into `PolicyStatement`: `subject` (group/dynamic-group/any-user/service, incl.
  identity-domain qualifier), `verb` (`inspect|read|use|manage`), `resource` (type or family),
  `location` (tenancy/compartment path), `conditions` (raw `where` clause + parsed vars),
  plus `Define`, `Endorse`, `Admit` statement types.
- The parser must be tolerant: unparseable statements become a LOW finding (`POLICY-PARSE-001`), not a crash.
- Initial rule set (each rule gets a `docs/detections/<rule_id>.md` and unit tests):
  - `manage all-resources in tenancy` granted to any group other than Administrators.
  - Any `any-user` / `any-group` grant, especially without a `where` clause.
  - `manage` on `users`, `groups`, `policies`, `dynamic-groups`, `domains` outside an IAM-admin group.
  - Broad `Endorse`/`Admit` cross-tenancy statements (who can reach in/out of each tenancy).
  - Dynamic groups with overly broad matching rules combined with `manage` grants.
  - Policies attached at root that could be scoped to a compartment.
  - CIS OCI Foundations Benchmark IAM controls (map rule → CIS control id in `cis_refs`).
- Prior art worth reading (do not vendor): Oracle's CIS compliance script in the
  `oracle-quickstart/oci-cis-landingzone-quickstart` repo.

### 7.4 Audit logs & anomalies (collection: Tier 1 · anomaly rules: Tier 5)
- Sources: `AuditClient.list_events` (per compartment, per region) or Logging Search
  (`LogSearchClient.search_logs`) against the tenancy's `_Audit` logs including subcompartments.
  Prefer Logging Search for tenancy-wide queries; confirm query time-window limits in current docs
  and chunk long ranges.
- Audit retention is limited (default 365 days); for longer history, rely on a customer-configured
  Service Connector → Object Storage export (read-only consumption by us).
- Normalize only allow-listed `AuditEvent` fields, store with tenancy + region. No request/response
  blobs or headers. Audit collection follows `docs/delta-fetching.md`: durable events before scoped
  checkpoints, complete pagination, overlap/reconciliation and visible gaps. Daily summaries are for
  trends; short-window rules query exact events using minute-level candidate indexes (collection §7).
- Initial anomaly rules (deterministic first, statistical later):
  - IAM changes: policy create/update/delete, user/group membership changes, API key / auth token /
    customer secret key creation, MFA changes, identity domain settings.
  - Security control tampering: Cloud Guard disable/target/recipe changes, Security Zone changes,
    Audit retention change, logging/Service Connector deletion, Vault key schedule-deletion.
  - Console sign-in failure bursts (only after source event coverage is verified); sign-ins from a source
    IP / user agent never seen for that
    principal (baseline per tenancy, with warmup/coverage requirements). Country scoring is deferred
    until an approved geography source and privacy/dependency design exist.
  - Activity in a region the tenancy normally doesn't use.
  - Off-hours activity by privileged principals (configurable business hours / timezone per tenancy).
  - Same principal or IP active across multiple child tenancies in a short window.
- Every anomaly rule: `rule_id`, description, severity, required event types, tests with fixtures.

---

## 8. Coding conventions

- Type hints everywhere; `mypy --strict` must pass for `src/`.
- Format and lint with `ruff format` and `ruff check`. Line length 100.
- Pydantic models are immutable (`frozen=True`) unless there is a reason.
- No `print()` in library code — use the logger. CLI output via `rich`/typer helpers only.
- Functions that call OCI take a client (or client factory) as a parameter → easy to mock.
- Timestamps are timezone-aware UTC (`datetime.now(tz=UTC)`); store ISO-8601.
- OCIDs are strings validated by a shared `Ocid` type in `models/`.
- Keep modules small and single-purpose; one collector per OCI service.
- Docstrings on public functions: what it does, which OCI API(s) it calls, required IAM permission.

---

## 9. Commands

> Agents must run the quality gates before declaring a task done.

```bash
# setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# quality gates (all must pass)
ruff format --check .
ruff check .
mypy src
pytest -m "not live"

# live integration tests (opt-in; needs OCI credentials for a NON-PRODUCTION tenancy)
pytest -m live

# CLI
osc admin bootstrap --tenancy-ocid <ocid> --scan-method cli_profile|api_key|instance_principal \
    [--admin-method oidc --domain-url ... --client-id ... --client-secret-ocid ...] [--yes]
osc admin recover            # finish/roll back an interrupted organization switch
osc org discover | osc org show
osc policies parent [--check] | osc policies child <ocid>
osc child select|verify|activate <ocid>
osc scan [--tier N] [--only <datasets>] [--tenancy <ocid>] [--no-audit]
osc audit ingest | osc audit reconcile
osc scheduler [--once]       # long-running collection process (separate from `osc web`)
osc findings list [--status open|resolved|all]
osc db purge | osc db backup <dir> | osc db restore <backup> [--expect-parent ...] [--main-db-only]
osc web

# CLI (planned, Tier 5)
osc audit anomalies --since 24h
```

---

## 10. Testing rules

- Unit tests mock SDK clients; assert on our models, not on SDK internals.
- Each policy rule and anomaly rule needs at least one **positive** and one **negative** test.
- The policy parser gets table-driven tests with real-world statement shapes (synthetic names).
- Live tests are marked `@pytest.mark.live`, skipped by default, and must be read-only.
- Use synthetic fixtures. The fixture sanitizer is planned, not present; do not commit recorded OCI
  responses until a reviewed sanitizer and leak checks exist. See `docs/detections/README.md`.

---

## 11. Open decisions (update as they are made)

- [x] Deployment: **both** — `workstation` mode for dev/POC, `oci` mode (Compute instance principal) for production;
      Container Instance resource-principal support is gated on validated matching rules/auth. (2026-10-07)
- [x] Users: **two roles**, `OSC-Admins` and `OSC-Viewers`, from identity-domain groups. (2026-10-07)
- [x] Child access: **cross-tenancy only**, no per-child credentials. (2026-10-07)
- [x] Writes: **none — strictly read-only.** OSC displays required policies and checks them; humans
      apply them. (2026-10-07, replaces the earlier parent-side writer idea)
- [x] Storage Phase 1: **SQLite only** on the OSC server; **90-day** default retention; future backends
      (Object Storage, ADB, MySQL, DB MCP write path) behind the same interfaces. (2026-10-07)
- [ ] Storage follow-ups S5, S6, S8, S9 in `docs/storage.md` (SQLCipher, file granularity, MCP contract).
- [x] Control-plane audit retention: 365 days (`OSC_CONTROL_PLANE_EVENT_RETENTION_DAYS`). (2026-10-08)
- [x] Audit checkpoint/replay design: `docs/delta-fetching.md` (2026-10-08); coordinator implementation
      is implemented with mocked recovery tests. Incremental inventory fetching is deferred; scoped full snapshots first.
- [x] UI: **web admin UI on FastAPI**, server-rendered templates (v0.1, 2026-10-07).
- [ ] POC: is a token-exchanged UPST honored by Endorse/Admit across tenancies? (D2)
- [ ] Notification channel for new HIGH/CRITICAL findings (OCI Notifications topic, email, Slack).
- [x] Anomaly design: 30-day proposed lookback, 7 complete days before novelty scoring; exact-event
      correlation via minute candidates, late-event recomputation, coverage and cardinality limits
      (`docs/collection.md` §7, 2026-10-08). Capacity/defaults require POC validation.
- [ ] Whether to export findings to OCI Logging / Object Storage for SIEM ingestion.
- [x] Organizations per deployment: **one** for now. `osc admin bootstrap` with a new parent replaces the
      previous organization and removes active local data using the generation-fenced design
      in control-plane §6.1; backups follow their own retention. (2026-10-08)
- [x] Positioning: **governance and observability tool**, not a security scanner. Data collected in
      **tiers** 1–5 (`docs/collection.md`); permissions stay `read all-resources`; users and groups keep
      name, domain ID, OCID (+ group members) only; audit collects **all events**. Policy analysis and
      anomaly detection are Tiers 4 and 5. (2026-10-08)
- [ ] Collection capability gates Q1–Q6 in `docs/collection.md` (Q4 is an optional optimization).
- [x] Collection runs in a **separate scheduler process** (`osc scheduler`, plus one-shot `osc scan`),
      not in the web server. Audit files are stored **per organization generation**
      (`audit/g<N>/<tenancy>/<YYYY-MM>.db`). (2026-10-09)
- [x] Review contracts: policy-local aliases; source-specific finding identity; scoped complete
      snapshots; Vault dependency restrictions; fenced organization switching; complete backup/restore;
      SDK allow-list requirement. (2026-10-08)
- [x] Implement these contracts: `docs/architecture.md` §4 — done 2026-10-09 with mocked tests
      (Tier 1 collection, audit coordinator, journaled switch, backup/restore, SDK boundary).
- [x] Close the six implementation review issues: atomic candidate installation, directional audit
      splits, maintenance fencing, dependency completeness, restored finding rekeying, and persistent
      reconciliation sweeps (`docs/review-fixes.md`, 2026-10-09).
- [ ] Verify them against OCI: capability gates Q1–Q6 need an authorized non-production tenancy;
      mocked tests do not certify OCI compatibility. Tiers 2–5 are designed but not built.
- [ ] **Backlog — multi-organization support** (several parents in one deployment). To decide: user
      isolation (users see only the org whose identity domain they signed in to, plus an "operator"
      org that sees all), adding orgs (CLI + web for global admins — preferred), org-scoped settings,
      group caches, aliases and URLs, and how `oci` mode scans orgs other than the one hosting OSC
      (the instance principal lives in a single tenancy).

---

## 12. Working agreement for agents

- Read this file and the relevant `docs/` design before making structural changes.
- Small, reviewable changes; one pillar or concern per PR.
- If a task would add a write/mutating OCI call, a new IAM permission, or a new dependency — stop and
  call it out explicitly in the PR description (or ask first).
- When unsure about an OCI API's behavior, limit, or permission name, check the current OCI
  documentation / SDK reference rather than guessing, and note the source in a code comment.
- Update §11 and the relevant `docs/` page when a decision is made.
