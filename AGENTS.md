# AGENTS.md — OCI Governance Center

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) and humans working in this repository.
Keep this file current: when an architectural decision changes, update it in the same PR.

---

## 1. What we are building

**OCI Governance Center** is a Python **governance and observability** tool that gives a team a single pane
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
| 5 | **Cost visibility** | Read-only monthly cost for the parent and children from the parent's Usage API, viewable by tenancy, service and compartment (2026-10-27). |

Data is collected in **tiers** (`docs/collection.md`): **1** inventory and oversight · **2** guardrail
coverage · **3** change over time · **4** policy analysis (pillar 3 rules) · **5** activity analytics
(pillar 4 anomaly rules). Each tier includes the lower ones; dashboards follow the tier collected.
Tiers describe data scope only. Tier 1 access views cover observed IAM statements and group membership;
identity-domain admin-role grants arrive at Tier 4. No tier claims a complete effective-permissions
evaluator. Dashboards show unsupported, partial and stale coverage explicitly. The required design and
current implementation gates are in `docs/architecture.md` §4.

### Non-goals (for now)
- Auto-remediation or **any** write action against any tenancy, parent or child. **OGC is strictly
  read-only.** It shows the IAM policies it needs; humans apply them.
- Multi-cloud support.
- Replacing Cloud Guard. We aggregate and correlate; Cloud Guard remains the detector of record.
- Security-scanner data: key or token **material**, credential types other than API signing keys
  (auth tokens, customer secret keys, SMTP/DB credentials), expiring certificates, network or bucket
  exposure, vulnerability scanning and Data Safe results. **In scope since 2026-10-22:** per-user MFA
  status, federation/service-user flags, last successful sign-in and API-key creation date (age),
  used only for identity analysis. Key material and fingerprints are never stored.
- Workload, service and flow-log contents; metrics.
- Creating or enforcing Security Zones from the parent (a governance use case, deferred; OGC stays
  read-only).

---

## 2. Security principles (non-negotiable)

This is a security tool with read access to an entire Organization. Treat it like a privileged system.

1. **Read-only against tenancies.** Collectors must only call `get_*`, `list_*`, `summarize_*`, `search_*`
   resource APIs. The single reviewed exception is the Usage API query
   `UsageapiClient.request_summarized_usages` (a side-effect-free query sent as POST); any other
   `request_*` operation fails the boundary tests until reviewed. Mutating OCI resource calls are prohibited throughout **all** of `src/`, including
   the control plane; moving one outside collectors does not make it permitted. A future write feature
   requires an explicit design change. SDK constructors/signers and OIDC credential issuance are
   separately reviewed infrastructure operations. Enforced by the explicit allow-list in
   `oci_clients/__init__.py` (every factory client is a `ReadOnlyClient`), the static surface tests
   in `tests/unit/test_sdk_boundary.py` and the runtime bypass tests in
   `tests/unit/test_auth_and_boundary.py` (`docs/architecture.md` §3).
2. **Least privilege.** `docs/iam/ogc-local-read.md` is the source of truth for what the tool needs;
   `provisioning/bundle.py` renders it into the setup packages and manual guides. If you add a
   collector that needs a new permission, update both in the same change.
3. **No secrets in the repo, logs, or test fixtures.** No API private keys, fingerprints paired with keys,
   auth tokens, or `~/.oci/config` contents. The current scanner uses only the parent API key (§6),
   encrypted at rest with the encryption key managed separately.
4. **Redact before logging.** Never log full request/response bodies from the OCI SDK. Use the logging
   helpers in `oci_governance_center/logging.py` (structured JSON, redaction filter).
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
| OIDC client | `authlib` (Authorization Code + PKCE; access-token verification uses joserfc) |
| Persistence | **SQLite only (Phase 1)** on the OGC server: `ogc.db` + per-tenancy monthly audit DBs; stdlib `sqlite3` behind the storage interfaces (no ORM; SQLAlchemy/Alembic are proposed with the ADB/MySQL backends); 90-day default retention (`docs/storage.md`). Future backends behind the same `DataStore`/`Sink` interfaces: Object Storage, ADB, MySQL, DB MCP server (write path) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` (the OCI SDK is synchronous) |
| Testing | `pytest`, `pytest-mock`; no live OCI calls in unit tests |
| Lint/format/types | `ruff` (lint + format), `mypy --strict` on `src/` |
| Packaging | `pyproject.toml` (hatchling), `src/` layout |

---

## 4. Repository layout

The new package is `src/oci_governance_center/`; the deleted `oci_security_center` implementation
must not be restored. Current source modules:

- `models.py`, `config.py`, `logging.py`: contracts, operator settings and redaction.
- `auth/`: independent human OIDC, verified JWTs and parent API-key and encrypted child OAuth/WIF credentials.
- `oci_clients/`: official SDK construction, read-operation allow-list and pagination adapters.
- `provisioning/`: administrator-applied Terraform and manual guides; no runtime resource writes.
- `storage.py`: SQLite, encrypted credentials/sessions, scoped snapshots, durable Audit events,
  per-tenancy scan settings and finding triage.
- `service.py`: enrollment, organization discovery, child lifecycle and collection orchestration.
- `collectors/`, `severity.py`: explicit field projections and source severity mapping;
  `collectors/cost.py` reads organization cost from the parent's Usage API.
- `analyzers/`: pure analysis that never calls OCI — `__init__` (governance mirroring), `policy.py`
  (tolerant statement parser), `identity.py` (Tier 4 policy and identity rules per analysis scope).
- `web/`: FastAPI routes (`app.py`), pure tab view models (`views.py`), server-rendered templates and
  static CSS; no frontend framework.
- `cli.py`: `ogc web`, separate `ogc scheduler`, one-shot scan, retention and setup package commands.

Tests use synthetic fixtures and block network access. Current capability/release status is in
`docs/implementation/status.md`; older design pages do not certify the new implementation.
Collectors return pydantic models; analyzers never call OCI.

---

## 5. Core domain model

- **Tenancy** — `ocid`, `name`, `alias`, `org_role`, `home_region`, `subscribed_regions`,
  `organization_id`, `parent_tenancy_ocid`, `onboarding_status`
  (`discovered` → `pending` → `verified` → `active`, or `error`), `last_verified_at`, `last_scanned_at`.
  Credentials are separate `Connection`s (`admin|scan|delegated_scan`), never tenancy fields.
  Optional per-tenancy delegated scan connections follow `docs/delegated-scans.md`.
- **ScanRun** — id, start/end, tenancies attempted/succeeded/failed, per-collector status and errors.
- **Finding** — the normalized unit every pillar emits:
  source-specific versioned identity (`docs/storage.md` §3.4),
  `source` (`cloud_guard` | `security_zone` | `advisor` | `policy` | `identity` | `audit_anomaly` |
  `coverage` | `governance`),
  `tenancy_ocid`, `region`, `compartment_ocid`, `resource_ocid`, `resource_type`,
  `severity` (`CRITICAL|HIGH|MEDIUM|LOW|INFO`), `title`, `description`, `rule_id`,
  `first_seen`, `last_seen`, `resolved_at` (required addition), `status`
  (`open | resolved` from evaluation; `ignored | closed` from administrator triage, stored
  separately and applied on read), `triage`, `raw_ref` (pointer to source record, not the raw blob), `cis_refs`.
- **PolicyStatement** — parsed form of one IAM statement (see §7.3); alias definitions are policy-local.
- **AuditEvent** — normalized audit record (event type, principal, source IP, user agent, compartment,
  resource, time, request action, response status).

Current model definitions are in `models.py`; the full domain schema above remains a design target.
Source-specific severity mapping is in `severity.py`.
Required additions: `CollectionScope`, complete manifests, organization generation and leases, durable
audit batch receipts and interval checkpoints (`docs/storage.md`, `docs/delta-fetching.md`).

---

## 6. OCI integration — enrollment, application access and scanner trust

**Decisions: 2026-10-21; interview consolidated 2026-10-22.** OCI Governance Center (OGC)
has a new implementation under `src/oci_governance_center/`. Local validation and live release
gates are tracked in `docs/implementation/status.md`. Sections 6 and 7 define the
current enrollment, login, scanning and organization-replacement design. They supersede conflicting
older descriptions elsewhere in this file and `docs/`, including the historical decisions in §11.
The remaining specifications await separate review.

### 6.1 Deployment and enrollment boundary

- OGC is already running on a customer-selected host. Deploying the application or its hosting
  infrastructure is outside this release and remains in the backlog.
- Each OGC installation supports **one parent organization with multiple child tenancies**.
  Users enroll the parent; discovered children are configured under that parent, not independently.
- An installation with no enrolled parent presents a first-run web enrollment wizard. An
  **operator-supplied setup password** protects it before OIDC is configured. Disable that password
  after enrollment; subsequent configuration and parent replacement require `ogc_admin` login.
- The wizard collects the parent tenancy OCID, its **default identity-domain GUID**, and other
  required metadata such as home region and OGC's callback/base URL. Treat domain GUID, domain
  OCID, domain URL and tenancy OCID as distinct values and verify their relationships.
- Generate setup Terraform with a **Deploy to Oracle Cloud** Resource Manager button and a
  downloadable bundle. Also provide equivalent step-by-step OCI Console instructions.
  Administrators create the resources through Resource Manager/Terraform or the Console;
  OGC never applies Terraform or performs OCI resource mutations itself.

### 6.2 Parent setup and completion

The parent setup creates an API-key-capable user named `ogc` in its **default identity domain**,
the `ogc_scanner`, `ogc_viewer` and `ogc_admin` groups, required memberships and local read policies,
and a dedicated OIDC application for human login. These are identity-domain groups, not built-in
OCI administrator roles. The administrator selects an existing default-domain human user;
setup adds that user to `ogc_admin` so initial application administration is possible.

The administrator generates the scanner key pair locally. Setup registers **only the public key**
on the parent `ogc` user. The private key must not enter Terraform configuration, state or outputs.
After creating resources, the administrator returns to the wizard and supplies the `ogc` user OCID,
API-key fingerprint and matching private-key file, plus the human-login OIDC client ID and secret.
The wizard uses non-secret identifiers returned by setup and verifies them against the parent.

Upload the private key over HTTPS and encrypt it at rest. The operator supplies the encryption
key separately from the application database. Protect OIDC secrets similarly. Never display or
export the stored private key or include credentials in logs, URLs or ordinary stack outputs.
Terraform may retain OIDC application secrets in state: treat that state as sensitive and provide
explicit secure handoff instructions rather than presenting secrets as normal outputs.

Enrollment completes only after scanner credential/access verification and a successful OIDC
sign-in by a member of the **new parent's `ogc_admin` group**. Start parent scanning and discover
children after completion. Newly discovered children remain **Not configured** until their setup
and verification are complete. Resource creation or Terraform success alone is not verification.

### 6.3 Human login and application authorization

Human login uses OIDC through the enrolled parent's **default identity domain**, with its own
client ID and secret. Authorization requests use only `urn:opc:idm:__myscopes__`; no ID token,
openid/profile/groups scopes or Me lookup are required. Verify the returned user access token and
bind Asserter membership results to that user using group IDs. Login is separate from scanner
authentication; scanners never use those client credentials. Only the parent's groups determine
application access:

| Parent default-domain group | Application access |
|---|---|
| `ogc_viewer` | Login and view collected data, findings and reports across the parent and every configured child; no configuration changes. |
| `ogc_admin` | Login, view organization-wide data and manage configuration, including scanner credentials, child setup, pause/resume and parent replacement. |
| Both groups | Administrator access. |
| Neither group | No application access. |

`ogc_scanner` grants OCI read access to the automation identity; it grants no application login
rights by itself. Child-domain group membership grants no application access. Administrators
manage all group membership in OCI; OGC reads and enforces membership and provides no membership
or role-assignment write feature.

Re-check membership at least every five minutes during active sessions and before configuration
changes. If membership cannot be verified, deny configuration changes. At the next membership
check, losing both login groups ends the session; losing `ogc_admin` while retaining `ogc_viewer`
reduces access to viewing. Enforce authorization server-side on every protected route.

Keep OIDC login independent of scanner availability. An invalid scanner key must not prevent
an authorized human from signing in, viewing historical data or repairing credentials. Membership
verification must support this separation; a failed membership check never grants admin access.

### 6.4 Scanner credentials and tenancy-level permissions

Parent inventory and organization discovery use the parent `ogc` API key directly. Parent
API-key-to-JWT issuance also uses that key, without OAuth client credentials. Each child stores
its confidential application's client ID and secret encrypted for JWT-to-UPST caller authentication.
These credentials are distinct from the human login application. Do not introduce CLI profiles,
instance/resource principals, interactive delegated-login grants or child API keys.

`ogc_scanner` receives tenancy-level local read permissions for the required datasets: Cloud Guard,
Security Zones, Audit logs, Cloud Advisor, compartments, subscribed regions, users, groups and
membership, IAM policies, identity domains, and organization/child discovery where applicable.
The parent alone also needs `read usage-report` for organization cost (the Usage API returns the
tenancies its billing covers); children never need it.
Map the actual collector operations to current OCI resource types and least-privilege read grants
before publishing the templates. The application-access groups are not scanner resource permissions.

The default-domain scanner identity must scan **every identity domain in its tenancy, including
new domains**, using tenancy-level read grants. Do not require separate users, trusts or routine
Terraform updates per target domain. Discover domains on subsequent scans and read their resources.
Validate this behavior for users, groups and memberships with the actual SDK endpoints. Any denied
or unsupported domain read is an explicit coverage gap, never proof of an empty domain.
**Default scope (2026-10-27):** each tenancy reads users, groups, dynamic groups and API keys from
its **default domain only**; reading every domain is a per-tenancy administrator opt-in on the Scan
tab. The grants stay tenancy-level so opting in needs no setup change. Subjects in unread domains
are unknown to analysis, never missing or unused.

The parent and children each have their own local scanner permissions. Parent group membership
alone grants no child access. **Endorse/Admit policies are not an OGC access mechanism.**

### 6.5 Child Configure and setup

For each discovered child, Configure asks for its **default identity-domain URL** plus the child
confidential application's **client ID and secret**. Other child metadata is discovered automatically.
OGC derives its GUID from the validated URL, exchanges the parent JWT for a child UPST, and uses
child credentials to discover the child's home region and active Default-domain OCID. Match the
URL and domain ownership to the selected organization child. Search the child domain for exactly
one active service user with `userName eq "ogc"`; discover its user OCID automatically. Validate
that user and domain against child-tenancy IAM before saving configuration or enabling monitoring.
No manual child user OCID, domain OCID, GUID or region is required for verification. Terraform
stack inputs still require the target identifiers needed by the administrator to provision resources.
Discovery/access failures preserve existing configuration and show the failed verification step.

Generate a child-specific Terraform bundle and Deploy to Oracle Cloud button. The administrator
signs into that child tenancy and reviews/applies its stack. Supply equivalent OCI Console
instructions for customers performing setup manually. Both paths create the same prerequisites:

1. A child-local `ogc` service user in the default domain and the groups/memberships required
   for local scanning, including `ogc_scanner`. No child API key or scanner password is created.
2. Local tenancy-level read policies covering the required resources across all identity domains.
3. Identity Propagation Trust in the child's default domain, trusting the **parent default domain**
   and mapping only the authorized parent `ogc` principal to the child-local `ogc` service user.
   Bind the actual issuer, verification keys and required claims; do not use wildcard parent users.
4. An active confidential application bound to the trust's OAuth client allow-list. The admin
   retrieves its client ID and secret and supplies them to OGC for the child exchange.
5. Verified setup identifiers and instructions for returning to OGC and checking access.

Use the official OCI Terraform provider, including its
[Identity Propagation Trust resource](https://docs.oracle.com/en-us/iaas/tools/terraform-provider-oci/latest/docs/r/identity_domains_identity_propagation_trust.html).
Pin provider requirements and validate resource schemas. Provide explicit import/reuse instructions
for pre-existing resources. OGC generates/checks setup but never executes provisioning.

After setup, **successful verification automatically enables monitoring**; there is no separate
Activate action. If identity/authentication succeeds but some datasets are inaccessible, enable
collection of the accessible datasets and mark the child **Partial coverage** with explicit gaps.
An authentication or identity-binding failure leaves that child disabled.

### 6.6 API key → parent JWT → child UPST

Parent scans use the API key directly. For child scans only:

Child Terraform provisions an active confidential OAuth application (Client Credentials grant)
and binds its OAuth client ID to the trust's `oauthClients`. The trust sets `subjectClaimName=sub`,
`subjectType=User`, `subjectMappingAttribute=userName`, the parent issuer and JWKS endpoint, and
an exact parent-ogc impersonation rule targeting the child service user. The rule matches the
parent `ogc` user's **username** (the parent JWT `sub`, normally `sub eq ogc`), never its SCIM ID
or OCID (decision 2026-10-22). Export the client ID
and trust ID for validation; retrieve the generated client secret securely from the application's
configuration and enter it in OGC. No secret is printed in ordinary Terraform outputs. OGC encrypts
child credentials separately from child metadata and removes them on parent replacement. Protect
Terraform state because it may contain the application's generated secret.

1. Make an OCI API-key-signed request as the parent `ogc` user to the parent default-domain token
   endpoint to obtain that user's JWT access token. This is a domain-issued token, not a locally
   minted assertion claiming to be issued by the domain.
2. Exchange that parent JWT through WIF at the child's default domain, authenticating the caller
   with the child's confidential application client ID/secret using HTTP Basic. Its trust maps the exact
   parent principal to the child `ogc` service user and returns a child UPST.
3. Validate the returned principal and owning tenancy. Use the UPST with its bound signing key
   and the official OCI SDK for child scans, including reads across the child's identity domains.
4. Obtain fresh tokens before expiry using the same parent API key. Isolate token/signing-key state
   by parent, child and domain, and invalidate affected cached state on credential/configuration changes.

Oracle's [API-key-to-access-token request example](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/token_exchange_grant_type.html)
authenticates the first exchange with an OCI request signature without an OAuth client secret.
Use that flow for parent issuance; use child confidential-client credentials only for the second
exchange. Oracle also documents
[JWT-to-UPST exchange](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm).
Prove the combined flow, including first-hop scope, issued claims, child-exchange caller authorization,
trust mapping, SDK support and renewal, in an authorized non-production organization. The OIDC
application for human login must not become an implicit dependency of scanner authentication.

### 6.7 Monitoring lifecycle and failure behavior

- Administrators can **pause** a child without deleting its configuration or collected history.
  Resume re-verifies access before restarting. Automatic coverage retries never override a pause.
- Continue accessible datasets during partial coverage, retry failed datasets on schedule, and
  automatically restore full coverage after successful reads. Clear warnings only on complete
  successful checks of the affected scope. One child's failure must not stop healthy siblings.
- Retry temporary network/service failures with bounded backoff; show delayed/stale coverage.
  Coverage errors include the HTTP status, validated OCI error code, failed operation name, OCI's
  short error message (control characters stripped, tokens/keys redacted, at most 300
  characters; 2026-10-27) and `opc-request-id` for Oracle support. No other response body content
  is kept.
  A temporary failed request is not confirmation that a key has been revoked.
- A **confirmed invalid/revoked parent API key stops organization-wide collection**, including new
  child exchanges; discard cached child tokens as agreed. Preserve historical data. Require an
  administrator to supply and verify a valid key before collection resumes.
- Recheck organization membership. If successful discovery confirms a child has left, stop monitoring
  it and retain history under normal retention. Failed discovery shows unknown status, not removal.
- Show failures through persistent in-application banners, status and coverage findings. No email or
  external notifications in this release. Authorized users can still view history with stale warnings.
- Preserve per-tenancy/domain/region/dataset coverage and timestamps. Failed/incomplete reads must
  not erase prior inventory or resolve findings as though results were empty.
- All OCI resource calls are read-only, with reviewed SDK operations, pagination, bounded concurrency
  and retries. Use the scanned tenancy's IAM home region, Cloud Guard reporting region and subscribed
  Audit regions. Never derive a child's scope from the parent's subscriptions.

### 6.8 Parent replacement

An authenticated `ogc_admin` can replace the parent through the UI. Replacement starts at the
**same first screen as new parent onboarding**, with no reuse of old parent credentials, domain
settings or child configuration. The existing admin session authorizes beginning replacement;
finalization also requires successful `ogc_admin` sign-in against the newly configured parent.
The disabled first-run setup password does not become an alternative way to replace a parent.

Keep the existing organization intact until fresh onboarding and verification of the new parent
succeed. A failed or canceled candidate setup leaves the existing organization operational.
After successful onboarding, stop/fence old collection and requests, invalidate old sessions,
install the new organization, and cleanly remove the old organization's server-held data and
credentials, including child configurations, token caches, histories, server-managed backups and
generated exports. Files already downloaded by users are outside OGC's control.

The server must recover interrupted switches/cleanup safely and must not allow old workers or
sessions to read or publish across organizations. Do not report replacement as complete while
required cleanup remains unfinished. This release still has one active parent; future multi-parent
support must allow distinct organization configuration, credentials, access and data boundaries.

### 6.9 Scan tab and recurring collection

Provide a Scan tab with an administrator-only on-demand full organization scan and one optional
recurring schedule. Support exactly **daily** (time of day) and **weekly** (weekday and time of
day), with an explicit IANA timezone. Administrators may update or disable recurrence; viewers
may inspect the schedule, next run and history. Recurrence is initially disabled. Full scans
include parent and configured, unpaused children, governance and Audit, limited by each tenancy's
collection settings (Cloud Guard, Cloud Advisor, identities from the default domain or all
domains, policies, Audit; organization cost on the parent; `docs/scanning.md`). Disabled datasets are not read and are not
coverage gaps; stored data for them is kept and labeled.

Queue work durably for the separate scanner process; never run collection in the web request.
Show queued/running/completed/partial/failed/interrupted history and worker offline status.
Coalesce overlapping requests and missed occurrences, prevent concurrent organization runs and
preserve partial dataset coverage. Calendar schedules replace fixed family collection intervals;
initial enrollment and child configuration still trigger automatic collection. Fence all controls
and worker results by organization generation. Clear schedules/history on successful parent
replacement; preserve them during failed onboarding and same-parent credential repair.
Flag incomplete scopes as OGC-ACCESS-002 scanner coverage findings with a distinct UI label.
Provide incomplete-only Coverage filtering and scan details with per-scope diagnostics, tenancy,
dataset, domain/region, timestamps and last success. Snapshot diagnostics when jobs finish; clearly
label live coverage and unavailable older snapshots. Preserve historical failure evidence after
recovery. Do not serve raw process logs, debug payloads or credentials through these views.
See `docs/scanning.md` for timezone/DST, recovery, retention and authorization contracts.

Tenancy collection leases last 600 s and are renewed every 60 s while a scan runs. Lease owners
are tagged with the scanner worker's identity, so when a crashed or restarted worker's job is
marked interrupted its tenancy leases are released and a queued scan starts within about two
minutes. While a queued scan waits for earlier locks, the Scan tab says when it will start.
Stopping `ogc scheduler` (with or without `--once`; Ctrl-C or SIGTERM) ends the running scan
after its current OCI request, keeping everything committed. Analysis still runs and fails closed
on inputs not read. The job is marked interrupted only if work actually ended early; a parent-key
failure is still reported as such. A second signal marks the job interrupted, releases this
worker's tenancy locks and exits immediately. Long Audit
ranges log progress every 24 hours of history (2026-10-27).

Collection settings are per tenancy (`docs/scanning.md`); the default reads only the tenancy's
default identity domain. `ogc_admin` may **ignore**, **mark closed** or **reopen** any finding,
including coverage findings. Triage is stored apart from evaluated findings, applied on read
(status `ignored`/`closed`), logged as a control event, cleared on parent replacement, and never
writes to OCI. Ignored findings stay ignored across scans; closed findings reopen when a later
complete evaluation still detects them. Finding lists show Open by default.

Tabs: Overview, Coverage, Cloud Guard, Cloud Advisor, Cost (monthly cost for 12 months by
tenancy, service and compartment tree with rolled-up totals; currencies never mixed), Resource organization (compartment tree
with policy statements in each compartment and in its hierarchy, i.e. the compartment plus every
compartment above it), Identity (users, groups, dynamic groups, policies, policy analysis),
Activity (Audit events filterable by tenancy, region, principal, event and result), Scan and
Configuration. Finding, Cloud Guard, Identity and data pages filter by tenancy and the relevant
fields (severity, type, rule, status, dataset, domain, compartment).

---

## 7. Implementation plan

This is a plan for a new implementation, not a record of completed work. Validate the identity
path first; implement the enrollment experience and collection against these agreed contracts.

### 7.1 Prove authentication and tenancy-wide read access

In an explicitly authorized non-production parent and child, demonstrate API key → parent-domain
JWT → child WIF exchange → child `ogc` UPST → required read-only OCI calls. Confirm scanner
operation/renewal using child confidential-client credentials, without child API keys, interactive
login or refresh grants.
Record scope, issuer/key relationships, subject mapping, exchange caller authorization, expiration
and signing-key binding. Reject wrong principals, issuers, children, domains and expired assertions.

Verify default-domain scanner access to users, groups and memberships across **existing and newly
created domains**, with tenancy-level policies and no per-domain scanner setup. The administrator
performs test provisioning separately; OGC only reads resources. Document exact missing permissions
or API limitations as validation blockers rather than silently changing the design.

### 7.2 Implement setup packages and manual guides

Build parent and child Terraform packages with official pinned providers, deploy buttons,
non-secret outputs and equivalent OCI Console instructions. Parent setup creates the scanner,
application groups, initial human admin membership, read policies and dedicated login OIDC app.
Child setup creates its service identity, local scan grants and trust. Neither deploys OGC itself.

Validate formatting, provider schemas, expected plan contents and existing-resource handling.
Keep the scanner private key outside Terraform and document secure OIDC-secret retrieval and
state protection. Verify both setup methods produce the same prerequisites and no child API keys.

### 7.3 Implement enrollment and human access

Build the setup-password-protected first-run wizard, metadata collection, setup generation,
credential upload/encryption and verification, and final `ogc_admin` OIDC sign-in. Reject concurrent
or stale enrollment completion so only one active parent can be installed.

Implement OIDC login, group-based route authorization, membership rechecks, session termination
and admin-to-viewer downgrade. Test group management remains exclusively in OCI. Verify that
OIDC access and credential repair work during scanner authentication failures. Discover children
after parent enrollment and render them as Not configured until their own setup is verified.

### 7.4 Implement child configuration and monitoring

Implement Configure → default-domain GUID and verified metadata → Terraform/deploy-button or
manual setup → Verify → automatic monitoring. Preserve an explicit distinction between invalid
identity/authentication and individual dataset failures; partial access starts partial monitoring.

Implement token acquisition/renewal, principal isolation, reviewed read-only SDK enforcement,
bounded scheduling, per-scope coverage, scheduled recovery retries and pause/resume. Handle parent
key invalidation, child trust removal and confirmed child departure without destroying history.
Show persistent application failures and stale data; do not build external notification integrations.

Implement the Scan tab, persistent daily/weekly calendar schedule and durable full-scan queue
as specified in section 6.9 and `docs/scanning.md`. Extend the separate scanner with heartbeat,
atomic claims, renewable leases, missed-run coalescing and interrupted-job recovery. Validate
admin/viewer permissions, CSRF, calendar/DST boundaries, concurrent workers and replacement
fences with offline regression tests.

### 7.5 Implement safe parent replacement

Reuse fresh enrollment screens for the replacement candidate without copying old secrets/settings.
Require the current admin to initiate and the new parent's admin to complete. Keep old state intact
until candidate verification succeeds. Fence old work, switch authentication/configuration and remove
old server-held organization data, backups and exports. Test cancel/failure, concurrent operations,
crash recovery and cleanup failures so data or credentials cannot cross the organization boundary.

### 7.6 Collection, analysis and acceptance

Collect inventory and governance data according to the reviewed collection tiers: Cloud Guard,
Security Zones, Cloud Advisor, compartments, identity/policy inventory and regional Audit events.
Build governance aggregation from verified stored records, preserving source identities and scoped
finding resolution. Add Tier 4 policy rules and Tier 5 audit anomalies after prerequisite data and
coverage exist. Analyzers never call OCI. Customer Endorse/Admit grants may be analyzed but are
not generated or required for OGC access. Audit ingestion must remain durable and gap-aware.

Test setup/enrollment, both application roles and role removal, all-domain reads, WIF renewal,
partial recovery, pause/resume, credential/trust revocation, key replacement and organization cleanup.
Use synthetic fixtures and mocked OCI clients for unit tests; live checks require an explicitly
authorized non-production organization. Passing mocks does not certify OCI interoperability.
Run applicable lint, type and test gates once application code and tooling exist again.

### 7.7 Backlog and remaining specification review

- **OGC application/hosting deployment**, including a full Resource Manager deployment stack.
  The current stacks configure tenancy prerequisites only; hosting will be decided later.
- **Multiple parent organizations in one installation**, with organization-specific login routing,
  credentials, access boundaries, configuration and storage.
- **Per-tenancy visibility restrictions** for application users; current viewers/admins see the
  whole enrolled organization according to their application role.
- **External administrator notifications**, such as email or another notification service.
  Current failures are visible only inside OGC; notification delivery requires a separate integration.

Reconcile the remaining sections, IAM templates and `docs/` as those areas are reviewed. Remove
obsolete credential options, cross-tenancy access prerequisites and claims about deleted code.
Until reconciled, these sections take precedence for the contracts listed at the start of §6.

---

## 8. Coding conventions

- Type hints everywhere; `mypy --strict` must pass for `src/`.
- Format and lint with `ruff format` and `ruff check`. Line length 100.
- Pydantic models are immutable (`frozen=True`) unless there is a reason.
- No `print()` in library code — use the logger. CLI output via `rich`/typer helpers only.
- Functions that call OCI take a client (or client factory) as a parameter → easy to mock.
- Timestamps are timezone-aware UTC (`datetime.now(tz=UTC)`); store ISO-8601.
- OCIDs are strings validated by a shared `Ocid` type in `models.py`.
- Keep modules small and single-purpose; one collector per OCI service.
- Docstrings on public functions: what it does, which OCI API(s) it calls, required IAM permission.

---

## 9. Commands

Agents must run these quality gates before declaring work done:

```bash
ruff format --check .
ruff check .
mypy src
pytest -m "not live"
```

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ogc encryption-key   # generate once; operator stores separately from data/backup
ogc web              # HTTPS reverse proxy required; operator settings in README.md
ogc scheduler        # separate process; observes organization/child changes
ogc scheduler --once
ogc scan --family identity|governance|audit|all
ogc purge
ogc setup-package parent /tmp/ogc-parent.zip
ogc setup-package child /tmp/ogc-child.zip
```

Enrollment and parent replacement are web workflows, not host bootstrap commands.
The runtime exposes Tier 1 plus Tier 4 policy and identity analysis (admin-role grants excluded).
Tiers 2, 3 (attribution) and 5 are not implemented; do not advertise them as implemented.

---

## 10. Testing rules

- Unit tests mock SDK clients; assert on our models, not on SDK internals.
- Each policy rule and anomaly rule needs at least one **positive** and one **negative** test.
- The policy parser gets table-driven tests with real-world statement shapes (synthetic names).
- Live tests are marked `@pytest.mark.live`, skipped by default, and must be read-only.
- Use synthetic fixtures. The fixture sanitizer is planned, not present; do not commit recorded OCI
  responses until a reviewed sanitizer and leak checks exist. See `docs/detections/README.md`.

---

## 11. Historical decisions and pending review

The new decisions in sections 6–7 supersede conflicting historical entries below. Current
implementation status is in `docs/implementation/status.md`; checked items here may refer to deleted code.

- [x] Deployment: **both** — `workstation` mode for dev/POC, `oci` mode (Compute instance principal) for production;
      Container Instance resource-principal support is gated on validated matching rules/auth. (2026-10-07)
- [x] Users: **two roles**, `OSC-Admins` and `OSC-Viewers`, from identity-domain groups. (2026-10-07)
- [x] Child access: default cross-tenancy; optional **child-local delegated UPST scan connections**
      replace the cross-tenancy-only restriction (2026-10-15, `docs/delegated-scans.md`).
- [x] Onboarding UI and Verify follow the selected scan connection: delegated scans show local
      prerequisites; parent-scanner Endorse/Admit requirements remain conditional
      (`docs/delegated-scans.md`, 2026-10-15).
- [x] Delegated authorization pages allow only their saved identity-domain origin in CSP
      `form-action`; other pages stay local-only. Discovery endpoints compare host/effective HTTPS
      port so explicit `:443` works (`docs/delegated-scans.md`, 2026-10-15).
- [x] Delegated UPST identity binding uses `GetTenancy` + `GetUser(sub)` and the user's owning
      tenancy on every exchange/renewal; no `res_tenant` claim is required. Added read-only `get_user`
      under the existing local read grant (`docs/delegated-scans.md`, 2026-10-15).
- [ ] Validate API-backed UPST binding against OCI, refresh lifetime and multi-domain read access
      in a named non-production tenancy; mocked checks do not establish OCI authorization.
- [x] Delegated scan implementation: schema v4 encrypted offline grants, admin OIDC authorization,
      serialized refresh rotation, per-tenancy CLI/scheduler routing and restore invalidation
      (`docs/delegated-scans.md`, 2026-10-15).
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
- [x] Child trust impersonation rules match the parent `ogc` user's **username** (`sub eq ogc`),
      not its SCIM ID or OCID; the parent package outputs `scanner_username` (2026-10-22).
- [x] Token-exchange debug logging of bearer tokens is removed; tokens are always redacted and
      no setting may disable redaction (2026-10-22, AGENTS.md §2).
- [x] Audit cursors: forward catches up to the present each scan, reconciliation re-reads the 24h
      before the previous forward checkpoint, backfill runs toward a fixed target with a per-scan
      hour budget (`OGC_AUDIT_BACKFILL_HOURS`). `OGC_SETUP_PASSWORD` is at least 16 characters and
      only failed unlocks count toward the setup throttle (2026-10-22).
- [x] Navigation: Overview, Coverage, Cloud Guard, Cloud Advisor, Resource organization (compartment
      tree), Identity, Activity, Scan, Configuration. Findings/Inventory leave the menu; their routes
      and exports remain (2026-10-22).
- [x] Tier 4 policy/identity analysis enabled as persisted findings in four fail-closed scopes
      (`analysis.policy`, `analysis.identity`, `analysis.api_keys`, `analysis.activity`). "Not in use"
      combines static policy references with sign-in and Audit activity; activity rules run only when
      Audit coverage spans `OGC_INACTIVE_DAYS`. OCI API keys do not expire, so age is flagged against
      `OGC_API_KEY_MAX_AGE_DAYS` (2026-10-22).
- [x] Per-tenancy collection settings on the Scan tab (Cloud Guard, Cloud Advisor, identities,
      policies, Audit; identity domains default-only or all). Default reads only the default
      identity domain. Subjects in unread domains are unknown: never stale or unused (2026-10-27).
- [x] Resource organization shows policy statements per compartment and per hierarchy
      (compartment plus every ancestor up to the tenancy); hidden, never zero, when policy
      collection is incomplete or disabled (2026-10-27).
- [x] Administrators can ignore, mark closed or reopen any finding. Ignore persists across scans;
      closed reopens when a later complete evaluation detects it again. Triage is local state
      only and never writes to OCI (2026-10-27, `docs/scanning.md`).
- [x] Scan worker lease recovery: tenancy lease owners carry the worker identity; claiming work
      after a dead worker releases that worker's leases; queued scans show when locks expire
      (2026-10-23). Leases taken before this change can only expire (up to 10 minutes).
- [x] Coverage messages include the validated OCI error code and request ID, never bodies
      (2026-10-23). `ListApiKeys` is called without an attribute list after OCI rejected
      `id,ocid,user,meta` with HTTP 400; key material and fingerprints are dropped.
- [ ] Live gates: `ListApiKeys` under `read users` (the parent `ogc` key was still not shown on
      2026-10-23), SCIM MFA/federation/sign-in attributes and `ListCategories` names, in a named
      tenancy.
- [x] Cost visibility: dataset `cost.monthly` from the parent's Usage API (`request_summarized_usages`,
      MONTHLY, COST, 12 months, grouped by tenant ID, service, compartment ID and path; the API allows at most four groupBy keys, so tenancy names come from OGC); parent-only
      grant `read usage-report`; Cost tab by tenancy, service and compartment (rolled up); a Cost
      switch on the parent's collection settings, on by default (2026-10-27).
- [ ] Cost live gates: the parent's Usage API returns child tenancies; `compartmentPath` format and
      `compartment_depth=6`; paging; `read usage-report` alone is sufficient.
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

### Review corrections (2026-10-27)

Policy counts require successful policy coverage for the tenancy root and every expected active
compartment, plus complete compartment discovery. A missing scope is unknown, never zero. Orphan
compartments may show collected own statements, but hierarchy totals stay unavailable for them
and their descendants until all ancestors are known. Deleted compartments without policy coverage
also show unknown counts. Cost queries use Usage API depth 6 (root depth 1); deeper costs are
aggregated into depth-6 ancestors. Cost totals group by tenancy OCID, keeping equal display names
separate. Labels do not establish tenancy identity.
