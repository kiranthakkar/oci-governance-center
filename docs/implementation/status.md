# New OGC implementation — status and acceptance

Date: 2026-10-22. Authority: AGENTS.md sections 6–7 and the subsequent design interview.
Older design pages describe the removed implementation and are not proof of current capabilities.

## Local implementation

The new package is `oci_governance_center`; the command is `ogc` and operator settings use `OGC_`.
The server-rendered FastAPI application includes initial parent enrollment, administrator/viewer login,
configuration, normalized organization dashboards and JSON exports. Collection runs in a separate
scheduler process. The parent uses its API key directly; child workers exchange the parent key for a
domain JWT and exchange that assertion for child-local UPST credentials using the child confidential
application client ID/secret. Parent issuance remains API-key authenticated.

Application passwords, scanner keys and tokens are never browser session payloads. The browser
holds a random server-session ID and CSRF token; all server sessions and enrollment candidates are
encrypted. Admin access is verified against the human token's default-domain Me/group response,
independently of scanner credentials. JWT verification restricts algorithms, keys, issuer, expiration,
audience, nonce and authorized party where applicable. No token-controlled key URLs are followed.

The local SDK boundary exposes exact reviewed reads per client class. Each worker owns its clients,
HTTP transport and child token-signing keys. Token renewal rechecks child identity and owning tenancy.
Parent-key invalidity is confirmed using the parent's GetTenancy; a child permission denial does not
invalidate the whole organization. A confirmed invalid key fences all subsequent collection publication.

Snapshot publication, child revision checks, worker leases, organization generations and credential
suspension are checked inside write transactions. Partial collection preserves the previous snapshot.
Findings retain first_seen and resolve only after complete matching-scope evaluation. Snapshot changes
are tracked, but audit-to-drift attribution and higher-tier analytical dashboards are not implemented.

Regional Audit collection uses the Audit API per accessible compartment, not Logging Search. Each scan
runs three durable cursors per region in order: forward reads catch up from the last checkpoint (with a
15-minute overlap) all the way to the present, so daily and weekly schedules never fall behind;
reconciliation re-reads the 24 hours before the previous forward checkpoint for late deliveries; and
historical backfill reads up to `OGC_AUDIT_BACKFILL_HOURS` (default 168) per scan toward a fixed target,
the point where forward collection began, so it finishes. Late events older than the reconciliation
window require a separately designed wider replay capability. Event files commit before progress. Events are deduplicated
by region/event ID; the recent-event view also deduplicates same-organization key-rotation files.
Backfill progress remains an explicit coverage finding. Time-window/capacity guarantees await live tests.

Parent replacement begins with empty onboarding fields. Old state remains available until verified
new-parent admin login. The switch atomically installs the candidate, fences old sessions/workers and
records pending filesystem cleanup. Old server-held organization data and artifacts are removed;
cleanup failures prevent completion and are retried on startup. No previously downloaded files can
be recalled. New-parent authorization cannot reuse an old parent's session role.

Findings, Inventory, Coverage and Activity pages filter by tenancy. Findings also filter by severity,
finding type (source), rule, status and title; Inventory and Coverage by dataset and region (plus name
or result); Activity by region, principal, event/action and success or failure. Filters are server-side
GET parameters validated against known values. Activity filters run in SQL before the 200-event limit,
so older matching events stay findable, and LIKE wildcards in search text are matched literally.

## Verification performed

- Python lint, formatting, strict types and network-blocked unit/integration-style HTTP tests.
- Actual OCI SDK client construction with ephemeral synthetic API keys, without network calls.
- Cryptographically signed JWT positive/negative tests, group authorization and state/CSRF checks.
- Generation, child revision and expired-lease fencing; scoped snapshot preservation/resolution;
  Audit durability/deduplication; cleanup recovery; retention; and recent-first Audit scheduling.
- Parent and child Terraform JSON `fmt -check` and `validate` with Terraform 1.13.5 and the signed
  official OCI provider 8.10.0. These checks load schemas only; no plan or apply has been performed.

## Required live acceptance gates

1. Use an explicitly authorized non-production organization. Confirm API-key-to-JWT scopes, issuer
   and subject; then prove the child confidential-client-authenticated exchange is accepted by its
   exact-subject trust. Verify client binding, secret rotation and isolated per-child credentials.
2. Validate the parent ordinary user/public key, child service-user flag, trust mapping/rule syntax,
   OIDC app template, allowed scopes and provider assignments through reviewed plan/apply.
   Terraform schema validity alone does not establish server-side acceptance.
3. Confirm human OIDC ID-token claims and Me group IDs, including membership revocation, downgrade,
   token expiry and administrator credential repair while the scanner key is invalid.
4. Prove tenancy-level default-domain scanner grants cover users/groups/memberships in every existing
   and newly created domain. Verify SCIM total counts, groups near/above membership limits, and any
   realm/region behavior. Unsupported endpoints and large groups must show coverage failures.
5. Prove each collector's local read policy, reporting/home/subscribed-region scope, SDK pagination,
   service-disabled cases, Audit interval limits, rate limits and late-event distribution.
6. Rehearse key rotation, trust revocation, child departure, pause/resume and parent switch/cleanup with
   a running scheduler and web process. Validate disk capacity, retention, restart and SQLite locking.
7. Validate Console-only setup steps against the current tenancy UI. Oracle documents trust/service-user
   operations through APIs/Terraform; a complete click-only Console path is not certified. Use the
   administrator-applied Resource Manager bundle where the Console lacks these controls.

The code does not advertise unsupported tiers or silently collect less than a requested higher tier.
The runtime exposes Tier 1 collection plus Tier 4 policy and identity analysis (2026-10-22): a
tolerant statement parser and the POL-*/IAM-* rules in `docs/detections/`, persisted as findings in
four fail-closed analysis scopes. Identity collection adds user MFA status, federation/service-user
flags, last successful sign-in and API-key metadata (creation date only; never key material). Tier 2
guardrail data, full Tier 3 attribution, Tier 4 admin-role grants and Tier 5 anomaly detection still
require implementation and their specified positive/negative/boundary tests before they can be
enabled. No effective-permissions completeness claim is made: where-conditions are recorded but not
evaluated, and policy aliases are not substituted. Full backup/restore tooling and wider Audit reconciliation are also not
implemented; replacement already removes artifacts in the managed backup/export directories.

## Backlog retained from the interview

Application hosting/deployment; multiple parents in one installation; per-tenancy viewer restrictions;
and external notifications. Failures currently appear only inside OGC.

## Dependency decisions

Direct dependencies are pinned in pyproject.toml. OCI handles request signing and resource clients;
Authlib handles OAuth Code+PKCE; joserfc (already used by Authlib) provides its current JWT verification
API; requests is used because the official OCI signer implements requests authentication; cryptography
provides Fernet credential encryption, public-key fingerprints and ephemeral UPST-bound keys. FastAPI,
Jinja2, multipart, uvicorn, pydantic/settings and typer implement the agreed application stack. Tests
use httpx, pytest and pytest-mock. No ORM, cloud abstraction, frontend framework or notification client
is added. The installed Authlib/Starlette versions currently emit HTTP-client migration deprecations;
the pinned integration is tested and those warnings are not suppressed.

Human login requests only `urn:opc:idm:__myscopes__` using Authorization Code + PKCE, with
one-time state validation. No openid/profile/groups scopes or ID-token dependency remain.
The returned JWT access token is verified against trusted domain keys and issuer, expiration,
identity-domain API audience, configured OAuth client ID/name, tok_type=AT and sub_type=user.
Asserter receives this token as bearer authorization with subjectType=user and includeMemberships=true.
Verified user_id is preferred for lookup; otherwise verified sub/sub_mappingattr is used. Responses
must match the selected user, and groups[].value must match a configured OGC group ID. Tokens are
stored only encrypted; expiry or legacy sessions require new sign-in. Rechecks occur every five
minutes and before configuration changes. Live acceptance must validate token claims, client
binding, Asserter permissions, and membership-change visibility. Scanner API-key exchanges remain
separate and continue to use the same myscopes scope for parent JWT issuance before child UPST.

## Scan controls

The Scan tab provides administrator-only on-demand scans and persistent daily/weekly schedules
with weekday, local time and IANA timezone controls. Viewers can inspect schedules and history.
The separate scanner executes durable, coalesced organization jobs including Audit, publishes
liveness, renews job leases and records interrupted runs. See `docs/scanning.md`.

## Child setup bundle correction

Child packages now create an active confidential OAuth client before creating propagation trust.
The trust binds `oauth_clients` to the app's OAuth `name` (not its resource ID) and explicitly
sets `subject_mapping_attribute=userName`, retaining the exact parent-subject impersonation rule.
The package creates the service user, scanner group/membership and local-read policy as before;
it exports the exchange client ID without exporting its generated secret. Parent and child bundles
pass Terraform 1.13.5/provider 8.10.0 schema validation. Live apply and exchange remain user tests.
Reference: https://github.com/balajepalli84/token-exchange-tf/tree/main/Resource_Manager

## URL-only child verification

Child Configure requires the default identity-domain URL and child confidential-app client ID/secret. The child UPST is used to discover
home-region subscriptions, match the active Default domain and search `userName eq "ogc"` in
that domain. Exactly one active service user is required; its OCID is discovered and verified with
child-tenancy IAM. Saving remains fenced by organization generation and child configuration revision.
Failed verification preserves prior configuration. Resume repeats discovery using the saved URL.
The parent's region is used only for bootstrap routing and is never assumed to be the child's home.

## Child token exchange authentication correction

The child JWT-to-UPST request now uses the child confidential application's HTTP Basic credentials,
not the parent's API-key signature. Parent scans and parent API-key-to-JWT issuance are unchanged.
Admin-only child configuration accepts the child app client ID/secret. Credentials are encrypted in
an isolated table, saved atomically with verified child metadata, reused during resume and renewal,
and deleted on parent replacement. Failed verification leaves previous credentials intact; changing
client IDs requires a new secret. Blank secret retains the existing secret for the same client only.
Logs identify each exchange stage, auth method, HTTP status and a short SHA-256 subject-token
fingerprint, without exposing bearer tokens or secrets. Live exchange still requires a tenancy test.

## Child trust subject rule syntax

Child Terraform emits `sub eq ${var.parent_subject}` without quoting the subject value, so
`parent_subject=ogc` produces `sub eq ogc`. The manual guide matches this syntax. Exact-subject
input validation still rejects wildcard values and quotes. The child download route uses the
same corrected generator.

## Scanner diagnostics visibility

Findings distinguish scanner coverage gaps (OGC-ACCESS-002) from resource security findings.
Coverage supports incomplete-only and tenancy filters. Scan history links to scope diagnostics,
with immutable finish-time snapshots, failure-first ordering and earlier-attempt labels.
Administrators and viewers can read diagnostics; anonymous users cannot. Snapshot writes require
an unexpired owned job and organization fence. Replacement and retention remove associated snapshots.
Raw debug logs and credentials remain outside the UI.

## Navigation and tabs (2026-10-22)

Overview, Coverage, Cloud Guard (per-tenancy status, mirrored problems with risk/type/region/resource
filters, Security Zones), Cloud Advisor (enrollment, recommendations with category names, estimated
savings and resource counts), Resource organization (collapsible compartment tree per tenancy without
JavaScript; deleted compartments optional; stale/missing collection is shown explicitly), Identity
(users, groups, dynamic groups, policies and policy analysis, filterable by tenancy and identity
domain), Activity, Scan and Configuration. The former Findings and Inventory pages remain reachable
at `/data/findings` and `/data/records` and through JSON exports but are no longer in the menu.

## Scan settings, policy counts and triage (2026-10-27)

Per-tenancy collection settings on the Scan tab (Cloud Guard, Cloud Advisor, identities with
default-domain-only or all domains, policies, Audit); the default reads only each tenancy's
default identity domain. Unread domains make policy subjects unknown, never stale or unused.
Resource organization shows policy statements per compartment and for its hierarchy
(the compartment plus every compartment above it), hidden when policy collection is incomplete
or disabled. Administrators can ignore, close or reopen any finding (`docs/scanning.md`).
Mocked tests only.

## Cost visibility (2026-10-27)

Cost tab with monthly cost for 12 months by tenancy, service and compartment (tree with rolled-up
totals), read from the parent's Usage API (`request_summarized_usages`, reviewed read-only query
exception). Parent-only grant `read usage-report`. Mocked tests only; live gates: child tenancies
in parent data, `compartmentPath` format/depth and paging.

Additional live gates: `ListApiKeys` authorization under `read users` in every domain; the MFA,
federation, service-user and last-sign-in SCIM attributes; and `ListCategories` names.

## Review corrections: policy hierarchy and cost

Counts now require all expected active-compartment policy scopes and complete compartment discovery;
missing reads remain unknown. Hierarchy totals are unavailable for orphan subtrees while own counts
can remain visible when collected. Cost queries use compartment depth 6, with deeper costs aggregated
by OCI, and tenancy cost grouping uses OCIDs rather than display names. Regression cases cover all
four corrections, including same-name parent/child tenancies with separate currency totals.
