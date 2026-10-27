# OGC implementation status and acceptance

Reviewed against the source on **2026-10-27**. Specifications are in [AGENTS.md sections 6–7](../../AGENTS.md).
This page describes implemented behavior; synthetic test success is not live OCI certification.
Use the [operator guide](../operations.md) for setup, settings, storage and troubleshooting.
Historical OSC designs are identified in the [documentation index](../README.md).

## Implemented capabilities

| Area | Current behavior |
|---|---|
| Parent enrollment | Setup-password-protected wizard; encrypted retry drafts; scanner verification plus final human administrator sign-in |
| Human access | Parent Default-domain OAuth Code + PKCE; only `urn:opc:idm:__myscopes__`; signed user access-token validation and Asserter group-ID checks; no ID-token dependency |
| Authorization | `ogc_viewer` reads organization-wide data; `ogc_admin` also manages configuration/triage; membership rechecked every five minutes and before writes |
| Scanner identity | Parent API key for parent reads and JWT issuance; child confidential client HTTP Basic authentication for JWT-to-UPST; worker-local bound keys and token renewal |
| Child enrollment | URL plus child app client ID/secret; automatic home-region/domain discovery; username lookup for one active `ogc` service user; child-tenancy identity validation |
| Setup packages | Administrator-applied Terraform/Resource Manager bundles and manual guides; child service user/group/policies/app/trust; no child API keys; exact unquoted `sub eq ogc` rule for subject `ogc` |
| Collection | IAM compartments/regions/domains/policies; identity users/groups/dynamic groups/API-key metadata; Cloud Guard/Security Zones; Cloud Advisor; Audit; parent organization cost |
| Collection settings | Per tenancy; enabled by default, identities from Default domain only unless All identity domains is selected; cost is parent-only |
| Scan controls | Separate worker, durable queue, on-demand organization scans, optional daily/weekly timezone-aware recurrence, coalescing, heartbeat and lease recovery |
| Diagnostics | Coverage findings, dataset/tenancy/region filters, scan details and finish-time scope snapshots; no raw terminal logs or credentials in UI |
| Finding triage | Administrator Ignore/Mark closed/Reopen decisions; local history and control events; effective state visible in views and exports |
| Resource organization | Compartment tree; own/ancestor statement counts require complete expected policy coverage; unknown ancestor chains suppress hierarchy totals |
| Cost | Parent Usage API, current plus eleven previous months; tenancy/service/compartment views, currencies separate, grouping by tenancy OCID; compartment depth 6 aggregates deeper costs |
| Tier 4 analysis | Tolerant policy parser and POL-*/IAM-* rules in four fail-closed analysis scopes; identities in unread domains remain unknown |
| Organization lifecycle | Child pause/resume/departure, verified parent key repair, fresh parent replacement with generation/revision fencing and journaled cleanup |
| Storage | SQLite scoped snapshots/coverage/findings/settings/history, encrypted credentials and server sessions, separate monthly Audit databases and retention |

Navigation: Overview, Coverage, Cloud Guard, Cloud Advisor, Cost, Resource organization, Identity
(users, groups, dynamic groups, policies, policy analysis), Activity, Scan and Configuration.
The generic Findings and Inventory pages remain at `/data/findings` and `/data/records`, with JSON
exports, but are not separate navigation tabs. Configuration and mutation controls require admin access.

## Authentication and credential handling

The parent login app is separate from each child exchange app. A human access token is validated
against trusted issuer/JWKS, expiration, identity-domain API audience, configured client ID/name,
`tok_type=AT` and `sub_type=user`. Asserter receives it as bearer authorization with
`subjectType=user` and `includeMemberships=true`. The response must bind to verified `user_id`
or `sub`/`sub_mappingattr`; membership uses group IDs, not display names. An expired token or
legacy session requires fresh sign-in. Scanner failure does not authorize bypassing human checks.

Parent JWT validation accepts consistent username, SCIM ID or OCID subject mapping to the parent
`ogc` identity selected by its configured OCID. Child Configure discovers `ogc` by username and
requires one active service user before accepting its discovered OCID. Child secrets are encrypted
separately from child metadata and saved atomically after verification. Blank secret reuse is limited
to the same client ID and domain URL; failed replacement credentials preserve the existing values.
No token-controlled key URLs are followed. Raw bearer-token debug logging has been removed, including
the old `OGC_DEBUG_TOKEN_EXCHANGE` option. Normal logs use safe stages, status, categories and fingerprints.

## Audit progress and shutdown

Audit reads use `AuditClient.list_events` for each accessible compartment and READY subscribed
region. Forward collection catches up from its checkpoint with a 15-minute overlap, targeting
five minutes behind now. Reconciliation re-reads the 24 hours preceding the previous forward
checkpoint. Backfill processes up to `OGC_AUDIT_BACKFILL_HOURS` (default 168) per region per scan
toward the fixed point where forward collection began. Event files commit before progress;
events are deduplicated by region/event ID. Late events older than the reconciliation window need
a separately designed replay mechanism.

Unfinished backfill is currently represented as incomplete coverage and `OGC-ACCESS-002`, even
when reads succeed. “History is still being collected through” describes a cursor, not a denied
read. The UI does not yet have a distinct Backfill-in-progress state. Other failed coverage scopes
preserve their last complete inventory snapshots and provide safe diagnostics. A finished worker
can therefore leave Partial coverage.

Scheduler shutdown supports a safe first signal and an immediate second signal, including `--once`.
The first requests cancellation after current reads; complete Audit hours stay committed and an
incomplete hour is retried. The second interrupts owned jobs and releases worker tenancy locks.
A crash recovers through the expiring job lease; standalone CLI leases have their own expiry.
See [scanning](../scanning.md) for queue, lease, retention and triage contracts.

## Enforcement and verification

The SDK boundary exposes exact reviewed operations. `UsageapiClient.request_summarized_usages`
is an explicitly reviewed read-only POST query exception to the normal read-prefix rule. Raw HTTP
is confined to authentication modules. Collection publishers check organization generation, pending
cleanup, key suspension, child revision and owned unexpired leases inside write transactions.
Incomplete analysis resolves no prior findings. Complete matching-scope evaluation drives resolution;
triage determines the effective displayed state without changing OCI resources.

Validation performed in this checkout includes lint, formatting, strict types, network-blocked
unit/integration-style HTTP tests, cryptographically signed token tests, real SDK construction with
synthetic keys, parser/lifecycle tests, scheduling/DST, cost grouping, missing policy scopes/orphan
hierarchies, cancellation/recovery and storage fencing. Test counts change with the suite; the last
command output is the source of truth, not a pinned count in this page.

Parent/child bundles have passed Terraform JSON formatting and schema validation using Terraform
1.13.5 and pinned OCI provider 8.10.0. Those checks do not constitute plan/apply or live token-exchange
certification. Browser enrollment checks use isolated Chrome and synthetic identity endpoints.

## Remaining live acceptance gates

1. Prove parent API-key-to-JWT issuance and child confidential-client JWT-to-UPST exchange with the
   reviewed exact-subject trust. Check issuer/claims, signature binding, expiration and isolated renewal.
2. Verify administrator-applied setup, service-user attributes, OAuth app grants/activation, provider
   behavior, existing-resource import and confidential client binding/secret rotation.
3. Verify human access-token audience/client binding, Asserter permissions, group completeness,
   revocation/downgrade and repair access while the scanner key is invalid.
4. Confirm tenancy-level read grants across existing/new identity domains when enabled, SCIM pagination,
   large memberships, `ListApiKeys` authorization and MFA/service/federation/sign-in attributes.
5. Exercise collector grants and pagination, subscribed/reporting/home regions, disabled services,
   Advisor category names and Audit delivery/late-event behavior at representative volumes.
6. Confirm cost data covers the intended billed children, four-key grouping, paging, depth-6 path
   semantics, currency handling and renamed/deleted compartments. Billing membership is not assumed
   identical to organization discovery membership.
7. Rehearse key/trust revocation, pause/resume, child departure, parent replacement, shutdown/restart,
   disk capacity, SQLite locking, retention and cleanup failure recovery.
8. Validate manual Console steps. Where the UI lacks a trust/service-user control, use the reviewed
   administrator-applied Terraform/Resource Manager flow; a complete click-only path is not certified.

## Limitations and backlog

Tier 2 guardrail collectors, full Audit-to-drift attribution, identity-domain administrator role
grants and Tier 5 anomalies are not implemented. Observed statement counts and analysis are not
complete effective permissions: where-conditions are recorded rather than executed and aliases
are not substituted. Coverage findings intentionally identify collection uncertainty.

No automated deployment, multiple active parents, per-tenancy viewer restrictions, or external
notifications. No full backup/restore CLI, versioned schema migration runner, key-rotation migration,
explicit Audit gap ledger/lost-file repair or replay beyond the reconciliation window. Replacement
cleans managed old-organization artifacts but cannot recall files already downloaded elsewhere.

Direct dependency pins live in `pyproject.toml` and transitive resolutions in `uv.lock`. Existing
Authlib/Starlette HTTP-client deprecation warnings are visible; they are not suppressed.
