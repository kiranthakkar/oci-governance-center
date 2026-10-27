# Data Collection — Design

> **2026-10-22:** This page contains historical design/implementation details.
> New enrollment/scanner contracts are in [AGENTS.md sections 6–7](../AGENTS.md#6-oci-integration--enrollment-application-access-and-scanner-trust);
> current code and release gates are in [implementation status](implementation/status.md).

**2026-10-15 update:** [Delegated tenancy scans](delegated-scans.md) supersedes older statements
that children never have connections or that refreshable UPST grants cannot run scheduled scans.
It defines encrypted grant storage, lifecycle, routing and live acceptance gates.


Status: **Design v0.2** (2026-10-08) · Owner: Kiran Thakkar
Scope: what OSC reads from the parent tenancy and every child tenancy, organized in **tiers**, and the
dashboards and findings each tier supports. Read with `AGENTS.md` §2 (security principles) and §6
(region and client rules), `docs/control-plane.md` (how OSC reaches each tenancy) and `docs/storage.md`
(where collected data lives).

### Decisions recorded (2026-10-08)
| # | Decision |
|---|----------|
| C1 | **OSC is a governance and observability tool** for an OCI Organization. It inventories what exists, shows observed access grants, checks that governance guardrails are in place and makes activity observable. Security-scanner features are out of scope (§8). |
| C2 | **Data is collected in tiers.** A tier is a scope of collected data plus the dashboards and findings built on it. Each tier includes all lower tiers. |
| C3 | **Permissions stay at `read all-resources`** (parent: `osc-parent-access`; children: Endorse/Admit) for now. A per-service least-privilege list is a later step (control-plane D7). |
| C4 | **Users and groups: minimal fields.** Users: user name, domain ID, OCID. Groups: name, domain ID, OCID, members. These limits apply to identity inventory; audit keeps the normalized principal, IP and user-agent fields listed below. |
| C5 | **Audit scope: all events**, every subscribed region of every tenancy. |
| C6 | Policy analysis (risky grants, CIS IAM mapping) and audit anomaly detection **stay in scope as Tiers 4 and 5**. |

---

## 1. Principles

- **Read-only.** Only `get_*`, `list_*`, `summarize_*`, `search_*` calls (AGENTS.md §2.1). The identity
  domain API is called with `list_*` only.
- **Field allow-lists.** Every collector keeps an explicit list of fields (`pick()` in `oci_clients/`);
  whole SDK objects are never stored. New fields need a design change here. Audit fields are limited
  to event ID/type/time, tenancy/region, principal ID/name/auth type, source IP, user agent, compartment,
  resource ID/type, action and response status. Request/response payloads, headers, credentials and
  free-form SDK bodies are excluded even when present in OCI Audit. No arbitrary raw JSON passthrough.
- **Same path for every tenancy.** Parent and children are read with the scan identity; children
  cross-tenancy through Endorse/Admit. No per-child credentials.
- **Region rules** (AGENTS.md §6): identity and Cloud Advisor in the **home region**; Cloud Guard in the
  **reporting region**; Audit in **every subscribed region**.
- **Snapshots vs streams.** Inventory datasets are complete snapshots per tenancy (added / modified /
  removed tracked in `record_changes`). Scope and completeness are explicit (storage §4.1). Audit is
  an append-only stream with a checkpoint per `(generation, tenancy, region)` and a durable interval
  ledger ([audit recovery](delta-fetching.md)). A partial collection never replaces its snapshot.
- **Coverage is reported, not hidden.** A source that can't be read (access denied, service not enabled,
  throttled past retries) produces a coverage finding and a `partial`/`failed` scan-run item.

---

## 2. Tiers at a glance

| Tier | Question it answers | New data collected | Dashboards |
|---|---|---|---|
| **1 — Inventory and oversight** | What exists, and which IAM grants and group memberships are observed? | compartments, policies, identity domains, users, groups, dynamic groups, region subscriptions, Cloud Guard status and problems, Security Zone membership, Cloud Advisor status and recommendations, audit events | organization tree; who is in which group and which policies grant it access; Cloud Guard on/off and open problems per tenancy; Cloud Advisor recommendations; activity volume per tenancy and region |
| **2 — Guardrail coverage** | Are the organization's governance controls in place in every tenancy? | Cloud Guard targets, Security Zone recipes, tag namespaces and tag defaults, compartment quotas, budgets and their alert rules, audit retention, audit export connectors, event rules, Organization governance rules | coverage gaps: compartments without a Cloud Guard target or Security Zone; tenancies without tag defaults, quotas or budgets; audit retention below standard; no audit export |
| **3 — Change over time** | How is the organization changing, and who changed it? | nothing new | drift (what changed between scans); policy, group-membership and compartment change history joined with the audit events that caused it; activity trends per tenancy and region |
| **4 — Policy analysis** | Which access grants are broader than they should be? | identity domain admin-role grants | risky-grant findings and CIS IAM mapping (AGENTS.md §7.3) |
| **5 — Activity analytics** | Is anything unusual happening? | nothing new (baselines derived from audit) | anomaly findings (AGENTS.md §7.4) |

The tier is a deployment setting (`OSC_COLLECTION_TIER`, default `1`, validated 1–5). Collectors and dashboards declare
their tier; the scheduler runs only collectors at or below it, and the UI shows only dashboards whose data
is collected and all required capabilities passed their release gates. A tier never implies complete
coverage. Tier 1 access views exclude identity-domain admin-role grants, which arrive in Tier 4; all
views show that limitation. Even Tier 4 is grant analysis, not a complete effective-permissions engine.
Lowering the tier stops the corresponding collectors and analyzers; historical data follows normal
retention and remains visibly dated. Findings from disabled tiers are not resolved by absence.

Implementation status (2026-10-09): Tier 1 collectors, the scan runner, audit ingestion, the
scheduler and the Tier 1 dashboards (`/coverage`, `/governance`, `/access`, `/compartments`,
`/activity`) are implemented with mocked tests. Tiers 2–5 are designed here but not built; setting a
higher tier today collects Tier 1 only.

---

## 3. Tier 1 — Inventory and oversight

| Dataset | API (SDK) | Region / scope | Record key | Fields kept | Kind |
|---|---|---|---|---|---|
| `identity.compartments` | `IdentityClient.list_compartments(compartment_id_in_subtree=True, access_level="ACCESSIBLE")` + root | home | compartment OCID | id, parent, name, description, lifecycle state, created | snapshot |
| `identity.policies` | `IdentityClient.list_policies` per compartment (no subtree option) | home | policy OCID | id, compartment, name, description, statements, lifecycle state, created, version date | snapshot |
| `identity.region_subscriptions` | `IdentityClient.list_region_subscriptions` | home | region name | region key/name, status, is home | snapshot |
| `identity.domains` | `IdentityClient.list_domains` **per compartment** (domains can live in any compartment; no subtree option) | home | domain OCID | id, compartment, display name, URL, home region, replica regions, type, lifecycle state | snapshot |
| `identity_domains.users` | `IdentityDomainsClient(service_endpoint=<domain URL>).list_users` per domain with `active`, MFA `mfaStatus`, `isFederatedUser`, `serviceUser` and `lastSuccessfulLoginDate` attributes (2026-10-22) | domain URL | `<domain OCID>/<user id>` | domain OCID, id, OCID, user name, active, MFA status, federated, service user, last successful sign-in | snapshot |
| `identity_domains.api_keys` | `IdentityDomainsClient.list_api_keys` per domain with default attributes (an explicit `id,ocid,user,meta` list was rejected with HTTP 400 live; 2026-10-22) | domain URL | API key id | id, OCID, owning user id/OCID, created. **Never** the key material or fingerprint; OCI API keys have no expiry | snapshot |
| `identity_domains.groups` | `IdentityDomainsClient.list_groups(attributes="displayName,ocid,members")` per domain | domain URL | `<domain OCID>/<group id>` | domain OCID, id, OCID, display name, members (value, OCID, type) | snapshot |
| `identity_domains.dynamic_groups` | `IdentityDomainsClient.list_dynamic_resource_groups(attributes="displayName,ocid,matchingRule")` per domain | domain URL | `<domain OCID>/<id>` | domain OCID, id, OCID, display name, matching rule | snapshot |
| `cloud_guard.configuration` | `CloudGuardClient.get_configuration` | home → gives reporting region | tenancy OCID | status, reporting region, self-manage resources | snapshot |
| `cloud_guard.problems` | `CloudGuardClient.list_problems(compartment_id_in_subtree=True, access_level="ACCESSIBLE")` | reporting | problem OCID | id, compartment, resource (id, type, name), region, risk level, detector, detector rule, labels, lifecycle state/detail, first/last detected | snapshot of open problems; resolved ones become `removed` |
| `security_zones.zones` | `CloudGuardClient.list_security_zones` | reporting | zone OCID | id, compartment, display name, recipe, lifecycle state | snapshot |
| `optimizer.enrollment` | `OptimizerClient.list_enrollment_statuses` | home | enrollment status OCID | status, status reason | snapshot |
| `optimizer.categories` | `OptimizerClient.list_categories(compartment_id_in_subtree=True)` | home | category OCID | id, name, description, lifecycle state | snapshot (own scope, so a failure does not block recommendations) |
| `optimizer.recommendations` | `OptimizerClient.list_recommendations(compartment_id_in_subtree=True)` | home | recommendation OCID | id, category, name, description, importance, status, estimated cost saving, resource counts (status → count), time created/updated | snapshot |
| `audit.events` | `LogSearchClient.search_logs` on `search "<tenancy OCID>/_Audit_Include_Subcompartment"`; fallback `AuditClient.list_events` per compartment | **every subscribed region** | OCI event ID | normalized `AuditEvent` (AGENTS.md §5) | stream, checkpoint per (generation, tenancy, region) |

`cost.monthly` (2026-10-27) is read once per scan from the **parent** with
`UsageapiClient.request_summarized_usages` (MONTHLY, COST, current month plus 11 previous, grouped by
`tenantId`, `service`, `compartmentId`, `compartmentPath`, `compartment_depth=6`; the API accepts at
most four groupBy keys, so tenancy names come from OGC's tenancy list). It keeps month, tenant ID,
service, compartment ID and path, computed amount and currency; no
resource IDs or tags. Requires `read usage-report` in the parent only. Depth is limited to 6
(root is depth 1); costs below that depth are aggregated into their depth-6 ancestor.

`identity_domains.*` datasets are read from each tenancy's default identity domain unless the
tenancy's collection settings enable all domains; Cloud Guard, Cloud Advisor, identities,
policies and Audit can each be disabled per tenancy. Disabled datasets are not read and are not
coverage gaps (`docs/scanning.md`, 2026-10-27).

Notes:
- **Users and groups.** The domain ID (SCIM `id`) is not the OCID. Audit events and IAM policies refer to
  principals by OCID, so both are kept. Policies may also name a group by OCID (`group id ocid1…`).
  Large groups: membership enumeration must pass Q5. Truncated or unverified member lists mark
  the group dataset partial and cannot replace a complete snapshot or imply absence of membership.
- **Identity domains vs. legacy IAM.** The previous `identity.groups` / `identity.dynamic_groups` datasets
  (IAM API, Default domain only) are replaced by the domain-scoped ones above.
- **Cloud Advisor across the organization.** `list_recommendations` accepts `include_organization` and
  `child_tenancy_ids`. If the parent can read child recommendations that way, one call could replace
  per-child calls (*verify* in the POC); until then, read each tenancy itself.
- **Audit volume.** All events, including reads, is by far the largest dataset. Size it per tenancy during
  the POC. First collection backfills at most `OSC_AUDIT_BACKFILL_DAYS` (default = OSC's audit
  retention, 90 days). Log Search queries are bounded, paginated to
  exhaustion and checked for completeness. Source time-window, result and rate limits are a release
  gate (Q2). First-run/backfill, delayed events and crash recovery follow [delta-fetching.md](delta-fetching.md).

**Findings raised in Tier 1** (each gets `docs/detections/<rule_id>.md` and tests when implemented):

| Rule (proposed ID) | Severity | When |
|---|---|---|
| `GOV-CG-001` Cloud Guard not enabled | HIGH | `cloud_guard.configuration.status != ENABLED` |
| `GOV-ADV-001` Cloud Advisor not enabled | MEDIUM | no active enrollment |
| `CG-PROBLEM` Cloud Guard problems | mapped from risk level (`models/severity.py`) | one finding per open problem, `source=cloud_guard`; Security Zone violations (identified with `list_problems(problem_category="SECURITY_ZONE")`) use `source=security_zone` |
| `ADV-RECOMMENDATION` Cloud Advisor recommendations | mapped from importance, one step lower (`models/severity.py`) | one finding per pending recommendation, `source=advisor` |
| `OSC-ACCESS-002` source not collected | HIGH | a Tier-1 dataset failed or was partial for a tenancy/region |

---

## 4. Tier 2 — Guardrail coverage

| Dataset | API (SDK) | Region | Record key | Fields kept |
|---|---|---|---|---|
| `cloud_guard.targets` | `CloudGuardClient.list_targets(compartment_id_in_subtree=True)` | reporting | target OCID | id, target resource (id, type), recipes attached, lifecycle state |
| `security_zones.recipes` | `CloudGuardClient.list_security_recipes` | reporting | recipe OCID | id, display name, policies (IDs), lifecycle state |
| `identity.tag_namespaces` | `IdentityClient.list_tag_namespaces(include_subcompartments=True)` | home | namespace OCID | id, compartment, name, is retired |
| `identity.tag_defaults` | `IdentityClient.list_tag_defaults` per compartment | home | tag default OCID | id, compartment, tag definition, value, is required |
| `limits.quotas` | `QuotasClient.list_quotas` | home | quota OCID | id, compartment, name, statements |
| `budget.budgets` | `BudgetClient.list_budgets` + `list_alert_rules` | home | budget OCID | id, target (compartment/tag), reset period, alert rule count and thresholds — *no spend figures* |
| `audit.configuration` | `AuditClient.get_configuration` | home | tenancy OCID | retention period (days) |
| `sch.service_connectors` | `ServiceConnectorClient.list_service_connectors` per compartment | every subscribed | connector OCID | id, compartment, display name, source (log sources), target kind, lifecycle state |
| `events.rules` | `EventsClient.list_rules` per compartment | every subscribed | rule OCID | id, compartment, display name, condition, is enabled, action kinds |
| `governance.rules` | `GovernanceRuleClient.list_governance_rules`, `list_tenancy_attachments`, `list_enforced_governance_rules` (*verify* where each is called: parent vs child) | home | rule OCID | id, type, display name, template summary, attached tenancies, lifecycle state |

**Findings raised in Tier 2** (proposed): compartment holding resources with no Cloud Guard target
(`GOV-CG-002`); Cloud Guard target missing on the tenancy root (`GOV-CG-003`); compartment not in any
Security Zone where the organization standard requires one (`GOV-SZ-001`, standard configurable);
audit retention below the configured standard (`GOV-AUD-001`); no connector exporting audit logs
(`GOV-AUD-002`); no event rule for IAM changes (`GOV-EVT-001`); tenancy without required tag defaults
(`GOV-TAG-001`); no quota policy (`GOV-QTA-001`); no budget with an alert rule (`GOV-BUD-001`). The
organization standards (retention days, required tags, which compartments need zones) are OSC settings.

---

## 5. Tier 3 — Change over time

No new collection. Built on:
- `record_changes` (`docs/storage.md` §3.3): added / modified / removed per dataset per scan.
- `audit.events`: the event that caused a change (matched on resource OCID and time).

Dashboards: drift since a date; policy statement diffs; group membership changes; compartment moves and
deletions; Cloud Guard and Security Zone configuration changes; activity trends. History depth follows
retention (90 days default; `record_changes` can be set longer per dataset).

---

## 6. Tier 4 — Policy analysis

Collects one more dataset:

| Dataset | API (SDK) | Record key | Fields kept |
|---|---|---|---|
| `identity_domains.admin_role_grants` | `IdentityDomainsClient.list_grants` filtered to admin app roles (*verify* filter) | `<domain OCID>/<grant id>` | grantee (id, OCID, type), app role (name), granted at |

Domain admin roles grant identity power outside IAM policies, so they belong next to the policy analysis.
Rules are the AGENTS.md §7.3 set (risky grants, `any-user`/`any-group`, IAM-resource `manage` outside
IAM admins, broad Endorse/Admit, broad dynamic-group rules combined with `manage`, root-level policies),
with a verified CIS reference where applicable in `cis_refs`; custom rules must not invent CIS
mappings. Record benchmark version with the rule. Unparseable statements → `POLICY-PARSE-001`.

---

## 7. Tier 5 — Activity analytics

No new source collection. Daily summaries are used only for activity trends. Short-window rules use
minute-level candidate indexes in osc.db plus bounded reads of exact event timestamps in monthly audit
databases. Candidate rows include tenancy, region, principal OCID, source IP, UTC bucket, event count,
first/last event time and event-file references. An analyzer loads exact events for the candidate window,
including adjacent buckets/months and permitted tenancies; a shared bucket alone is not an anomaly.

Rule definitions specify required event types/fields, UTC window and boundary semantics, threshold,
subject identity, required coverage and recurrence key. Cross-tenancy principal matching uses the same
principal OCID or an explicit verified identity mapping; matching usernames across domains is unsafe.
Source-IP correlation remains a separate signal and does not establish a person's identity.

| Rule family | Required inputs / evidence |
|---|---|
| IAM/control changes | Action/event type, time, principal, resource, response status; distinguish attempts from successful changes. |
| Sign-in failure bursts | Verified authentication-failure event types, exact timestamps, subject/IP and status. If tenancy Audit lacks them, the rule is unsupported; do not invent a new source silently. |
| New IP/user agent or unusual region | Per-principal historical observations and sufficient complete baseline coverage; exclude the event being scored from its own baseline. |
| Off-hours privileged activity | Exact event times, configured business calendar/IANA timezone (including DST), and justified privilege attribution from policy/admin-role evidence. |
| Cross-tenancy short-window activity | Exact timestamps, verified subject/IP mapping, per-region/tenancy interval completeness and deterministic occurrence identity. |

Baselines use a proposed 30-day lookback, with at least 7 complete days before novelty scoring; these
are OSC defaults to validate in the POC, not OCI guarantees. Business hours are customer-configured;
without a calendar the off-hours rule is disabled with an explanation. Country-based detection is
deferred until an approved geography source, privacy treatment and dependency are designed. Cap
baseline/candidate cardinality per tenancy and report exceeded limits as partial analysis, never healthy.

Late events invalidate affected candidates/baselines and rerun deterministic windows using storage
§3.4 identities. Derived state records the rule version, source checkpoints, covered period and warmup
state. Gaps suppress healthy conclusions; detectors may emit positive evidence with a partial-coverage
label. Candidate indexes retain the analysis window and are reproducible from audit; pruning/restore
must not leave summaries claiming coverage for missing event files. Rules remain the AGENTS.md §7.4
set and each needs a specification plus positive/negative and boundary tests before enabling it.

---

## 8. Out of scope (for now)

- Security-scanner data: credential hygiene (MFA status, API key / token age), expiring keys or
  certificates, firewall / network exposure, bucket exposure, vulnerability scanning and Data Safe results.
- Workload, service and VCN flow-log contents; metrics.
- Creating or enforcing Security Zones (or anything else) from the parent — OSC stays read-only.

---

## 9. Schedule (proposal)

| Data | Default interval |
|---|---|
| Audit events | every 15 minutes, per tenancy and region |
| Cloud Guard problems, Cloud Advisor recommendations | hourly |
| Identity (compartments, policies, domains, users, groups, dynamic groups) | every 6 hours |
| Tier 2 guardrail datasets | daily |

Work runs in `(tenancy, region, dataset)` units on the bounded thread pool (AGENTS.md §6). Every unit is
a `scan_run_items` row with generation, full scope, status, counts, completeness evidence and error.
Prevent overlapping scope runs across processes using leases. Schedule forward audit collection ahead
of backfill; bound queue depth and disk/memory budgets. Apply rate limits per service/tenancy and
report retry exhaustion. No dataset job may bypass maintenance or generation fencing.

---

## 10. Capability release gates

| ID | Question | Plan |
|---|---|---|
| Q1 | Identity-domain access from the scanner, including child domains | Required gate: prove Default and named-domain list-users/groups/dynamic-groups with a child-local delegated UPST (see `delegated-scans.md`). Cross-tenancy failures do not prove local-domain access. Confirm minimal field projection and principal OCID mapping. Report unsupported/partial scope without automatic tier downgrade or parent-identity fallback. |
| Q2 | Log Search windows, paging, completeness, rate limits and audit event ID uniqueness | Required gate: record SDK/API version and sources, exhaust multi-page results, test dense/same-timestamp intervals and controlled retries. SDK documents a continuation page; numeric source limits must be verified rather than copied from Console UI. Apply delta-fetching.md before release. |
| Q3 | Audit volume, late arrival and operational capacity | Required gate: measure representative peak events, bytes/day, backfill duration, late-event delay, writer latency, disk reserve, backup/restore time and summary cost. Configure resource caps; reject unsustainable deployments or report capacity gaps. |
| Q4 | Parent Cloud Advisor organization-wide reads | Optional optimization gate. Keep per-tenancy reads as the baseline; only replace them after proving child attribution, equivalent completeness and source identity. |
| Q5 | Complete membership for large groups | Required gate: exceed one membership page, compare an independently known count/set, prove paging for each supported domain type, and test truncation failure. No inferred empty memberships. |
| Q6 | Governance-rule placement and API permissions | Required Tier-2 gate: verify parent/child call placement, record scope and permission references, and test inaccessible children as partial coverage. |

For every gate record scanner method, SDK version, authorized sandbox identity (sanitized), date,
expected/actual coverage and pass/fail evidence. Mark a gate passed only after its evidence exists;
mocked tests alone do not prove OCI compatibility. No live POC is authorized by this document.

A source capability has `untested`, `supported`, `unsupported` or `error` status per relevant scope.
Collectors/dashboards are enabled only when their dependencies are supported; capability failure is
visible alongside the configured tier. Recheck after principal, policy, domain or region changes.
Production deployment requires the architecture acceptance gates as well as the selected tier's
capability gates. The current v0.1 control-plane smoke test is not a Tier-1 certification.

## References

- [Oracle cross-tenancy region/policy prerequisites](https://docs.oracle.com/en-us/iaas/Content/Identity/policieshow/iam-cross-domain.htm)
- [Oracle LogSearchClient paging contract](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/loggingsearch/client/oci.loggingsearch.LogSearchClient.html)
