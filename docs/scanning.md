# Scan controls and scheduling

The Scan tab covers the enrolled parent organization. A full scan discovers children and
collects what each tenancy's collection settings enable (by default IAM inventory from the
selected scanner identity domain, policies, governance datasets and Audit activity) from the parent and
configured, unpaused children. Unconfigured and departed children are
excluded. Existing dataset permissions, partial coverage and read-only OCI boundaries apply.

`ogc_admin` can start an on-demand scan, save a recurring schedule and disable recurrence.
`ogc_viewer` can inspect the schedule, next run and scan history. All write actions require
fresh administrator membership verification, CSRF protection and the current organization.

Only two recurring frequencies are supported:

- **Daily:** choose a time of day and timezone.
- **Weekly:** choose a weekday, time of day and timezone.

There is one optional schedule per organization; recurrence is disabled until saved. Times
use a named IANA timezone, with UTC as the initial default. Next-run timestamps are stored in
UTC and displayed in the selected timezone. During daylight-saving transitions a skipped
clock time runs at the next valid local minute; a repeated clock time runs once, at its first
occurrence. Saving a schedule replaces it and calculates the next future occurrence.
Disabling recurrence preserves queued work and history.

The web server queues requests in SQLite without performing OCI collection in the request.
Run `ogc scheduler` separately with the same configuration and data directory. Its polling
interval is five seconds. The Scan tab reports the worker offline after 30 seconds without
a heartbeat; queued work remains durable until the worker returns. Calendar schedules replace
the previous fixed IAM, governance and Audit collection intervals. New parent enrollment and
child configuration changes still automatically request collection.

Only one full organization scan runs at a time. Repeated manual requests and scheduled
occurrences coalesce with queued or running work. Configuration changes can queue one follow-up
behind active work. After downtime, missed occurrences combine into one catch-up scan and the
next occurrence advances into the future. Parent credential failures block collection; an overdue
schedule is retained for recovery after credential repair.

Workers claim jobs atomically across processes and renew their job lease while scanning. An
expired job is marked Interrupted; operators can retry. Existing per-tenancy collection leases
must expire or release before another full scan starts. Live scans renew these ten-minute leases
every minute. Tenancy leases carry the scheduler's identity: when a stopped or restarted scheduler's
job lease expires (two minutes), its job is marked Interrupted and its tenancy leases are released
in the same step, so the next queued scan starts within about two minutes. Leases from other
processes, such as a CLI `ogc scan`, still run to their own expiry. While a queued scan waits for
leases, the Scan tab says so and shows when it will start at the latest. Graceful shutdown
requests cancellation at safe points while the worker maintains its active job lease.

The tab shows the newest 50 requests with trigger, queued/running/completed/partial/failed/
interrupted status, UTC request/start/finish times and a sanitized result. A run is Partial when
collection coverage contains failed scopes; consult Coverage for the affected datasets. Scan
history follows configured retention (90 days by default). Failures appear in the application;
external notifications remain backlog.

Schedules and requests are fenced by organization generation. Successful parent replacement
clears the previous organization's schedule and jobs; incomplete onboarding leaves them intact.
Repairing credentials for the same parent retains schedule and history, interrupts old active
jobs and fences their workers. No scanner secrets are stored in schedule/job metadata.

## Collection settings per tenancy (2026-10-27)

The Scan tab's **What to collect** card holds one setting set per tenancy (parent and each
configured child). `ogc_admin` changes them with CSRF protection and fresh membership
verification; viewers see them read-only. Each change is recorded as a `scan_settings_changed`
control event. A tenancy without saved settings uses the defaults below; successful parent
replacement clears all settings.

| Setting | Default | Datasets |
|---|---|---|
| Cloud Guard | on | `cloud_guard.*`, `security_zones.zones` |
| Cloud Advisor | on | `optimizer.*` |
| Identities | on | `identity_domains.users/groups/dynamic_groups/api_keys` |
| Identity domains | **selected scanner domain only** | which domains identities are read from; "All identity domains" reads every active domain |
| Policies | on | `identity.policies` |
| Audit | on | `audit.*` and the activity analysis |
| Cost (parent row only) | on | `cost.monthly`: organization cost from the parent's Usage API; needs `read usage-report` in the parent |

Compartments, subscribed regions and the identity-domain list are always collected because
scoping, Audit and selected-domain detection depend on them. The scanner domain is the domain
verified at enrollment or Configure (matching the configured domain OCID).

A disabled dataset is not read and publishes no coverage scope, so it is never an
`OGC-ACCESS-002` gap and never makes a child Partial. Data and findings already stored for it are
kept and not re-evaluated; tabs name the tenancies whose collection is disabled. Analysis scopes
follow the settings: `analysis.policy` needs Policies; `analysis.identity`, `analysis.api_keys`
and `analysis.activity` need Identities (activity also needs Audit). Policy analysis without
identities, or with only the selected scanner domain read, treats subjects in unread domains as unknown:
they are never reported stale or unused, and the Identity → Policies view lists them as "Not
analyzed". The scanner's read grants are unchanged and remain tenancy-level, so enabling all
domains needs no new setup.

## Scanner trace (2026-10-27)

The scanner process logs one line when each collection phase of a tenancy starts and one when it
ends, for example `tenancy: ktdemos Cloud Guard scan started` and `tenancy: ktdemos Cloud Guard scan
completed`. Phases are Compartment, IAM policy, Identity, Cloud Guard, Cloud Advisor, Cost Analysis
(parent only) and Audit, as enabled in the tenancy's collection settings. A phase with gaps ends
"completed with N incomplete scopes (see Coverage)", and each incomplete dataset is logged with its
error; an aborted phase logs "scan failed". Lines contain no identifiers, records or tokens.

Audit history logs progress every 24 collected hours, for example `tenancy: ktdemos Audit scan:
audit.backfill us-sanjose-1 collected through 2026-08-16 08:56 UTC (24 of 168 hours this scan)`.
Backfill reads every compartment for every hour, so it is the slowest phase.

**Stopping the scanner** (`ogc scheduler`, with or without `--once`). The first Ctrl-C or SIGTERM
asks the running scan to stop after its current OCI request; everything already read is kept and
an Audit hour is committed only when complete. Policy and identity analysis still run and fail
closed on inputs that were not read. The job is marked interrupted only if a tenancy actually
ended early (a parent-key failure is still reported as a failure), and the next scan continues from
the saved progress. A second Ctrl-C marks the job interrupted, releases this worker's tenancy
locks and exits immediately.

Coverage and scan-detail errors for OCI service failures read, for example,
`OCI read failed (HTTP 400 InvalidParameter) in request_summarized_usages. OCI says: <message>.
Check local grants and service availability. Request ID: <id>.` OCI's message is sanitized and
bounded (`collectors/inventory.py` `oci_message`).

## Finding triage (2026-10-27)

`ogc_admin` can act on any open finding, including coverage findings, from the Cloud Guard,
Identity → Policy analysis and `/data/findings` tables:

- **Ignore** — accepted or suppressed. The finding keeps its evaluation history but shows as
  Ignored across later scans until an administrator reopens it. If OCI no longer reports it, it
  shows Resolved; if it reappears, it is Ignored again.
- **Mark closed** — the administrator states it is fixed. It shows as Closed until a later
  complete evaluation still detects it, which reopens it automatically.
- **Reopen** — removes the decision.

Decisions (state, actor, time and an optional reason of at most 500 characters) are stored apart
from evaluated findings in `finding_triage`, so rescans cannot drop them, and each is recorded as a
control event. Every reader, including exports, sees the effective status
(`open | resolved | ignored | closed`) and the decision. Finding lists show Open by default; the
status filter shows Ignored, Closed, Resolved or all. Parent replacement clears triage, and
retention removes decisions for purged findings. Triage never changes anything in OCI.

## Coverage findings and scanner diagnostics in the UI

Every incomplete scope is flagged as an open `OGC-ACCESS-002` finding, labeled **Scanner coverage
gap** in Findings. It resolves only after that same scope completes successfully. These flags
identify collection gaps rather than a demonstrated resource security violation. Coverage offers
an incomplete-only filter, and finding links open the affected tenancy's current diagnostics.

Each Scan history row links to **View scan details**. Administrators and viewers may inspect
status, trigger, times, dataset, tenancy, domain/region, last success and recorded failure reason.
Incomplete scopes appear first. The count covers the organization and includes unresolved earlier
attempts; the details distinguish attempts during this run from earlier recorded attempts.

Completing a job atomically snapshots scope diagnostics with the owned job lease and organization
fence. Later successful collection does not rewrite that historical snapshot. Active jobs show
explicitly labeled live organization coverage. Older jobs and interrupted jobs without a snapshot
link to current Coverage without presenting it as historical results. Snapshot retention follows
scan history, and successful parent replacement clears both. The UI does not expose terminal logs,
raw troubleshooting payloads, bearer tokens, client secrets or tracebacks.

## Interpreting historical Audit coverage

An `audit.backfill` message saying **“Audit history is still being collected through <timestamp>”**
records successful progress up to a durable cursor. Subsequent scans continue toward the fixed
point where forward reads began, with a default budget of 168 hours per region per scan
(`OGC_AUDIT_BACKFILL_HOURS`). `audit.events` collects current activity separately, and
`audit.reconcile` re-reads the previous checkpoint's 24-hour window for late deliveries.
Targets are five minutes behind the current clock.

Backfill progress currently uses the same incomplete status and OGC-ACCESS-002 finding as actual
API failures. The UI has no separate Backfill-in-progress state. Read the dataset and error text
before treating a Partial scan as a permissions failure; an actual failed API read carries a safe
error diagnostic. A finished scan can retain unresolved gaps from previous attempts. Ignoring or
closing a finding does not change the underlying Coverage status or authorize collection.

See the [operator guide](operations.md) for the complete settings table, queue/authentication
troubleshooting, storage boundaries and startup/recovery instructions.
