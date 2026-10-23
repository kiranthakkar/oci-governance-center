# Scan controls and scheduling

The Scan tab covers the enrolled parent organization. A full scan discovers children and
collects IAM inventory across every identity domain, governance datasets and Audit activity
from the parent and configured, unpaused children. Unconfigured and departed children are
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
every minute, so crash recovery waits at most ten minutes. Graceful shutdown drains active work while renewing its lease.

The tab shows the newest 50 requests with trigger, queued/running/completed/partial/failed/
interrupted status, UTC request/start/finish times and a sanitized result. A run is Partial when
collection coverage contains failed scopes; consult Coverage for the affected datasets. Scan
history follows configured retention (90 days by default). Failures appear in the application;
external notifications remain backlog.

Schedules and requests are fenced by organization generation. Successful parent replacement
clears the previous organization's schedule and jobs; incomplete onboarding leaves them intact.
Repairing credentials for the same parent retains schedule and history, interrupts old active
jobs and fences their workers. No scanner secrets are stored in schedule/job metadata.

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
