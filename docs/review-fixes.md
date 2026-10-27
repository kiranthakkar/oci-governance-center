# Implementation review fixes — 2026-10-09

> **Historical OSC review.** The fixes and test/module names below describe the removed runtime.
> They do not establish that current OGC implements backup/restore or the same Audit replay.
> Current capabilities and review corrections are in [implementation status](implementation/status.md).

These six local correctness issues were fixed with synthetic regression tests. No live OCI calls,
new dependencies, IAM permissions or mutating OCI operations were introduced.

| # | Issue | Fix | Regression coverage |
|---|---|---|---|
| 1 | Organization replacement could finish before the new parent and connections were saved, leaving an empty active organization after failure. | Construct the candidate first; install its parent and supplied connections in the same durable transaction as deletion, generation advancement and the committed journal phase. CLI secret cleanup preserves references owned by committed connections. | Candidate-install failure rolls back the old organization; interruption after commit recovers the complete candidate (`test_org_switch.py`). |
| 2 | Splitting a backward audit chunk oldest-first could advance the cursor past a failed newer interval. | Fetch and commit backward pieces newest-first; stop at the first gap so the next run retries it. Forward ingestion keeps oldest-first ordering. | A failed newer half leaves the cursor unchanged; retry stores the missing event before advancing (`test_audit_ingestion.py`). |
| 3 | Audit appends and retention could write or delete files during maintenance. | Audit batches hold the main database writer transaction across monthly commits and check maintenance/generation plus the ingestion scope lease. Backup holds the main database barrier through every file copy. Retention takes exclusive maintenance, drains workers, holds the barrier through deletion and clears cached database handles. | Writes refuse maintenance/revoked leases; maintenance waits for monthly commits; purge refuses concurrent maintenance and aborts on drain timeout; backup prevents purge during copying (`test_storage_sqlite.py`, `test_backup_restore.py`). |
| 4 | A failed scope discovery could be replaced by an old successful dependency snapshot, allowing incomplete policy collection to report success. | Require the latest dependency discovery to have published complete coverage; block failed/skipped dependencies within the current run. Keep old data for display, but never use it to certify completeness after a failure. | Compartment discovery failure blocks policy collection in the same run and later policy-only runs; fresh successful discovery restores collection (`test_collectors.py`). |
| 5 | Restore changed finding generation columns without updating hashed IDs or serialized models, causing duplicates and lost suppression. | Rebuild findings under the restored generation while preserving lifecycle fields; update serialized manifest generations. Choose a generation newer than both live and backed-up state. | Restore uses a generation newer than live state, updates serialized manifests, and recollection retains one finding, its original first-seen time and suppression (`test_backup_restore.py`). |
| 6 | Reconciliation repeatedly read the same recent chunks and never reached older late events. | Persist a separate reconciliation cursor with each complete interval; resume backward across runs/restarts and start another sweep at the retention cutoff. Forward/backfill checkpoints remain independent. | Budgeted sweeps survive reopen, recover an older late event, reach the cutoff and restart at the recent boundary (`test_audit_ingestion.py`). |

The related contracts remain in [control-plane §6.1](control-plane.md#61-coordinated-organization-replacement),
[storage §6.1](storage.md#61-full-backup-and-restore-contract), and
[audit recovery](delta-fetching.md). OCI capability gates Q1–Q6 remain open; mocked regression tests
establish local behavior, not OCI compatibility.
