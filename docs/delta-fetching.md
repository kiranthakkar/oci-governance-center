# Audit ingestion and delta recovery

Status: Required design, 2026-10-08; implemented 2026-10-09 in `collection/audit.py` and
`SqliteDataStore.commit_interval` with mocked tests. Source limits, delivery latency and event-ID
uniqueness (gate Q2) and capacity (Q3) still need an authorized non-production tenancy.
Related: [storage](storage.md), [collection](collection.md), [architecture](architecture.md).
Inventory uses full scoped snapshots initially; incremental inventory fetching is deferred. This
contract resolves audit stream checkpoints now rather than postponing correctness to a future design.

## 1. Scope and checkpoints

One checkpoint covers `(organization_generation, tenancy_ocid, audit.events, region)`. Its value is
`complete_through`, the end of a contiguous, fully fetched and durably stored interval, not the maximum
observed event timestamp. Record source, query version, run ID, actual coverage start, overlap and gap
intervals. A successful empty interval advances the checkpoint only after all pages complete.

A per-scope lease serializes runs. Fence stale workers by organization generation and lease token at
commit time. A delayed old run cannot replace a newer checkpoint. Backfill and forward collection use
separate cursors so historical work cannot move the forward cursor backwards or declare a gap filled.
Split pieces follow the cursor direction: forward oldest-first, backward newest-first; a failure stops
progress before the gap. Audit batches hold the main database writer transaction through their
monthly commits, fencing maintenance and validating the ingestion scope lease before writing.

## 2. Fetch protocol

1. Validate region accessibility and acquire the scope lease for the current organization generation.
2. Choose a UTC interval ending before a configurable ingestion delay (proposed default 5 minutes).
   Re-read an overlap (proposed default 24 hours), clamped to retention and the source's availability.
   Both settings require POC tuning; they are not guarantees about OCI delivery latency.
3. First collection backfills at most the effective audit retention (90 days by default), in bounded
   chunks. Record the actual covered start. Prioritize forward ingestion so backfill does not starve
   current activity; bound memory, queue depth and per-tenancy disk use.
4. Use SDK pagination generators and the retry strategy. SearchLogs supports a continuation page;
   consume it to exhaustion. Validate query/result completeness, not just HTTP success. When an API
   truncates results or cannot prove completeness, subdivide the time interval, keeping boundary
   overlap; if a minimal interval remains incomplete, record a gap and do not advance across it.
5. Normalize only allow-listed AuditEvent fields. Partition by validated event time in UTC, not the
   fetch time. Stream bounded batches into all affected monthly files; de-duplicate by event ID within
   each tenancy. Validate ID uniqueness in the POC; if it is regional, use `(region, event_id)` instead.
6. Acknowledge a batch only after its transaction commits. After every page/batch in the interval is
   durable, commit the ingestion ledger, checkpoint and successful scan-run item together in osc.db,
   under the generation/lease fence. Failures retain the last complete checkpoint and raise coverage.

The implementation must enforce event durability before checkpoint durability across separate files.
Use `synchronous=FULL` for audit batch writes and checkpoint transactions; NORMAL is insufficient for
this cross-file power-loss contract. Do not advance while a writer queue still has unacknowledged work.

Reference: [Oracle LogSearchClient API](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/loggingsearch/client/oci.loggingsearch.LogSearchClient.html).
Query window and rate limits remain a release gate; do not treat Console UI limits as API limits.

## 3. Recovery and late events

| Interruption | Recovery |
|---|---|
| Before any batch commit | Retry the interval from the last complete checkpoint. |
| After some/all audit commits, before checkpoint commit | Replay the interval; committed event IDs make replay idempotent. |
| After checkpoint commit | Resume with overlap; all preceding batches were already durable. |
| Pagination/source error | Keep committed events, mark interval partial, keep the checkpoint behind the gap. |
| Lost/corrupt monthly file or partial restore | Invalidate affected coverage/checkpoints; rebuild from the earliest missing retained interval. |
| Organization generation changed | Reject writes/checkpoints and cancel the old run. |

Run periodic reconciliation across the retained analysis window (proposed daily, rate-budgeted), rather
than relying only on the overlap. A separate `audit.events#reconcile` cursor records each complete
backward interval atomically with its ledger entry. Runs and restarts resume the sweep; reaching the
moving retention cutoff starts a new sweep at the overlap boundary. Reconciliation never changes
forward or backfill checkpoints. Late arrivals beyond overlap reopen affected summary buckets and
rerun anomaly rules using stable finding identities. Reconciliation emits a coverage finding if data
is no longer obtainable, and shows permanent gaps explicitly. Do not silently bridge missing periods.

## 4. Snapshot deltas

Content hashes exclude collection timestamps and other volatile metadata. Canonicalize unordered
member sets and normalize timestamps before hashing. Compare only snapshots with the same scope and
schema; `record_changes` includes scope and generation. A complete empty snapshot means removal;
a failed domain/region/compartment is not an empty snapshot. Removal timestamp is distinct from last
observation. Schema changes establish a new baseline or migrate hashes; they do not manufacture drift.

## 5. Required verification

Mock source paging and durable stores to inject interruption before/after every batch and checkpoint
commit, including month boundaries. Test duplicate/late events, successful empty windows, truncated
results, concurrent lease acquisition, out-of-order runs, disk-full errors, retention races and restored
checkpoints with missing files. Verify source limits and delivery characteristics separately in an
explicitly authorized non-production OCI tenancy before releasing the ingestion coordinator.

Implementation failure-path fixes and regression coverage: [review summaries](review-fixes.md).
