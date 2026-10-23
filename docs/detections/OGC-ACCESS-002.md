# OGC-ACCESS-002 — source collection incomplete

Source: coverage. Severity: HIGH. Enabled in the new Tier 1 runtime.

Raise a finding when a named dataset/API scope fails or Audit historical backfill is unfinished.
Identity is SHA-256 of the versioned canonical scope (tenancy, dataset, region, domain, compartment).
Keep first_seen when the same failure recurs. Preserve previously collected snapshots on failure.
Resolve only after a complete successful collection/check for that exact scope. An unrelated scope,
paused child or failed authentication never establishes successful coverage.

Evidence is a safe error category/status and timestamps; no SDK bodies or credential material.
Positive/negative/resolution and snapshot-preservation tests are in tests/unit/test_storage.py.
The OGC prefix is the new implementation's coverage identifier; old OSC specifications remain historical.
