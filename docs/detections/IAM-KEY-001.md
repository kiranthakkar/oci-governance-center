# IAM-KEY-001 — API key older than the rotation age

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: identity. Severity: MEDIUM.
Analysis scope: `analysis.api_keys`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.domains`, `identity_domains.users` and `identity_domains.api_keys` for the tenancy, from the same collection run.

**Trigger.** An API signing key's creation date is older than `OGC_API_KEY_MAX_AGE_DAYS` (default 90). OCI API signing keys have no expiry date, so age is the only rotation signal.

**Identity.** Keyed by the API key id. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** Only key metadata (owner, created) is collected; key material and fingerprints are never stored. Whether `read users` authorizes `ListApiKeys` in every domain is a live gate.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
