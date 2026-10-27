# IAM-USR-003 — User inactive

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: identity. Severity: LOW.
Analysis scope: `analysis.activity`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Evaluated after each Audit collection over the latest stored users and groups. It requires
a complete `analysis.identity` scope and complete Audit coverage for every subscribed region over
`OGC_INACTIVE_DAYS`: the forward cursor complete, and backfill finished or the window starting after
forward collection began. `OGC_RETENTION_DAYS` must be at least `OGC_INACTIVE_DAYS`.

**Trigger.** An active user has no successful sign-in (`lastSuccessfulLoginDate`) within `OGC_INACTIVE_DAYS` (default 90) **and** no Audit event with that user's OCID as principal in the same window. Audit activity covers API-key use, which sign-in dates do not.

**Identity.** Keyed by the user's SCIM id. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** The rule is skipped (coverage finding on `analysis.activity`) until Audit coverage spans the whole window, so missing history is never mistaken for inactivity.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
