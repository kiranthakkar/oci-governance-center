# IAM-GRP-002 — Every member of this group is inactive

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: identity. Severity: LOW.
Analysis scope: `analysis.activity`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Evaluated after each Audit collection over the latest stored users and groups. It requires
a complete `analysis.identity` scope and complete Audit coverage for every subscribed region over
`OGC_INACTIVE_DAYS`: the forward cursor complete, and backfill finished or the window starting after
forward collection began. `OGC_RETENTION_DAYS` must be at least `OGC_INACTIVE_DAYS`.

**Trigger.** A group has at least one user member and every user member is inactive under IAM-USR-003.

**Identity.** Keyed by the group's SCIM id. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
