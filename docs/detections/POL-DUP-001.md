# POL-DUP-001 — Duplicate policy

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: policy. Severity: LOW.
Analysis scope: `analysis.policy`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.policies` (every compartment), `identity.domains`, `identity_domains.groups` and `identity_domains.dynamic_groups` for the tenancy, from the same collection run.

**Trigger.** Two or more active policies have the same set of normalized statements. Normalization ignores case, whitespace and quote style; relative `compartment` paths are compared together with the policy's attachment compartment, so the same text attached elsewhere is not a duplicate.

**Identity.** One finding per policy in the duplicate group, keyed by policy OCID; the description names the other policies. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** Duplicates are redundant, not dangerous; removing one does not change access.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
