# IAM-USR-002 — User without MFA

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: identity. Severity: HIGH.
Analysis scope: `analysis.identity`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.domains`, `identity_domains.users` and `identity_domains.groups` for the tenancy, from the same collection run.

**Trigger.** An active user that is neither federated (`isFederatedUser`) nor a service user (`serviceUser`) has an MFA status other than `ENROLLED`. A user without a reported status counts as not enrolled **only** in identity domains where OCI returned `mfaStatus` for at least one user; elsewhere MFA is unknown (not collected, or the attribute is not readable) and no finding is raised. The Identity tab shows such users as MFA *Unknown*. Federated users authenticate, and are expected to use MFA, at their identity provider.

**Identity.** Keyed by the user's SCIM id; the description records the reported MFA status. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** MFA status is the identity domain's enrollment state; sign-on policies that do not require MFA are not evaluated. Reading the attribute is a live gate.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
