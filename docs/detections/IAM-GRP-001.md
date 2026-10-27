# IAM-GRP-001 — Group not in use

Version: 1 (2026-10-22). Status: implemented (Tier 4). Source: identity. Severity: LOW.
Analysis scope: `analysis.policy`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.policies` (every compartment), `identity.domains`, `identity_domains.groups` and `identity_domains.dynamic_groups` for the tenancy, from the same collection run.

**Trigger.** A group has no members, or no parsed Allow/Endorse statement references it (by name in its domain or by OCID). The Default-domain `ogc_admin` and `ogc_viewer` application groups are excluded because OGC sign-in uses them.

**Identity.** Keyed by the group's SCIM id; one finding lists every reason. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** Groups used through identity-domain application roles (admin-role grants, not collected) appear unreferenced. Membership limits follow the groups dataset completeness rules.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
