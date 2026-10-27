# POL-UNUSED-001 — Policy has no effect

Version: 1 (2026-10-22; unknown-domain handling 2026-10-27). Status: implemented (Tier 4). Source: policy. Severity: LOW.
Analysis scope: `analysis.policy`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.policies` (every compartment), `identity.domains`, and `identity_domains.groups` and `identity_domains.dynamic_groups` for each identity domain that was read, from the same collection run.

**Trigger.** Every Allow/Endorse statement in the policy is ineffective: its target compartment is missing or deleted, or all its subjects are missing groups, groups with no members or missing dynamic groups. Statements naming any-user, any-group, service or resource principals are always treated as effective; policies containing an unparsed statement, or a statement naming a subject in an identity domain that was not read, are skipped, so a policy that touches an unscanned domain is never reported as not in use.

**Unscanned identity domains (2026-10-27).** Each tenancy reads only its default identity domain
unless the Scan tab enables all domains. A subject in a domain that was not read (or a group OCID
that is not found while any active domain was not read, or any group when identities are disabled)
is **unknown**, not missing. A policy with any unknown subject is never reported; the Identity → Policies view
lists those statements as "Not analyzed".

**Identity.** Keyed by policy OCID. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** OCI provides no policy usage data; this is a static evaluation of the collected inventory.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
