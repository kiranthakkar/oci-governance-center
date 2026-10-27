# POL-STALE-001 — Policy statement references missing identities or compartments

Version: 1 (2026-10-22; unknown-domain handling 2026-10-27). Status: implemented (Tier 4). Source: policy. Severity: MEDIUM.
Analysis scope: `analysis.policy`. Code: `analyzers/identity.py`. No CIS mapping is assigned; add one only
after verifying it against a named CIS OCI Benchmark version.

**Inputs.** Complete `identity.compartments`, `identity.policies` (every compartment), `identity.domains`, and `identity_domains.groups` and `identity_domains.dynamic_groups` for each identity domain that was read, from the same collection run. Group and dynamic-group inputs are not required when identities are disabled in the tenancy's scan settings.

**Trigger.** An Allow or Endorse statement names a group or dynamic group that does not exist in the named (or Default) identity domain or by OCID, or an Allow statement targets a compartment path or OCID that is not found or is deleted. Relative paths resolve from the policy's attachment compartment.

**Unscanned identity domains (2026-10-27).** Each tenancy reads only its default identity domain
unless the Scan tab enables all domains. A subject in a domain that was not read (or a group OCID
that is not found while any active domain was not read, or any group when identities are disabled)
is **unknown**, not missing. Unknown subjects never trigger this rule; the Identity → Policies view
lists those statements as "Not analyzed".

**Identity.** Keyed by policy OCID and normalized statement. Finding IDs hash `["v1", tenancy, scope key, subject key, rule]`.

**Lifecycle.** The finding opens on the first evaluation that triggers it, keeps `first_seen`, and
resolves only when a later **complete** evaluation of the same analysis scope no longer triggers it.

**Incomplete coverage.** If any input above is incomplete, the analysis scope is published as
incomplete (`OGC-ACCESS-002`) and no finding in that scope is opened or resolved.

**Evidence.** `raw_ref` points to the source record; the description quotes the policy statement or
names the principal. No SDK bodies or credential material are stored.

**Limitations.** Admit subjects and Endorse target tenancies belong to other tenancies and are not resolved. A recreated group with the same name silently regains the grant, which is why stale statements matter.

Tests: `tests/unit/test_identity_analysis.py` (positive and negative) and
`tests/unit/test_identity_tab.py` (fail-closed scheduling and resolution).
