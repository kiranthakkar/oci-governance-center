> **Historical (2026-10-22).** This rule belonged to the removed OSC implementation and is not
> implemented in OGC. OGC no longer generates Endorse/Admit grants, so a replacement access-policy
> check needs a new design before it is assigned an `OGC-` ID.

# OSC-ACCESS-001 — Access policy coverage

Version: 1 (2026-10-08). Source: coverage. Severity: HIGH. No CIS mapping.

Purpose: make missing or uncheckable OSC permissions visible rather than silently skipping a tenancy.
Inputs: generated required statements, policy ID and statement text, policy-local alias maps, principal
identity and smoke-test outcomes. Ignore optional administrator-browse requirements when disabled.

Trigger: a required grant is missing; a policy read fails; or a required access probe fails. Report
unknown conditions/alias ambiguity as unknown coverage, never detected. Current emitted rule variants
are `OSC-ACCESS-001:<requirement-id>`, `:check`, and `:verify`. The target finding identity uses rule,
requirement/API, tenancy, region/domain scope and failure stage (storage §3.4), not resource alone.
Broader effective grants satisfy access with a policy-review warning; they do not trigger missing access.

Resolution: only a complete policy-local check and successful applicable probes can resolve findings
in the same evaluated scope. Failed/partial reads, untouched scopes and disabled tiers retain open
findings. Keep matched policy/statement references, checked time and probe scope; logs remain redacted.
A probe proves that call only, not every collector or all future conditional access.

Required tests: missing versus equivalent grant; same-policy versus split definitions; alias conflicts;
name/OCID/domain equivalence; broader grants; conditional unknown; failed read/verify retains findings;
complete recheck resolves only the matching scope. Existing tests cover a subset; architecture §4
tracks remaining runtime work. No live test is implied by this specification.
