# Detection specifications

Status: 2026-10-08. Specifications are not evidence that a rule is implemented.

| Rule | Status | Specification |
|---|---|---|
| OSC-ACCESS-001 | Implemented, with policy-local alias matching and scoped fail-closed resolution | [Access coverage](OSC-ACCESS-001.md) |
| OSC-ACCESS-002 | Implemented: per-scope collection and audit-gap coverage | [Source coverage](OSC-ACCESS-002.md) |
| POLICY-PARSE-001 | Planned finding; tolerant statement parser exists | [Parsing coverage](POLICY-PARSE-001.md) |
| GOV-CG-001 | Implemented (Tier 1) | [Cloud Guard not enabled](GOV-CG-001.md) |
| GOV-ADV-001 | Implemented (Tier 1) | [Cloud Advisor not enabled](GOV-ADV-001.md) |
| CG-PROBLEM | Implemented (Tier 1): mirrored Cloud Guard / Security Zone problems | [Cloud Guard problem](CG-PROBLEM.md) |
| ADV-RECOMMENDATION | Implemented (Tier 1): mirrored pending recommendations | [Advisor recommendation](ADV-RECOMMENDATION.md) |
| GOV-CG-002/003, GOV-SZ-001, GOV-AUD-001/002, GOV-EVT-001, GOV-TAG-001, GOV-QTA-001, GOV-BUD-001 | Planned | collection §4 |
| Policy risky-grant and audit anomaly rules | Planned; IDs must be assigned before implementation | AGENTS.md §7.3/§7.4 and collection §6/§7 |

Every enabled rule requires its own file documenting ID/version, purpose, source and required fields,
identity/scope, exact trigger and exclusions, severity, lifecycle/resolution, incomplete-coverage
behavior, evidence references, limitations and applicable benchmark version/control IDs. Include at
least one positive and one negative mocked test, plus boundary/late-event tests for time-window rules.
Do not attach CIS controls to OSC-specific operational coverage rules. Source-native problems retain
source IDs and risk mapping; Cloud Guard remains the detector of record.

Synthetic fixtures are the default. `scripts/sanitize_fixtures.py` is not implemented: no recorded
responses may be committed until a reviewed sanitizer and leak checks exist. Do not record real
credentials, request headers, key material, tokens or unsanitized personal/tenancy identifiers.
