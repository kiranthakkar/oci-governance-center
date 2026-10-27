# Detection specifications

Status: 2026-10-22. Specifications are not evidence that a rule is implemented.

| Rule | Status | Specification |
|---|---|---|
| OGC-ACCESS-002 | Implemented (Tier 1): per-scope collection coverage and unfinished Audit backfill | [Source collection incomplete](OGC-ACCESS-002.md) |
| GOV-CG-001 | Implemented (Tier 1) | [Cloud Guard not enabled](GOV-CG-001.md) |
| GOV-ADV-001 | Implemented (Tier 1) | [Cloud Advisor not enabled](GOV-ADV-001.md) |
| CG-PROBLEM | Implemented (Tier 1): mirrored Cloud Guard / Security Zone problems | [Cloud Guard problem](CG-PROBLEM.md) |
| ADV-RECOMMENDATION | Implemented (Tier 1): mirrored pending recommendations | [Advisor recommendation](ADV-RECOMMENDATION.md) |
| POLICY-PARSE-001 | Implemented (Tier 4, `analysis.policy`) | [Parsing coverage](POLICY-PARSE-001.md) |
| POL-DUP-001 | Implemented (Tier 4, `analysis.policy`) | [Duplicate policy](POL-DUP-001.md) |
| POL-DUP-002 | Implemented (Tier 4, `analysis.policy`) | [Duplicate policy statement](POL-DUP-002.md) |
| POL-STALE-001 | Implemented (Tier 4, `analysis.policy`) | [Policy statement references missing identities or compartments](POL-STALE-001.md) |
| POL-UNUSED-001 | Implemented (Tier 4, `analysis.policy`) | [Policy has no effect](POL-UNUSED-001.md) |
| POL-MANAGE-001 | Implemented (Tier 4, `analysis.policy`) | [Grant to manage a resource type](POL-MANAGE-001.md) |
| POL-MANAGE-002 | Implemented (Tier 4, `analysis.policy`) | [Grant to manage all-resources](POL-MANAGE-002.md) |
| POL-IAM-001 | Implemented (Tier 4, `analysis.policy`) | [Non-administrator can use or manage IAM resources](POL-IAM-001.md) |
| POL-ANY-001 | Implemented (Tier 4, `analysis.policy`) | [Grant to any-user or any-group](POL-ANY-001.md) |
| POL-DG-001 | Implemented (Tier 4, `analysis.policy`) | [Broad dynamic group is granted manage](POL-DG-001.md) |
| POL-XTEN-001 | Implemented (Tier 4, `analysis.policy`) | [Cross-tenancy policy statement](POL-XTEN-001.md) |
| IAM-GRP-001 | Implemented (Tier 4, `analysis.policy`) | [Group not in use](IAM-GRP-001.md) |
| IAM-GRP-002 | Implemented (Tier 4, `analysis.activity`) | [Every member of this group is inactive](IAM-GRP-002.md) |
| IAM-DG-001 | Implemented (Tier 4, `analysis.policy`) | [Dynamic group not referenced by any policy](IAM-DG-001.md) |
| IAM-USR-001 | Implemented (Tier 4, `analysis.identity`) | [User is not a member of any group](IAM-USR-001.md) |
| IAM-USR-002 | Implemented (Tier 4, `analysis.identity`) | [User without MFA](IAM-USR-002.md) |
| IAM-USR-003 | Implemented (Tier 4, `analysis.activity`) | [User inactive](IAM-USR-003.md) |
| IAM-KEY-001 | Implemented (Tier 4, `analysis.api_keys`) | [API key older than the rotation age](IAM-KEY-001.md) |
| GOV-CG-002/003, GOV-SZ-001, GOV-AUD-001/002, GOV-EVT-001, GOV-TAG-001, GOV-QTA-001, GOV-BUD-001 | Planned (Tier 2) | collection §4 |
| Audit anomaly rules | Planned (Tier 5); IDs must be assigned before implementation | AGENTS.md §7.6 and collection §7 |
| OSC-ACCESS-001 | Historical: removed with the OSC implementation; not implemented | [Access coverage](OSC-ACCESS-001.md) |
| OSC-ACCESS-002 | Superseded by OGC-ACCESS-002 | [Source coverage](OSC-ACCESS-002.md) |

Every enabled rule requires its own file documenting ID/version, purpose, source and required fields,
identity/scope, exact trigger and exclusions, severity, lifecycle/resolution, incomplete-coverage
behavior, evidence references, limitations and applicable benchmark version/control IDs. Include at
least one positive and one negative mocked test, plus boundary/late-event tests for time-window rules.
Do not attach CIS controls to OGC-specific operational coverage rules. Source-native problems retain
source IDs and risk mapping; Cloud Guard remains the detector of record.

Synthetic fixtures are the default. `scripts/sanitize_fixtures.py` is not implemented: no recorded
responses may be committed until a reviewed sanitizer and leak checks exist. Do not record real
credentials, request headers, key material, tokens or unsanitized personal/tenancy identifiers.
