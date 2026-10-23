# GOV-ADV-001 — Cloud Advisor not enabled

Version: 1 (2026-10-22). Status: implemented (Tier 1). Source: governance. Severity: MEDIUM.
No CIS mapping. Code: `analyzers.governance`; lifecycle in `Service.findings`.

Input: dataset `optimizer.enrollment`, read with `OptimizerClient.list_enrollment_statuses` in the
tenancy's home region and projected to `id`, `status` and `status_reason`.

Trigger: in a complete snapshot, each enrollment status whose `status` is neither `ACTIVE` nor
`ENROLLED`. A complete but empty listing is evaluated as one synthetic `enrollment` record with status
`DISABLED`, so absence is never treated as enabled. Identity: SHA-256 of `["v1", tenancy,
"optimizer.enrollment", <enrollment status id or "enrollment">, "GOV-ADV-001"]`.

Resolution: a later complete snapshot of the same scope without the triggering record. A failed read
raises `OGC-ACCESS-002` and never resolves the finding.

Tests: `tests/unit/test_jwt_and_analysis.py::test_positive_and_negative_governance_rules`.
