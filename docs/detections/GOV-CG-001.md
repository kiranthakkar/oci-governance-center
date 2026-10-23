# GOV-CG-001 — Cloud Guard not enabled

Version: 1 (2026-10-22). Status: implemented (Tier 1). Source: governance. Severity: HIGH.
No CIS mapping. Code: `analyzers.governance`; lifecycle in `Service.findings`.

Purpose: a tenancy without Cloud Guard has no detector of record; its problems and Security Zone
violations are invisible.

Input: dataset `cloud_guard.configuration`, read with `CloudGuardClient.get_configuration` in the
tenancy's home region and projected to `status` and `reporting_region`.

Trigger: a complete configuration snapshot whose `status` is not `ENABLED`, including a missing or
unknown status. Identity: SHA-256 of `["v1", tenancy, "cloud_guard.configuration", tenancy,
"GOV-CG-001"]`. Evaluation scope: the tenancy-wide `cloud_guard.configuration` scope.

Resolution: a later complete snapshot of the same scope that no longer triggers sets `status=resolved`
and `resolved_at`. A failed read never resolves the finding; it raises `OGC-ACCESS-002` for the
configuration scope and keeps the previous snapshot. When the configuration read fails, problems and
Security Zones are not attempted in that cycle.

Tests: `tests/unit/test_jwt_and_analysis.py::test_positive_and_negative_governance_rules` and
`tests/unit/test_service.py`. Limitations: status only; detector/target coverage is Tier 2
(`GOV-CG-002/003`, planned).
