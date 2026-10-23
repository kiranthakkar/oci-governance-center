# ADV-RECOMMENDATION — Cloud Advisor recommendation (mirrored)

Version: 1 (2026-10-22). Status: implemented (Tier 1). Source: advisor. No CIS mapping.
Code: `collectors/inventory.py`, `analyzers.governance`.

Input: dataset `optimizer.recommendations`, read with `OptimizerClient.list_recommendations` for the
tenancy subtree in the home region and projected to `id`, `category_id`, `name`, `importance`,
`status` and `time_updated`.

Trigger: status `PENDING` in a complete snapshot. Title: the recommendation name. Severity
(`severity.advisor_severity`) is one step below the source importance because recommendations are
advisory: `CRITICAL`→`HIGH`, `HIGH`→`MEDIUM`, `MODERATE`/`MEDIUM`→`LOW`, `LOW`→`INFO`; any other
value becomes `INFO`.

Identity: SHA-256 of `["v1", tenancy, "optimizer.recommendations", <recommendation OCID>,
"ADV-RECOMMENDATION"]`. Resolution: absent or no longer pending in a later complete snapshot of the
same scope. A failed read raises `OGC-ACCESS-002` and keeps findings open.

Tests: `tests/unit/test_jwt_and_analysis.py::test_positive_and_negative_governance_rules`.
