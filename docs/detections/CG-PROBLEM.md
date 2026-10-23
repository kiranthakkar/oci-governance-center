# CG-PROBLEM — Cloud Guard problem (mirrored)

Version: 1 (2026-10-22). Status: implemented (Tier 1). Source: `cloud_guard`, or `security_zone` for
Security Zone violations. No CIS mapping: Cloud Guard is the detector of record, and OGC mirrors its
problems rather than re-detecting them. Code: `collectors/inventory.py`, `analyzers.governance`.

Input: dataset `cloud_guard.problems` in the Cloud Guard reporting region (from
`cloud_guard.configuration`, falling back to the home region). The collector calls
`CloudGuardClient.list_problems` for the whole subtree with `access_level=ACCESSIBLE` and
`lifecycle_detail=OPEN`. A second call with the documented `problem_category=SECURITY_ZONE`
filter classifies Security Zone violations; detector names are not used. Both calls must succeed for
the scope to be complete.

Trigger: every open problem in a complete snapshot. Title: the problem's `resource_name`. Severity
(`severity.cloud_guard_severity`): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` and `INFO` are preserved;
any other value, including `MINOR` or a missing level, becomes `INFO` and is never promoted.

Identity: SHA-256 of `["v1", tenancy, "cloud_guard.problems", <problem OCID>, "CG-PROBLEM"]`. Both
categories share this namespace, so reclassification never duplicates a finding.
Resolution: the problem is absent from a later complete snapshot of the same scope. A failed read
raises `OGC-ACCESS-002` and keeps findings open.

Tests: `tests/unit/test_jwt_and_analysis.py::test_problem_reclassification_keeps_native_identity`.
