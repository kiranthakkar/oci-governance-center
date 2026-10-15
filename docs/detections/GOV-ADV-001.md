# GOV-ADV-001 — Cloud Advisor not enabled

Version: 1 (2026-10-09). Status: implemented (Tier 1). Source: governance. Severity: MEDIUM. No CIS
mapping.

Input: `optimizer.enrollment` (`OptimizerClient.list_enrollment_statuses`, home region).
Trigger: a complete enrollment snapshot with no `ACTIVE` enrollment. Identity: generation, tenancy,
rule, subject `cloud_advisor`. Resolution: a later complete snapshot with an `ACTIVE` enrollment; failed
reads raise `OSC-ACCESS-002` and never resolve. While not enrolled, `optimizer.recommendations` is not
applicable (rows kept). Tests: `tests/unit/test_collectors.py`.
