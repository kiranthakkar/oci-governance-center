# GOV-CG-001 — Cloud Guard not enabled

Version: 1 (2026-10-09). Status: implemented (Tier 1). Source: governance. Severity: HIGH. No CIS mapping.

Purpose: a tenancy without Cloud Guard has no detector of record; its problems and Security Zone
violations are invisible. Input: `cloud_guard.configuration` (`CloudGuardClient.get_configuration`,
home region): status, reporting region.

Trigger: a complete configuration snapshot whose status is not `ENABLED` (including unknown).
Identity: generation, tenancy, rule, subject `cloud_guard`. Evaluation scope: the tenancy-wide
`cloud_guard.configuration` scope.

Resolution: a later complete configuration snapshot with status `ENABLED`. A failed or partial read
never resolves it; it raises `OSC-ACCESS-002` for the configuration scope instead. While Cloud Guard is
disabled, `cloud_guard.problems` and `security_zones.zones` are shown as not applicable (rows kept).

Tests: `tests/unit/test_collectors.py` (disabled child raises; enabling resolves; enabled parent never
raises). Limitations: status only; detector/target coverage is Tier 2 (`GOV-CG-002/003`).
