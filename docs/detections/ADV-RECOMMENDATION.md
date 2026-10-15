# ADV-RECOMMENDATION — Cloud Advisor recommendation (mirrored)

Version: 1 (2026-10-09). Status: implemented (Tier 1). Source: advisor. Severity: one step below the
source importance (`models/severity.py`: CRITICAL→HIGH, HIGH→MEDIUM, MODERATE→LOW, LOW/MINOR→INFO);
recommendations are advisory. No CIS mapping.

Input: `optimizer.recommendations` — `list_categories`, then `list_recommendations` per category
(whole subtree, home region). Trigger: status `PENDING`. Identity: recommendation OCID. Resolution:
absent or no longer pending in a later complete snapshot. Tests: `tests/unit/test_collectors.py`.
