# CG-PROBLEM — Cloud Guard problem (mirrored)

Version: 1 (2026-10-09). Status: implemented (Tier 1). Source: `cloud_guard`, or `security_zone` for
Security Zone violations. Severity: mapped from the problem's risk level (`models/severity.py`:
CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM→MEDIUM, LOW→LOW, MINOR→INFO). No CIS mapping (Cloud Guard is the
detector of record; OSC mirrors, it doesn't re-detect).

Input: `cloud_guard.problems` — `CloudGuardClient.list_problems` in the reporting region, whole subtree,
`lifecycle_detail=OPEN`. Security Zone violations are identified with the SDK's documented filter
`problem_category=SECURITY_ZONE` (a second call), not by detector name.

Identity: the shared Cloud Guard namespace + problem OCID, so re-classification never duplicates.
Resolution: the problem is absent from a later complete snapshot of the tenancy's open problems. A
partial/failed read keeps findings open. `time_last_detected` is volatile (excluded from drift).
Evidence: `raw_ref = cloud_guard.problems/<problem OCID>`. Tests: `tests/unit/test_collectors.py`.
