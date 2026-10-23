"""Pure governance analysis over normalized complete collection results; never calls OCI."""

import hashlib
import json

from .models import Batch, Finding, FindingSource, Record, Severity
from .severity import advisor_severity, cloud_guard_severity


def governance(batch: Batch) -> list[Finding]:
    """Derive source-native findings; complete matching scope is required for resolution."""
    if not batch.complete:
        return []
    findings: list[Finding] = []
    dataset = batch.scope.dataset
    source_records = batch.records
    if dataset == "optimizer.enrollment" and not source_records:
        source_records = [Record(key="enrollment", data={"status": "DISABLED"})]
    for record in source_records:
        data = record.data
        rule, title = "", ""
        severity: Severity = "INFO"
        source: FindingSource = "governance"
        if dataset == "cloud_guard.configuration" and data.get("status") != "ENABLED":
            rule, severity, title = "GOV-CG-001", "HIGH", "Cloud Guard is not enabled"
        elif dataset == "cloud_guard.problems":
            rule, title = "CG-PROBLEM", str(data.get("resource_name") or "Cloud Guard problem")
            severity = cloud_guard_severity(str(data.get("risk_level") or ""))
            source = (
                "security_zone"
                if data.get("problem_category") == "SECURITY_ZONE"
                else "cloud_guard"
            )
        elif dataset == "optimizer.enrollment" and data.get("status") not in {
            "ACTIVE",
            "ENROLLED",
        }:
            rule, severity, title = "GOV-ADV-001", "MEDIUM", "Cloud Advisor is not enabled"
        elif dataset == "optimizer.recommendations" and data.get("status") == "PENDING":
            rule, severity, title, source = (
                "ADV-RECOMMENDATION",
                advisor_severity(str(data.get("importance") or "")),
                str(data.get("name") or "Cloud Advisor recommendation"),
                "advisor",
            )
        if rule:
            ident = hashlib.sha256(
                json.dumps(["v1", batch.scope.tenancy, dataset, record.key, rule]).encode()
            ).hexdigest()
            findings.append(
                Finding(
                    id=ident,
                    scope=batch.scope.key,
                    tenancy=batch.scope.tenancy,
                    source=source,
                    rule_id=rule,
                    severity=severity,
                    title=title,
                )
            )
    return findings
