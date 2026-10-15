"""Cloud Advisor (Optimizer) collectors (docs/collection.md §3; AGENTS.md §7.2).

* enrollment — ``OptimizerClient.list_enrollment_statuses`` in the home region. No active
  enrollment raises ``GOV-ADV-001``.
* recommendations — ``list_categories`` then ``list_recommendations`` per category (whole subtree)
  in the home region; not applicable while Cloud Advisor isn't enabled. Each pending recommendation
  becomes an ``advisor`` finding (advisory severity, ``models/severity.py``).

Per-tenancy reads are the baseline; the parent-side organization view (``include_organization``)
is optional capability gate Q4. IAM: ``read all-resources`` (``optimizer-api-family``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import oci

from oci_security_center.collection.base import (
    Collected,
    Evaluation,
    NotApplicable,
    TenancyContext,
    TenancyScoped,
)
from oci_security_center.models import (
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    Severity,
)
from oci_security_center.models.severity import from_advisor
from oci_security_center.oci_clients import ClientMaker, list_all, pick, to_plain

RECOMMENDATION_FIELDS = (
    "id",
    "category_id",
    "name",
    "description",
    "importance",
    "status",
    "lifecycle_state",
    "resource_counts",
    "estimated_cost_saving",
    "time_status_begin",
    "time_status_end",
    "time_updated",
)
DISABLED_RULE = "GOV-ADV-001"
RECOMMENDATION_RULE = "ADV-RECOMMENDATION"


def _enrolled(records: list[dict[str, Any]]) -> bool:
    return any(r.get("status") == "ACTIVE" for r in records)


class EnrollmentCollector(TenancyScoped):
    dataset = "optimizer.enrollment"
    tier = 1
    depends_on: tuple[str, ...] = ("identity.region_subscriptions",)

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        opt: Any = clients(oci.optimizer.OptimizerClient, ctx.home_region)
        rows = [
            pick(to_plain(e), ("id", "status", "status_reason", "lifecycle_state"))
            for e in list_all(opt.list_enrollment_statuses, compartment_id=ctx.tenancy_ocid)
        ]
        return Collected([ctx.envelope(self.dataset, str(r["id"]), r) for r in rows])

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        findings = []
        if not _enrolled([e.data for e in records]):
            findings.append(
                Finding(
                    source=FindingSource.GOVERNANCE,
                    tenancy_ocid=ctx.tenancy_ocid,
                    rule_id=DISABLED_RULE,
                    identity={"rule": DISABLED_RULE, "subject": "cloud_advisor"},
                    severity=Severity.MEDIUM,
                    title="Cloud Advisor is not enabled",
                    description="No active Cloud Advisor enrollment; recommendations are not "
                    "available for this tenancy.",
                    resource_ocid=ctx.tenancy_ocid,
                )
            )
        return Evaluation(findings, [(FindingSource.GOVERNANCE, DISABLED_RULE)])


class RecommendationsCollector(TenancyScoped):
    dataset = "optimizer.recommendations"
    tier = 1
    depends_on: tuple[str, ...] = ("optimizer.enrollment",)

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]:
        if not _enrolled(ctx.current("optimizer.enrollment")):
            raise NotApplicable("Cloud Advisor is not enabled in this tenancy")
        return [ctx.scope(self.dataset)]

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        opt: Any = clients(oci.optimizer.OptimizerClient, ctx.home_region)
        categories = list_all(
            opt.list_categories, compartment_id=ctx.tenancy_ocid, compartment_id_in_subtree=True
        )
        out = Collected()
        for cat in categories:
            for r in list_all(
                opt.list_recommendations,
                compartment_id=ctx.tenancy_ocid,
                compartment_id_in_subtree=True,
                category_id=cat.id,
            ):
                data = pick(to_plain(r), RECOMMENDATION_FIELDS)
                out.records.append(ctx.envelope(self.dataset, str(data["id"]), data))
        return out

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        findings = [
            Finding(
                source=FindingSource.ADVISOR,
                tenancy_ocid=ctx.tenancy_ocid,
                rule_id=RECOMMENDATION_RULE,
                identity={"recommendation_id": str(e.data["id"])},
                source_record_id=str(e.data["id"]),
                severity=from_advisor(e.data.get("importance")),
                title=str(e.data.get("name") or "Cloud Advisor recommendation"),
                description=str(e.data.get("description") or ""),
                raw_ref=f"optimizer.recommendations/{e.data['id']}",
            )
            for e in records
            if e.data.get("status") == "PENDING"
        ]
        return Evaluation(findings, [(FindingSource.ADVISOR, RECOMMENDATION_RULE)])
