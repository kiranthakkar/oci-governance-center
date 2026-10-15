"""Cloud Guard and Security Zone collectors (docs/collection.md §3; AGENTS.md §7.2).

* configuration — ``CloudGuardClient.get_configuration`` in the home region: status and the
  reporting region. A disabled Cloud Guard raises ``GOV-CG-001``.
* problems — ``list_problems`` (whole subtree, open problems) in the **reporting region**. Each open
  problem becomes a finding; Cloud Guard remains the detector of record. A second call with
  ``problem_category="SECURITY_ZONE"`` (the SDK's documented filter for security-zone violations)
  tags those problems; they are shown as ``source=security_zone`` but keep one identity namespace.
* security zones — ``list_security_zones`` per active compartment in the reporting region.

Problems and zones are not applicable while Cloud Guard is disabled (rows are kept, no coverage
finding; ``GOV-CG-001`` covers it). IAM: ``read all-resources`` (``cloud-guard-family``).
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
from oci_security_center.collectors.identity import _active_compartments
from oci_security_center.models import (
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    Severity,
)
from oci_security_center.models.severity import from_cloud_guard
from oci_security_center.oci_clients import ClientMaker, list_all, pick, to_plain

PROBLEM_FIELDS = (
    "id",
    "compartment_id",
    "detector_id",
    "detector_rule_id",
    "risk_level",
    "resource_id",
    "resource_name",
    "resource_type",
    "labels",
    "region",
    "regions",
    "target_id",
    "lifecycle_state",
    "lifecycle_detail",
    "time_first_detected",
    "time_last_detected",
)
ZONE_FIELDS = (
    "id",
    "compartment_id",
    "display_name",
    "security_zone_recipe_id",
    "lifecycle_state",
)
PROBLEM_RULE = "CG-PROBLEM"
DISABLED_RULE = "GOV-CG-001"
SECURITY_ZONE = "SECURITY_ZONE"  # list_problems(problem_category=...) allowed value


def _configuration(ctx: TenancyContext) -> dict[str, Any]:
    rows = ctx.current("cloud_guard.configuration")
    return rows[0] if rows else {}


def _reporting_region(ctx: TenancyContext) -> str:
    cfg = _configuration(ctx)
    if cfg.get("status") != "ENABLED":
        raise NotApplicable("Cloud Guard is not enabled in this tenancy")
    return str(cfg.get("reporting_region") or ctx.home_region)


class CloudGuardConfigurationCollector(TenancyScoped):
    dataset = "cloud_guard.configuration"
    tier = 1
    depends_on: tuple[str, ...] = ("identity.region_subscriptions",)

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        cg: Any = clients(oci.cloud_guard.CloudGuardClient, ctx.home_region)
        cfg = pick(
            to_plain(cg.get_configuration(ctx.tenancy_ocid).data),
            ("status", "reporting_region", "self_manage_resources"),
        )
        return Collected([ctx.envelope(self.dataset, ctx.tenancy_ocid, cfg)])

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        status = records[0].data.get("status") if records else None
        findings = []
        if status != "ENABLED":
            findings.append(
                Finding(
                    source=FindingSource.GOVERNANCE,
                    tenancy_ocid=ctx.tenancy_ocid,
                    rule_id=DISABLED_RULE,
                    identity={"rule": DISABLED_RULE, "subject": "cloud_guard"},
                    severity=Severity.HIGH,
                    title="Cloud Guard is not enabled",
                    description=f"Cloud Guard status is {status or 'unknown'}; problems and "
                    "Security Zone violations are not detected in this tenancy.",
                    resource_ocid=ctx.tenancy_ocid,
                )
            )
        return Evaluation(findings, [(FindingSource.GOVERNANCE, DISABLED_RULE)])


class CloudGuardProblemsCollector(TenancyScoped):
    dataset = "cloud_guard.problems"
    tier = 1
    depends_on: tuple[str, ...] = ("cloud_guard.configuration",)

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]:
        _reporting_region(ctx)  # not applicable while disabled
        return [ctx.scope(self.dataset)]

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        cg: Any = clients(oci.cloud_guard.CloudGuardClient, _reporting_region(ctx))
        query = {
            "compartment_id": ctx.tenancy_ocid,
            "compartment_id_in_subtree": True,
            "access_level": "ACCESSIBLE",
            "lifecycle_detail": "OPEN",
        }
        problems = list_all(cg.list_problems, **query)
        zone_ids = {
            p.id for p in list_all(cg.list_problems, problem_category=SECURITY_ZONE, **query)
        }
        records = []
        for x in problems:
            p = pick(to_plain(x), PROBLEM_FIELDS)
            p["problem_category"] = SECURITY_ZONE if x.id in zone_ids else None
            records.append(
                ctx.envelope(
                    self.dataset,
                    p["id"],
                    p,
                    compartment_ocid=p.get("compartment_id"),
                    resource_ocid=p.get("resource_id"),
                )
            )
        return Collected(records)

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        findings = []
        for env in records:
            p = env.data
            zone = p.get("problem_category") == SECURITY_ZONE
            findings.append(
                Finding(
                    source=FindingSource.SECURITY_ZONE if zone else FindingSource.CLOUD_GUARD,
                    tenancy_ocid=ctx.tenancy_ocid,
                    rule_id=PROBLEM_RULE,
                    identity={"problem_id": str(p["id"])},
                    source_record_id=str(p["id"]),
                    severity=from_cloud_guard(p.get("risk_level")),
                    title=f"{p.get('detector_rule_id') or 'Cloud Guard problem'}"
                    f" — {p.get('resource_name') or p.get('resource_id') or 'resource'}",
                    description=f"Detector {p.get('detector_id')}, risk {p.get('risk_level')}.",
                    resource_ocid=p.get("resource_id"),
                    resource_type=p.get("resource_type"),
                    region=p.get("region"),
                    compartment_ocid=p.get("compartment_id"),
                    raw_ref=f"cloud_guard.problems/{p['id']}",
                )
            )
        return Evaluation(findings, [(FindingSource.CLOUD_GUARD, PROBLEM_RULE)])


class SecurityZonesCollector(TenancyScoped):
    dataset = "security_zones.zones"
    tier = 1
    depends_on: tuple[str, ...] = ("cloud_guard.configuration", "identity.compartments")

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]:
        _reporting_region(ctx)
        return [ctx.scope(self.dataset)]

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        cg: Any = clients(oci.cloud_guard.CloudGuardClient, _reporting_region(ctx))
        expected = _active_compartments(ctx)
        out = Collected(expected_children=tuple(expected))
        visited: list[str] = []
        for cid in expected:
            try:
                zones = list_all(cg.list_security_zones, compartment_id=cid)
            except oci.exceptions.ServiceError as exc:
                out.errors.append(f"{cid}: {exc.status} {exc.code}")
                continue
            visited.append(cid)
            for z in zones:
                data = pick(to_plain(z), ZONE_FIELDS)
                out.records.append(
                    ctx.envelope(
                        self.dataset,
                        str(data["id"]),
                        data,
                        compartment_ocid=cid,
                        resource_ocid=data["id"],
                    )
                )
        out.visited_children = tuple(visited)
        return out
