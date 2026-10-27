"""View models for the governance tabs: pure functions over stored rows; never call OCI."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from ..analyzers.identity import RULE_TITLES, Inventory, timestamp
from ..models import SEVERITIES, Finding, now

Row = dict[str, Any]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


def records_by_dataset(rows: list[Row]) -> dict[str, list[Row]]:
    """Group stored records by dataset with their scope and data decoded."""
    grouped: dict[str, list[Row]] = defaultdict(list)
    for row in rows:
        scope = json.loads(row["scope"])
        grouped[scope["dataset"]].append(
            {
                "scope": scope,
                "key": row["key"],
                "data": json.loads(row["data"]),
                "collected": row["collected"],
            }
        )
    return grouped


def parse_findings(rows: list[Row]) -> list[Finding]:
    """Decode stored findings; Store.rows has already validated them."""
    return [Finding.model_validate_json(row["data"]) for row in rows]


def coverage_gaps(rows: list[Row], prefixes: tuple[str, ...]) -> dict[str, list[Row]]:
    """Incomplete coverage rows for the given dataset prefixes, keyed by tenancy."""
    gaps: dict[str, list[Row]] = defaultdict(list)
    for row in rows:
        scope = json.loads(row["scope"])
        if row["status"] != "complete" and scope["dataset"].startswith(prefixes):
            gaps[scope["tenancy"]].append({**row, "scope": scope})
    return gaps


def when(value: Any) -> str:
    """Display an ISO-8601 timestamp as UTC minutes; anything else is shown unchanged."""
    parsed = timestamp(value)
    if parsed is None:
        return "" if value is None else str(value)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def contains(needle: str, *values: Any) -> bool:
    """Case-insensitive substring match over several display values."""
    return not needle or needle.casefold() in " ".join(str(v or "") for v in values).casefold()


def cloud_guard(
    records: dict[str, list[Row]],
    findings: list[Finding],
    coverage: list[Row],
    tenancies: list[tuple[str, str]],
    filters: dict[str, str],
) -> dict[str, Any]:
    """Per-tenancy Cloud Guard status, mirrored problems and Security Zones."""
    labels = dict(tenancies)
    configuration = {r["scope"]["tenancy"]: r["data"] for r in records["cloud_guard.configuration"]}
    problems = {
        f"cloud_guard.problems/{r['key']}": r["data"] for r in records["cloud_guard.problems"]
    }
    gaps = coverage_gaps(coverage, ("cloud_guard.", "security_zones."))
    mirrored = [f for f in findings if f.rule_id == "CG-PROBLEM"]
    summaries = []
    for ocid, label in tenancies:
        config = configuration.get(ocid)
        open_problems = [f for f in mirrored if f.tenancy == ocid and f.status == "open"]
        summaries.append(
            {
                "tenancy": ocid,
                "label": label,
                "status": (config or {}).get("status") or "Not collected",
                "enabled": bool(config and config.get("status") == "ENABLED"),
                "reporting_region": (config or {}).get("reporting_region") or "",
                "counts": {
                    severity: sum(f.severity == severity for f in open_problems)
                    for severity in SEVERITIES
                },
                "gaps": gaps.get(ocid, []),
            }
        )
    rows = []
    for finding in mirrored:
        # Open problems join their current record; resolved ones keep the finding's details.
        detail = problems.get(finding.raw_ref, {})
        rows.append(
            {
                "finding": finding,
                "tenancy_label": labels.get(finding.tenancy, finding.tenancy),
                "type": "Security Zone" if finding.source == "security_zone" else "Cloud Guard",
                "resource_name": detail.get("resource_name") or finding.title,
                "resource_type": detail.get("resource_type") or finding.resource_type,
                "region": detail.get("region") or json.loads(finding.scope).get("region", ""),
                "detector_rule": detail.get("detector_rule_id") or finding.description,
                "first_detected": detail.get("time_first_detected") or finding.first_seen,
                "last_detected": detail.get("time_last_detected") or finding.last_seen,
            }
        )
    options = {
        "region": sorted({r["region"] for r in rows if r["region"]}),
        "resource_type": sorted({r["resource_type"] for r in rows if r["resource_type"]}),
    }
    rows = [
        r
        for r in rows
        if (not filters["tenancy"] or r["finding"].tenancy == filters["tenancy"])
        and (not filters["severity"] or r["finding"].severity == filters["severity"])
        and (not filters["source"] or r["finding"].source == filters["source"])
        and (not filters["region"] or r["region"] == filters["region"])
        and (not filters["resource_type"] or r["resource_type"] == filters["resource_type"])
        and (not filters["status"] or r["finding"].status == filters["status"])
        and contains(filters["q"], r["resource_name"], r["detector_rule"], r["finding"].title)
    ]
    rows.sort(key=lambda r: str(r["last_detected"]), reverse=True)
    rows.sort(key=lambda r: (r["finding"].status != "open", SEVERITY_RANK[r["finding"].severity]))
    zones = [
        {**r["data"], "tenancy_label": labels.get(r["scope"]["tenancy"], r["scope"]["tenancy"])}
        for r in records["security_zones.zones"]
        if not filters["tenancy"] or r["scope"]["tenancy"] == filters["tenancy"]
    ]
    zones.sort(key=lambda zone: (zone["tenancy_label"], str(zone.get("display_name") or "")))
    return {"summaries": summaries, "problems": rows, "zones": zones, "options": options}


def cloud_advisor(
    records: dict[str, list[Row]],
    coverage: list[Row],
    tenancies: list[tuple[str, str]],
    filters: dict[str, str],
) -> dict[str, Any]:
    """Per-tenancy Cloud Advisor enrollment and recommendations with category names."""
    labels = dict(tenancies)
    categories = {
        r["key"]: r["data"].get("name") or r["key"] for r in records["optimizer.categories"]
    }
    enrollment: dict[str, list[str]] = defaultdict(list)
    for record in records["optimizer.enrollment"]:
        enrollment[record["scope"]["tenancy"]].append(str(record["data"].get("status") or ""))
    collected = {
        json.loads(row["scope"])["tenancy"]
        for row in coverage
        if json.loads(row["scope"])["dataset"] == "optimizer.enrollment" and row["succeeded"]
    }
    gaps = coverage_gaps(coverage, ("optimizer.",))
    rows = [
        {
            **r["data"],
            "tenancy": r["scope"]["tenancy"],
            "tenancy_label": labels.get(r["scope"]["tenancy"], r["scope"]["tenancy"]),
            "category": categories.get(str(r["data"].get("category_id")), "Unknown category"),
            "saving": float(r["data"].get("estimated_cost_saving") or 0),
        }
        for r in records["optimizer.recommendations"]
    ]
    summaries = []
    for ocid, label in tenancies:
        statuses = enrollment.get(ocid, [])
        pending = [r for r in rows if r["tenancy"] == ocid and r.get("status") == "PENDING"]
        summaries.append(
            {
                "tenancy": ocid,
                "label": label,
                "status": (
                    ", ".join(sorted(set(statuses)))
                    if statuses
                    else "Not enrolled"
                    if ocid in collected
                    else "Not collected"
                ),
                "enrolled": any(s in {"ACTIVE", "ENROLLED"} for s in statuses),
                "pending": len(pending),
                "saving": sum(r["saving"] for r in pending),
                "gaps": gaps.get(ocid, []),
            }
        )
    options = {
        "importance": sorted({str(r["importance"]) for r in rows if r.get("importance")}),
        "status": sorted({str(r["status"]) for r in rows if r.get("status")}),
        "category": sorted(
            {(str(r.get("category_id")), r["category"]) for r in rows}, key=lambda c: c[1]
        ),
    }
    rows = [
        r
        for r in rows
        if (not filters["tenancy"] or r["tenancy"] == filters["tenancy"])
        and (not filters["importance"] or r.get("importance") == filters["importance"])
        and (not filters["status"] or r.get("status") == filters["status"])
        and (not filters["category"] or str(r.get("category_id")) == filters["category"])
        and contains(filters["q"], r.get("name"), r.get("description"), r["category"])
    ]
    rows.sort(key=lambda r: (r.get("status") != "PENDING", -r["saving"], str(r.get("name"))))
    return {
        "summaries": summaries,
        "recommendations": rows,
        "total_saving": sum(r["saving"] for r in rows if r.get("status") == "PENDING"),
        "options": options,
    }


def compartment_tree(
    records: dict[str, list[Row]],
    coverage: list[Row],
    tenancy: str,
    label: str,
    include_deleted: bool = False,
    policies_enabled: bool = True,
) -> dict[str, Any]:
    """Nest a tenancy's collected compartments under its root, sorted by name.

    Each node counts the statements of policies attached to it (``own``) and that count plus
    every compartment above it up to the tenancy (``hierarchy``). Counts are None unless every
    compartment's policy read is complete, so a gap never reads as zero statements.
    """
    rows = [
        r["data"]
        for r in records["identity.compartments"]
        if r["scope"]["tenancy"] == tenancy
        and (include_deleted or r["data"].get("lifecycle_state") != "DELETED")
    ]
    nodes: dict[str, Row] = {
        str(row["id"]): {
            "id": row["id"],
            "name": row.get("name") or row["id"],
            "state": row.get("lifecycle_state") or "",
            "created": row.get("time_created") or "",
            "children": [],
            "orphan": False,
        }
        for row in rows
    }
    root: Row = {"id": tenancy, "name": label, "state": "ACTIVE", "children": [], "orphan": False}
    for row in rows:
        node = nodes[str(row["id"])]
        parent = nodes.get(str(row.get("compartment_id")))
        if parent is not None:
            parent["children"].append(node)
        else:
            # The tenancy is the root; any other missing parent is shown, never dropped.
            node["orphan"] = row.get("compartment_id") != tenancy
            root["children"].append(node)

    def finish(node: Row) -> int:
        node["children"].sort(key=lambda child: str(child["name"]).casefold())
        node["descendants"] = sum(1 + finish(child) for child in node["children"])
        return int(node["descendants"])

    finish(root)
    scopes = [json.loads(row["scope"]) | {"row": row} for row in coverage]
    policy_scopes = [
        s["row"] for s in scopes if s["tenancy"] == tenancy and s["dataset"] == "identity.policies"
    ]
    policy_state = (
        "disabled"
        if not policies_enabled
        else "missing"
        if not policy_scopes
        else "incomplete"
        if any(row["status"] != "complete" for row in policy_scopes)
        else "complete"
    )
    own: dict[str, int] = defaultdict(int)
    for policy in records["identity.policies"]:
        data = policy["data"]
        if policy["scope"]["tenancy"] == tenancy and data.get("lifecycle_state") != "DELETED":
            own[str(data.get("compartment_id") or tenancy)] += len(data.get("statements") or [])

    def count(node: Row, above: int) -> None:
        known = policy_state == "complete"
        node["own"] = own[str(node["id"])] if known else None
        node["hierarchy"] = above + own[str(node["id"])] if known else None
        for child in node["children"]:
            count(child, above + own[str(node["id"])])

    count(root, 0)
    status = next(
        (
            s["row"]
            for s in scopes
            if s["tenancy"] == tenancy and s["dataset"] == "identity.compartments"
        ),
        None,
    )
    return {
        "tree": root,
        "count": len(nodes),
        "collected": status["succeeded"] if status else None,
        "incomplete": status is not None and status["status"] != "complete",
        "error": status["error"] if status else "",
        "policy_state": policy_state,
    }


IDENTITY_VIEWS = ("users", "groups", "dynamic-groups", "policies", "analysis")


def compartment_paths(records: dict[str, list[Row]], labels: dict[str, str]) -> dict[str, str]:
    """Readable root:child:grandchild paths for every collected compartment."""
    data = {str(r["data"]["id"]): r["data"] for r in records["identity.compartments"]}
    tenancy_of = {
        str(r["data"]["id"]): r["scope"]["tenancy"] for r in records["identity.compartments"]
    }
    paths: dict[str, str] = {
        ocid: label.removesuffix(" (parent)") for ocid, label in labels.items()
    }

    def path(ocid: str, depth: int = 0) -> str:
        if ocid in paths or depth > 64:
            return paths.get(ocid, ocid)
        item = data.get(ocid)
        if item is None:
            return ocid
        parent = str(item.get("compartment_id") or tenancy_of.get(ocid, ""))
        paths[ocid] = f"{path(parent, depth + 1)}:{item.get('name')}"
        return paths[ocid]

    for ocid in data:
        path(ocid)
    return paths


def identity(
    records: dict[str, list[Row]],
    findings: list[Finding],
    tenancies: list[tuple[str, str]],
    filters: dict[str, str],
    view: str,
    api_key_max_age_days: int,
    coverage: list[Row] | None = None,
) -> dict[str, Any]:
    """Users, groups, dynamic groups, policies and analysis findings for the Identity tab."""
    labels = dict(tenancies)
    domains = {r["key"]: r for r in records["identity.domains"]}
    domain_options = sorted(
        (
            (key, f"{r['data'].get('display_name')} — {labels.get(r['scope']['tenancy'], '')}")
            for key, r in domains.items()
            if not filters["tenancy"] or r["scope"]["tenancy"] == filters["tenancy"]
        ),
        key=lambda option: option[1],
    )

    def in_scope(row: Row) -> bool:
        return (not filters["tenancy"] or row["scope"]["tenancy"] == filters["tenancy"]) and (
            not filters["domain"] or row["scope"].get("domain") == filters["domain"]
        )

    def domain_name(row: Row) -> str:
        return str(
            domains.get(row["scope"].get("domain", ""), {}).get("data", {}).get("display_name")
            or "Unknown domain"
        )

    # One badge per open rule and resource, with its count and most severe level.
    grouped: dict[str, dict[str, Row]] = defaultdict(dict)
    for item in findings:
        if item.status == "open" and item.resource_ocid and item.source in {"policy", "identity"}:
            entry = grouped[item.resource_ocid].setdefault(
                item.rule_id,
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity,
                    "count": 0,
                    "title": RULE_TITLES.get(item.rule_id, item.title),
                },
            )
            entry["count"] += 1
            if SEVERITY_RANK[item.severity] < SEVERITY_RANK[entry["severity"]]:
                entry["severity"] = item.severity
    badges = {
        ocid: sorted(rules.values(), key=lambda b: (SEVERITY_RANK[b["severity"]], b["rule_id"]))
        for ocid, rules in grouped.items()
    }
    # Reference counts use the same resolution as the analysis rules.
    group_refs: dict[str, set[str]] = {}
    dynamic_refs: dict[str, set[str]] = {}
    unknown: dict[str, dict[str, list[str]]] = defaultdict(dict)
    for ocid in labels:
        for analyzed in Inventory(ocid, records).analyze_statements():
            policy_id = str(analyzed.policy["data"]["id"])
            if analyzed.unknown:
                unknown[policy_id][analyzed.statement.text] = analyzed.unknown
            for group in analyzed.groups:
                group_refs.setdefault(group["key"], set()).add(policy_id)
            for group in analyzed.dynamic_groups:
                dynamic_refs.setdefault(group["key"], set()).add(policy_id)
    result: dict[str, Any] = {"domain_options": domain_options, "rows": []}
    instant = now()
    if view == "users":
        member_of: dict[str, int] = {}
        for group in records["identity_domains.groups"]:
            for member in group["data"].get("members") or []:
                member_of[str(member.get("value"))] = member_of.get(str(member.get("value")), 0) + 1
        mfa_domains = {
            u["scope"].get("domain", "")
            for u in records["identity_domains.users"]
            if u["data"].get("mfa_status") is not None
        }
        key_scopes = {
            scope["domain"]: row
            for row in coverage or []
            if (scope := json.loads(row["scope"]))["dataset"] == "identity_domains.api_keys"
        }
        keys: dict[str, list[datetime]] = {}
        for api_key in records["identity_domains.api_keys"]:
            stamp = timestamp(api_key["data"].get("created"))
            if stamp:
                keys.setdefault(str(api_key["data"].get("user_id")), []).append(stamp)
        for user in records["identity_domains.users"]:
            data = user["data"]
            if not in_scope(user) or not contains(
                filters["q"], data.get("user_name"), data.get("ocid")
            ):
                continue
            domain = user["scope"].get("domain", "")
            if data.get("mfa_status") == "ENROLLED":
                mfa = "ENROLLED"
            elif domain in mfa_domains:
                mfa = "not_enrolled"
            else:
                mfa = "unknown"  # not collected, or not returned for any user in this domain
            if filters["mfa"] and filters["mfa"] != mfa:
                continue
            created_keys = keys.get(str(data.get("id")), [])
            key_coverage = key_scopes.get(domain)
            result["rows"].append(
                {
                    **data,
                    "domain": domain_name(user),
                    "tenancy_label": labels.get(user["scope"]["tenancy"], ""),
                    "groups": member_of.get(str(data.get("id")), 0),
                    "mfa": mfa,
                    "sign_in_collected": "last_successful_login" in data,
                    # Counts are shown only from a completed read; otherwise they are unknown.
                    "keys_collected": bool(key_coverage and key_coverage["succeeded"]),
                    "keys_stale": bool(key_coverage and key_coverage["status"] != "complete"),
                    "api_keys": len(created_keys),
                    "oldest_key_days": max(
                        ((instant - c).days for c in created_keys), default=None
                    ),
                    "badges": badges.get(str(data.get("ocid")), []),
                }
            )
        result["rows"].sort(key=lambda r: str(r.get("user_name") or "").casefold())
    elif view in {"groups", "dynamic-groups"}:
        dataset = (
            "identity_domains.groups" if view == "groups" else "identity_domains.dynamic_groups"
        )
        references = group_refs if view == "groups" else dynamic_refs
        for group in records[dataset]:
            data = group["data"]
            if not in_scope(group) or not contains(
                filters["q"], data.get("display_name"), data.get("matching_rule")
            ):
                continue
            result["rows"].append(
                {
                    **data,
                    "domain": domain_name(group),
                    "tenancy_label": labels.get(group["scope"]["tenancy"], ""),
                    "member_count": len(data.get("members") or []),
                    "policies": len(references.get(group["key"], set())),
                    "badges": badges.get(str(data.get("ocid")), []),
                }
            )
        result["rows"].sort(key=lambda r: str(r.get("display_name") or "").casefold())
    elif view == "policies":
        paths = compartment_paths(records, labels)
        for policy in records["identity.policies"]:
            policy_data = policy["data"]
            if filters["tenancy"] and policy["scope"]["tenancy"] != filters["tenancy"]:
                continue
            attached = str(policy_data.get("compartment_id") or policy["scope"]["tenancy"])
            if filters.get("compartment") and attached != filters["compartment"]:
                continue
            if not contains(
                filters["q"], policy_data.get("name"), *(policy_data.get("statements") or [])
            ):
                continue
            compartment = str(policy_data.get("compartment_id") or policy["scope"]["tenancy"])
            result["rows"].append(
                {
                    **policy_data,
                    "path": paths.get(compartment, compartment),
                    "tenancy_label": labels.get(policy["scope"]["tenancy"], ""),
                    "badges": badges.get(str(policy_data.get("id")), []),
                    # Statements naming groups in unscanned domains are not analyzed.
                    "not_analyzed": unknown.get(str(policy_data.get("id")), {}),
                }
            )
        result["rows"].sort(key=lambda r: (r["path"].casefold(), str(r.get("name")).casefold()))
        result["not_analyzed"] = sum(len(r["not_analyzed"]) for r in result["rows"])
        if filters.get("compartment"):
            result["compartment_label"] = paths.get(filters["compartment"], filters["compartment"])
    else:
        analysis = [f for f in findings if f.source in {"policy", "identity"}]
        result["rules"] = sorted({f.rule_id for f in analysis})
        rows = [
            f
            for f in analysis
            if (not filters["tenancy"] or f.tenancy == filters["tenancy"])
            and (not filters["rule"] or f.rule_id == filters["rule"])
            and (not filters["severity"] or f.severity == filters["severity"])
            and (not filters["status"] or f.status == filters["status"])
            and contains(filters["q"], f.title, f.description)
        ]
        rows.sort(key=lambda f: (f.status != "open", SEVERITY_RANK[f.severity], f.rule_id))
        summary: dict[str, dict[str, Any]] = {}
        for f in rows:
            entry = summary.setdefault(
                f.rule_id,
                {
                    "rule": f.rule_id,
                    "title": RULE_TITLES.get(f.rule_id, f.title),
                    "count": 0,
                    "severity": f.severity,
                },
            )
            entry["count"] += 1
            if SEVERITY_RANK[f.severity] < SEVERITY_RANK[entry["severity"]]:
                entry["severity"] = f.severity
        result["rows"] = [
            {"finding": f, "tenancy_label": labels.get(f.tenancy, f.tenancy)} for f in rows
        ]
        result["summary"] = sorted(
            summary.values(), key=lambda e: (SEVERITY_RANK[e["severity"]], e["rule"])
        )
    result["api_key_max_age_days"] = api_key_max_age_days
    return result


COST_VIEWS = ("tenancy", "service", "compartment")
Money = dict[str, float]


def add(total: Money, currency: str, amount: float) -> None:
    total[currency] = total.get(currency, 0.0) + amount


def money(value: Money | None) -> str:
    """Format per-currency totals without mixing currencies; None means unknown."""
    if value is None:
        return "—"
    if not value:
        return "0.00"
    return " · ".join(f"{currency} {amount:,.2f}" for currency, amount in sorted(value.items()))


def cost(
    records: dict[str, list[Row]],
    coverage: list[Row],
    tenancies: list[tuple[str, str]],
    filters: dict[str, str],
    view: str,
    parent: str,
    enabled: bool = True,
) -> dict[str, Any]:
    """Organization cost by tenancy, service or compartment from the parent's Usage API data.

    Amounts stay per currency. The compartment view rolls each node's own cost up into its
    ancestors, using the compartment path reported by OCI.
    """
    labels = dict(tenancies)
    status = next(
        (
            row
            for row in coverage
            if (scope := json.loads(row["scope"]))["dataset"] == "cost.monthly"
            and scope["tenancy"] == parent
        ),
        None,
    )
    state = (
        "disabled"
        if not enabled
        else "missing"
        if status is None
        else "incomplete"
        if status["status"] != "complete"
        else "complete"
    )
    rows = [r["data"] for r in records["cost.monthly"] if r["scope"]["tenancy"] == parent]
    months = sorted({str(r["month"]) for r in rows})
    current = now().strftime("%Y-%m")
    start = filters["month_from"] or (months[-2] if len(months) > 1 else current)
    end = filters["month_to"] or (months[-1] if months else current)
    if start > end:
        start, end = end, start

    def tenant(row: Row) -> str:
        ident = str(row.get("tenant_id") or "")
        return labels.get(ident) or str(row.get("tenant_name") or ident or "Unknown tenancy")

    def matches(row: Row, *, months_too: bool = True) -> bool:
        return (
            (not months_too or start <= str(row["month"]) <= end)
            and (not filters["tenancy"] or row.get("tenant_id") == filters["tenancy"])
            and (not filters["service"] or row.get("service") == filters["service"])
            and contains(filters["q"], row.get("compartment_path"))
        )

    selected = [r for r in rows if matches(r)]
    total: Money = {}
    for r in selected:
        add(total, str(r.get("currency") or ""), float(r.get("amount") or 0))
    trend: dict[str, Money] = {month: {} for month in months}
    for r in rows:
        if matches(r, months_too=False):
            add(trend[str(r["month"])], str(r.get("currency") or ""), float(r.get("amount") or 0))
    peak = max((sum(m.values()) for m in trend.values()), default=0.0) or 1.0

    def grouped(key: Any) -> list[Row]:
        groups: dict[str, Money] = {}
        for r in selected:
            add(groups.setdefault(key(r), {}), str(r.get("currency") or ""), float(r["amount"]))
        result: list[Row] = [
            {
                "name": name,
                "amount": amounts,
                "share": {
                    c: (a / total[c] * 100 if total.get(c) else 0.0) for c, a in amounts.items()
                },
            }
            for name, amounts in groups.items()
        ]
        result.sort(key=lambda g: -sum(g["amount"].values()))
        return result

    by_service = grouped(lambda r: str(r.get("service") or "Unattributed"))
    result: dict[str, Any] = {
        "state": state,
        "collected": status["succeeded"] if status else None,
        "error": status["error"] if status else "",
        "months": months,
        "month_from": start,
        "month_to": end,
        "current_month": current,
        "total": total,
        "trend": [
            {"month": m, "amount": a, "width": round(sum(a.values()) / peak * 100, 1)}
            for m, a in trend.items()
        ],
        "top_services": by_service[:5],
        "services": sorted({str(r.get("service")) for r in rows if r.get("service")}),
        "children_missing": bool(rows) and len({r.get("tenant_id") for r in rows}) < 2,
        "rows": [],
    }
    if view == "tenancy":
        ids = {tenant(r): str(r.get("tenant_id") or "") for r in selected}
        result["rows"] = [g | {"tenant_id": ids.get(g["name"], "")} for g in grouped(tenant)]
    elif view == "service":
        result["rows"] = by_service
    else:
        result["tree"] = cost_tree(selected, filters["tenancy"] or parent, labels)
    return result


def cost_tree(rows: list[Row], tenancy: str, labels: dict[str, str]) -> Row:
    """Compartment hierarchy for one tenancy built from OCI compartment paths.

    Each node has its own cost and a rolled-up total including every sub-compartment.
    Compartment names cannot contain "/", so paths split unambiguously.
    """
    root: Row = {"name": labels.get(tenancy, tenancy), "own": {}, "children": {}, "id": tenancy}
    for row in rows:
        if row.get("tenant_id") != tenancy:
            continue
        parts = [p for p in str(row.get("compartment_path") or "").split("/") if p]
        node = root
        # The first path element is the tenancy's root compartment.
        for name in parts[1:]:
            node = node["children"].setdefault(
                name, {"name": name, "own": {}, "children": {}, "id": ""}
            )
        if parts[1:]:
            node["id"] = node["id"] or str(row.get("compartment_id") or "")
        add(node["own"], str(row.get("currency") or ""), float(row.get("amount") or 0))

    def finish(node: Row) -> Money:
        rolled = dict(node["own"])
        children = sorted(node["children"].values(), key=lambda c: str(c["name"]).casefold())
        for child in children:
            for currency, amount in finish(child).items():
                add(rolled, currency, amount)
        node["children"] = children
        node["rolled"] = rolled
        return rolled

    finish(root)
    return root
