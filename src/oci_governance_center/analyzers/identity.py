"""Pure policy and identity analysis over one tenancy's complete inventory; never calls OCI.

Rule specifications are in docs/detections/. Each function covers one analysis scope so a
missing input (for example denied API-key reads) blocks only the rules that depend on it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..models import Finding, FindingSource, Severity
from .policy import Statement, Subject, parse

Row = dict[str, Any]
IAM_RESOURCES = frozenset(
    {
        "users",
        "groups",
        "dynamic-groups",
        "policies",
        "domains",
        "identity-providers",
        "network-sources",
        "authentication-policies",
    }
)
# Application-access groups are used by OGC sign-in, not by OCI policies.
APPLICATION_GROUPS = frozenset({"ogc_admin", "ogc_viewer"})
DEFAULT_DOMAIN = "default"
# Generic rule names for summaries; individual findings carry instance-specific titles.
RULE_TITLES = {
    "POLICY-PARSE-001": "Policy statement could not be analyzed",
    "POL-DUP-001": "Duplicate policy",
    "POL-DUP-002": "Duplicate policy statement",
    "POL-STALE-001": "Statement references missing identities or compartments",
    "POL-UNUSED-001": "Policy has no effect",
    "POL-MANAGE-001": "Grant to manage a resource type",
    "POL-MANAGE-002": "Grant to manage all-resources",
    "POL-IAM-001": "Non-administrator can use or manage IAM resources",
    "POL-ANY-001": "Grant to any-user or any-group",
    "POL-DG-001": "Broad dynamic group is granted manage",
    "POL-XTEN-001": "Cross-tenancy policy statement",
    "IAM-GRP-001": "Group not in use",
    "IAM-GRP-002": "Every member of the group is inactive",
    "IAM-DG-001": "Dynamic group not referenced by any policy",
    "IAM-USR-001": "User is not a member of any group",
    "IAM-USR-002": "User without MFA",
    "IAM-USR-003": "Inactive user",
    "IAM-KEY-001": "API key past rotation age",
}


def timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 value (including a trailing Z); unknown values return None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Analyzed:
    """One parsed statement with its resolution against the tenancy inventory."""

    policy: Row
    statement: Statement
    key: str
    groups: list[Row] = field(default_factory=list)
    dynamic_groups: list[Row] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    # Subjects in identity domains that were not read: neither found nor missing.
    unknown: list[str] = field(default_factory=list)
    target: str = ""  # resolved compartment OCID, or "" when external/unresolved

    @property
    def stale(self) -> bool:
        return bool(self.missing)

    @property
    def administrators_only(self) -> bool:
        subjects = self.statement.subjects
        return bool(subjects) and all(
            s.kind == "group"
            and s.name.casefold() == "administrators"
            and (s.domain or DEFAULT_DOMAIN).casefold() == DEFAULT_DOMAIN
            for s in subjects
        )


class Inventory:
    """Index one tenancy's identity records for name, OCID and compartment resolution."""

    def __init__(
        self,
        tenancy: str,
        records: dict[str, list[Row]],
        scanned_domains: set[str] | None = None,
    ) -> None:
        """scanned_domains lists domains whose groups and dynamic groups were read completely;
        None means every domain present in the records."""
        self.tenancy = tenancy

        def mine(dataset: str) -> list[Row]:
            return [r for r in records.get(dataset, []) if r["scope"]["tenancy"] == tenancy]

        self.compartments = {str(r["data"]["id"]): r["data"] for r in mine("identity.compartments")}
        self.domains = {r["key"]: r["data"] for r in mine("identity.domains")}
        self.users = mine("identity_domains.users")
        self.groups = mine("identity_domains.groups")
        self.dynamic_groups = mine("identity_domains.dynamic_groups")
        self.api_keys = mine("identity_domains.api_keys")
        self.policies = [
            r for r in mine("identity.policies") if r["data"].get("lifecycle_state") != "DELETED"
        ]
        self.scanned = (
            {str(r["scope"]["domain"]) for r in self.groups + self.dynamic_groups}
            if scanned_domains is None
            else set(scanned_domains)
        )
        self.domain_by_name = {
            str(data.get("display_name") or "").casefold(): ocid
            for ocid, data in self.domains.items()
        }
        self.children = {
            (str(data.get("compartment_id")), str(data.get("name") or "").casefold()): data
            for data in self.compartments.values()
        }

    @staticmethod
    def _index(rows: list[Row]) -> tuple[dict[tuple[str, str], Row], dict[str, Row]]:
        by_name = {
            (r["scope"]["domain"], str(r["data"].get("display_name") or "").casefold()): r
            for r in rows
        }
        by_ocid = {str(r["data"].get("ocid")): r for r in rows if r["data"].get("ocid")}
        return by_name, by_ocid

    def resolve_subject(self, subject: Subject) -> tuple[Row | None, bool]:
        """Return (row, known). Unknown means the subject's domain was not read, so its
        absence proves nothing; a subject in a read (or nonexistent) domain is known."""
        rows = self.groups if subject.kind == "group" else self.dynamic_groups
        by_name, by_ocid = self._index(rows)
        if subject.ocid:
            row = by_ocid.get(subject.ocid)
            active = {
                ocid
                for ocid, data in self.domains.items()
                if (data.get("lifecycle_state") or "ACTIVE") == "ACTIVE"
            }
            return row, row is not None or active <= self.scanned
        domain = self.domain_by_name.get((subject.domain or DEFAULT_DOMAIN).casefold())
        if domain is None:
            return None, True
        if domain not in self.scanned:
            return None, False
        return by_name.get((domain, subject.name.casefold())), True

    def resolve_location(self, statement: Statement, attached: str) -> tuple[str, str]:
        """Return (compartment OCID, problem). Relative paths start at the attachment."""
        location = statement.location
        if location.kind == "tenancy":
            return ("", "") if location.value else (self.tenancy, "")
        if location.kind == "compartment_id":
            if location.value == self.tenancy:
                return self.tenancy, ""
            found = self.compartments.get(location.value)
            if found is None:
                return "", f"compartment {location.value} not found"
            if found.get("lifecycle_state") == "DELETED":
                return "", f"compartment {found.get('name')} is deleted"
            return location.value, ""
        current = attached
        for name in location.value.split(":"):
            found = self.children.get((current, name.strip().casefold()))
            if found is None:
                return "", f"compartment {location.value} not found"
            if found.get("lifecycle_state") == "DELETED":
                return "", f"compartment {location.value} is deleted"
            current = str(found["id"])
        return current, ""

    def analyze_statements(self) -> list[Analyzed]:
        analyzed = []
        for policy in self.policies:
            attached = str(policy["data"].get("compartment_id") or self.tenancy)
            for text in policy["data"].get("statements") or []:
                statement = parse(str(text))
                relative = statement.location.kind == "compartment" or not statement.parsed
                key = json.dumps([statement.normalized, attached if relative else ""])
                item = Analyzed(policy, statement, key)
                if statement.parsed and statement.kind in {"allow", "endorse"}:
                    for subject in statement.subjects:
                        if subject.kind not in {"group", "dynamic-group"}:
                            continue
                        row, known = self.resolve_subject(subject)
                        label = subject.ocid or "/".join(
                            filter(None, (subject.domain, subject.name))
                        )
                        if not known:
                            item.unknown.append(
                                f"{subject.kind} {label}: identity domain "
                                + (
                                    "not scanned"
                                    if subject.ocid
                                    else f"{subject.domain or 'Default'} not scanned"
                                )
                            )
                        elif row is None:
                            item.missing.append(f"{subject.kind} {label} not found")
                        elif subject.kind == "group":
                            item.groups.append(row)
                        else:
                            item.dynamic_groups.append(row)
                    if statement.kind == "allow":
                        item.target, problem = self.resolve_location(statement, attached)
                        if problem:
                            item.missing.append(problem)
                analyzed.append(item)
        return analyzed

    def members(self, group: Row) -> list[str]:
        return [
            str(m.get("value"))
            for m in group["data"].get("members") or []
            if (m.get("type") or "User") == "User"
        ]


def finding(
    tenancy: str,
    scope: str,
    rule: str,
    key: str,
    severity: Severity,
    title: str,
    source: FindingSource,
    *,
    description: str = "",
    resource_ocid: str = "",
    resource_type: str = "",
    compartment_ocid: str = "",
    raw_ref: str = "",
) -> Finding:
    ident = hashlib.sha256(json.dumps(["v1", tenancy, scope, key, rule]).encode()).hexdigest()
    return Finding(
        id=ident,
        tenancy=tenancy,
        scope=scope,
        source=source,
        severity=severity,
        title=title,
        rule_id=rule,
        description=description,
        resource_ocid=resource_ocid,
        resource_type=resource_type,
        compartment_ocid=compartment_ocid,
        raw_ref=raw_ref,
    )


def policy_findings(inventory: Inventory, scope: str) -> list[Finding]:
    """POL-* rules, POLICY-PARSE-001 and unused groups/dynamic groups (analysis.policy)."""
    tenancy = inventory.tenancy
    analyzed = inventory.analyze_statements()
    results: list[Finding] = []

    def emit(item: Analyzed, rule: str, severity: Severity, title: str, description: str) -> None:
        policy = item.policy["data"]
        results.append(
            finding(
                tenancy,
                scope,
                rule,
                json.dumps([policy["id"], item.key]),
                severity,
                title,
                "policy",
                description=f"{policy.get('name')}: {item.statement.text}"
                + (f" — {description}" if description else ""),
                resource_ocid=str(policy["id"]),
                resource_type="policy",
                compartment_ocid=str(policy.get("compartment_id") or ""),
                raw_ref=f"identity.policies/{item.policy['key']}",
            )
        )

    for item in analyzed:
        statement = item.statement
        if not statement.parsed:
            emit(item, "POLICY-PARSE-001", "LOW", "Policy statement could not be analyzed", "")
            continue
        if statement.kind in {"endorse", "admit", "define"}:
            emit(item, "POL-XTEN-001", "INFO", "Cross-tenancy policy statement", "")
            if statement.kind != "endorse":
                continue
        if item.stale:
            emit(
                item,
                "POL-STALE-001",
                "MEDIUM",
                "Policy statement references missing identities or compartments",
                "; ".join(item.missing),
            )
        in_tenancy = statement.location.kind == "tenancy" and not statement.location.value
        if statement.manage and statement.resource == "all-resources":
            if item.administrators_only:
                emit(item, "POL-MANAGE-002", "INFO", "Administrators manage all-resources", "")
            else:
                emit(
                    item,
                    "POL-MANAGE-002",
                    "CRITICAL" if in_tenancy else "HIGH",
                    "Grant to manage all-resources"
                    + (" in the tenancy" if in_tenancy else " in a compartment"),
                    "",
                )
        elif statement.manage:
            emit(
                item,
                "POL-MANAGE-001",
                "MEDIUM" if in_tenancy else "LOW",
                f"Grant to manage {statement.resource}",
                "",
            )
        if (
            statement.verb in {"use", "manage"}
            and statement.resource in IAM_RESOURCES
            and not item.administrators_only
        ):
            emit(
                item,
                "POL-IAM-001",
                "HIGH",
                f"Non-administrator can {statement.verb} {statement.resource}",
                "IAM resource access can be used to escalate privileges.",
            )
        if any(s.kind in {"any-user", "any-group"} for s in statement.subjects):
            emit(
                item,
                "POL-ANY-001",
                "HIGH" if statement.manage and not statement.condition else "MEDIUM",
                "Grant to any-user or any-group",
                "" if statement.condition else "No where-condition restricts the grant.",
            )
        if statement.manage:
            for group in item.dynamic_groups:
                rule = str(group["data"].get("matching_rule") or "")
                if tenancy.casefold() in rule.casefold() or not re.search(r"\.id\s*=", rule):
                    emit(
                        item,
                        "POL-DG-001",
                        "MEDIUM",
                        "Broad dynamic group is granted manage",
                        f"{group['data'].get('display_name')} matches {rule}",
                    )

    # Duplicate policies: identical statement sets (relative paths compared per attachment).
    by_policy: dict[str, list[Analyzed]] = defaultdict(list)
    for item in analyzed:
        by_policy[str(item.policy["data"]["id"])].append(item)
    groups: dict[frozenset[str], list[str]] = defaultdict(list)
    for policy_id, items in by_policy.items():
        groups[frozenset(item.key for item in items)].append(policy_id)
    duplicated = {pid: ids for ids in groups.values() if len(ids) > 1 for pid in ids}
    names = {pid: items[0].policy["data"].get("name") for pid, items in by_policy.items()}
    for policy_id, ids in duplicated.items():
        item = by_policy[policy_id][0]
        others = ", ".join(sorted(str(names[o]) for o in ids if o != policy_id))
        policy = item.policy["data"]
        results.append(
            finding(
                tenancy,
                scope,
                "POL-DUP-001",
                policy_id,
                "LOW",
                "Duplicate policy",
                "policy",
                description=f"{policy.get('name')} has the same statements as {others}",
                resource_ocid=policy_id,
                resource_type="policy",
                compartment_ocid=str(policy.get("compartment_id") or ""),
                raw_ref=f"identity.policies/{item.policy['key']}",
            )
        )
    # Duplicate statements, excluding repeats fully explained by duplicate policies.
    occurrences: dict[str, list[Analyzed]] = defaultdict(list)
    for item in analyzed:
        occurrences[item.key].append(item)
    for key, items in occurrences.items():
        owners = [str(item.policy["data"]["id"]) for item in items]
        if len(items) < 2 or (
            len(set(owners)) == len(owners) and all(owner in duplicated for owner in owners)
        ):
            continue
        listed = ", ".join(sorted({str(names[o]) for o in owners}))
        first = items[0]
        results.append(
            finding(
                tenancy,
                scope,
                "POL-DUP-002",
                key,
                "INFO",
                "Duplicate policy statement",
                "policy",
                description=f"{first.statement.text} appears {len(items)} times in {listed}",
                resource_ocid=owners[0],
                resource_type="policy-statement",
                compartment_ocid=str(first.policy["data"].get("compartment_id") or ""),
                raw_ref=f"identity.policies/{first.policy['key']}",
            )
        )
    # Policies whose every statement is ineffective (stale targets or empty/missing subjects).
    for policy_id, items in by_policy.items():
        grants = [item for item in items if item.statement.kind in {"allow", "endorse"}]
        if not grants or any(not i.statement.parsed or i.unknown for i in items):
            continue  # unparsed or unscanned-domain subjects: effect cannot be judged

        def effective(item: Analyzed) -> bool:
            if item.target == "" and item.statement.kind == "allow":
                return False
            subjects = item.statement.subjects
            if any(s.kind not in {"group", "dynamic-group"} for s in subjects):
                return True
            return bool(item.dynamic_groups) or any(inventory.members(g) for g in item.groups)

        if not any(effective(item) for item in grants):
            policy = items[0].policy["data"]
            results.append(
                finding(
                    tenancy,
                    scope,
                    "POL-UNUSED-001",
                    policy_id,
                    "LOW",
                    "Policy has no effect",
                    "policy",
                    description=f"{policy.get('name')}: every statement names missing or empty "
                    "groups, missing dynamic groups or missing/deleted compartments",
                    resource_ocid=policy_id,
                    resource_type="policy",
                    compartment_ocid=str(policy.get("compartment_id") or ""),
                    raw_ref=f"identity.policies/{items[0].policy['key']}",
                )
            )
    # Groups and dynamic groups not referenced by any grant.
    referenced = {g["key"] for item in analyzed for g in item.groups}
    referenced_dynamic = {g["key"] for item in analyzed for g in item.dynamic_groups}
    for group in inventory.groups:
        data = group["data"]
        name = str(data.get("display_name") or group["key"])
        domain = inventory.domains.get(group["scope"]["domain"], {})
        if name in APPLICATION_GROUPS and str(domain.get("display_name")) == "Default":
            continue
        reasons = []
        if not inventory.members(group):
            reasons.append("has no members")
        if group["key"] not in referenced:
            reasons.append("is not referenced by any policy")
        if reasons:
            results.append(
                finding(
                    tenancy,
                    scope,
                    "IAM-GRP-001",
                    group["key"],
                    "LOW",
                    "Group not in use",
                    "identity",
                    description=f"{name} ({domain.get('display_name', 'unknown domain')}) "
                    + " and ".join(reasons),
                    resource_ocid=str(data.get("ocid") or ""),
                    resource_type="group",
                    raw_ref=f"identity_domains.groups/{group['key']}",
                )
            )
    for group in inventory.dynamic_groups:
        if group["key"] in referenced_dynamic:
            continue
        data = group["data"]
        domain = inventory.domains.get(group["scope"]["domain"], {})
        results.append(
            finding(
                tenancy,
                scope,
                "IAM-DG-001",
                group["key"],
                "LOW",
                "Dynamic group not referenced by any policy",
                "identity",
                description=f"{data.get('display_name')} "
                f"({domain.get('display_name', 'unknown domain')})",
                resource_ocid=str(data.get("ocid") or ""),
                resource_type="dynamic-group",
                raw_ref=f"identity_domains.dynamic_groups/{group['key']}",
            )
        )
    return results


def user_label(inventory: Inventory, user: Row) -> str:
    domain = inventory.domains.get(user["scope"]["domain"], {})
    return f"{user['data'].get('user_name')} ({domain.get('display_name', 'unknown domain')})"


def identity_findings(inventory: Inventory, scope: str) -> list[Finding]:
    """IAM-USR-001 (no group) and IAM-USR-002 (no MFA) (analysis.identity)."""
    tenancy = inventory.tenancy
    members = {m for group in inventory.groups for m in inventory.members(group)}
    # MFA is judged only in domains where OCI returned the attribute for at least one user;
    # elsewhere it was not collected or not readable, which is unknown, not "no MFA".
    mfa_domains = {
        u["scope"]["domain"] for u in inventory.users if u["data"].get("mfa_status") is not None
    }
    results = []
    for user in inventory.users:
        data = user["data"]
        if data.get("active") is False:
            continue
        common = {
            "resource_ocid": str(data.get("ocid") or ""),
            "resource_type": "user",
            "raw_ref": f"identity_domains.users/{user['key']}",
        }
        if str(data.get("id")) not in members:
            results.append(
                finding(
                    tenancy,
                    scope,
                    "IAM-USR-001",
                    user["key"],
                    "LOW",
                    "User is not a member of any group",
                    "identity",
                    description=user_label(inventory, user),
                    **common,
                )
            )
        if (
            user["scope"]["domain"] in mfa_domains
            and data.get("federated") is not True
            and data.get("service_user") is not True
            and data.get("mfa_status") != "ENROLLED"
        ):
            results.append(
                finding(
                    tenancy,
                    scope,
                    "IAM-USR-002",
                    user["key"],
                    "HIGH",
                    "User without MFA",
                    "identity",
                    description=f"{user_label(inventory, user)}: MFA status "
                    f"{data.get('mfa_status') or 'not reported'}",
                    **common,
                )
            )
    return results


def api_key_findings(
    inventory: Inventory, scope: str, instant: datetime, max_age_days: int
) -> list[Finding]:
    """IAM-KEY-001: API keys older than the rotation age; OCI API keys have no expiry."""
    users = {str(u["data"].get("id")): u for u in inventory.users}
    results = []
    for key in inventory.api_keys:
        created = timestamp(key["data"].get("created"))
        if created is None or instant - created <= timedelta(days=max_age_days):
            continue
        owner = users.get(str(key["data"].get("user_id")))
        label = user_label(inventory, owner) if owner else str(key["data"].get("user_id"))
        results.append(
            finding(
                inventory.tenancy,
                scope,
                "IAM-KEY-001",
                key["key"],
                "MEDIUM",
                f"API key older than {max_age_days} days",
                "identity",
                description=f"{label}: key created {created.date().isoformat()} "
                f"({(instant - created).days} days ago). OCI API keys do not expire; rotate it.",
                resource_ocid=str(key["data"].get("ocid") or ""),
                resource_type="api-key",
                raw_ref=f"identity_domains.api_keys/{key['key']}",
            )
        )
    return results


def activity_findings(
    inventory: Inventory,
    scope: str,
    instant: datetime,
    inactive_days: int,
    active_principals: set[str],
) -> list[Finding]:
    """IAM-USR-003 inactive users and IAM-GRP-002 groups of inactive users (analysis.activity).

    Callers must only invoke this when Audit coverage spans the whole window.
    """
    since = instant - timedelta(days=inactive_days)
    inactive: dict[str, Row] = {}
    for user in inventory.users:
        data = user["data"]
        if data.get("active") is False:
            continue
        login = timestamp(data.get("last_successful_login"))
        if (login is None or login < since) and str(data.get("ocid")) not in active_principals:
            inactive[str(data.get("id"))] = user
    results = [
        finding(
            inventory.tenancy,
            scope,
            "IAM-USR-003",
            user["key"],
            "LOW",
            f"User inactive for {inactive_days} days",
            "identity",
            description=f"{user_label(inventory, user)}: no successful sign-in and no Audit "
            f"activity since {since.date().isoformat()}",
            resource_ocid=str(user["data"].get("ocid") or ""),
            resource_type="user",
            raw_ref=f"identity_domains.users/{user['key']}",
        )
        for user in inactive.values()
    ]
    for group in inventory.groups:
        members = inventory.members(group)
        if members and all(member in inactive for member in members):
            data = group["data"]
            results.append(
                finding(
                    inventory.tenancy,
                    scope,
                    "IAM-GRP-002",
                    group["key"],
                    "LOW",
                    "Every member of this group is inactive",
                    "identity",
                    description=f"{data.get('display_name')}: {len(members)} inactive member(s)",
                    resource_ocid=str(data.get("ocid") or ""),
                    resource_type="group",
                    raw_ref=f"identity_domains.groups/{group['key']}",
                )
            )
    return results
