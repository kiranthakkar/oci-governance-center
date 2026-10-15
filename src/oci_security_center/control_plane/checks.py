"""Read-only checks: are the required statements present? (docs/control-plane.md §5.3)

Matching is semantic, not byte-exact:

* whitespace/case/quotes are normalized; the statement may live in *any* policy of the tenancy;
* tenancy and group aliases are resolved through ``Define`` statements **of the same policy
  document** (aliases are policy-scoped in OCI), so the IAM admin may use their own alias names, but
  a grant whose definitions live in another policy is not detected; an alias defined inconsistently
  within one policy makes the match ``unknown``;
* group names are resolved to OCIDs when a name→OCID map is supplied;
* a broader grant (higher verb, ``all-resources``, ``any-user``/``any-group``, ``any-tenancy``)
  satisfies the requirement but is reported as ``broader``;
* a matching statement with a ``where`` clause is reported as ``unknown`` (it may be narrower).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from oci_security_center.analyzers.policy.statements import (
    VERB_RANK,
    DefineTable,
    ParsedStatement,
    Subject,
    parse_statement,
)
from oci_security_center.models import CheckStatus, PolicyRequirement, RequirementCheck, utcnow

_RANK = {
    CheckStatus.DETECTED: 3,
    CheckStatus.BROADER: 2,
    CheckStatus.UNKNOWN: 1,
    CheckStatus.MISSING: 0,
}


@dataclass(frozen=True)
class PolicyRecord:
    id: str
    name: str
    statements: tuple[str, ...]


@dataclass(frozen=True)
class _Outcome:
    status: CheckStatus
    detail: str = ""
    policy_id: str | None = None
    statement: str | None = None


def _subject_key(
    s: Subject, defines: DefineTable, names: Mapping[str, str], via_alias: bool
) -> tuple[str, ...]:
    if s.ocid:
        return (s.kind, s.ocid)
    if s.name is None:
        return (s.kind,)
    if via_alias:  # Admit statements reference aliases from Define statements
        table = defines.dynamic_groups if s.kind == "dynamic-group" else defines.groups
        if s.name in table:
            return (s.kind, table[s.name])
    qualified = f"{s.domain or 'default'}/{s.name}"
    if qualified in names:
        return (s.kind, names[qualified])
    return (s.kind, "name", s.domain or "default", s.name)


def _tenancy_key(alias: str | None, defines: DefineTable) -> str | None:
    if alias is None:
        return None
    return defines.tenancies.get(alias, f"alias:{alias}")


def _compare(
    req: ParsedStatement,
    req_defs: DefineTable,
    stmt: ParsedStatement,
    defs: DefineTable,
    names: Mapping[str, str],
) -> CheckStatus | None:
    """Return DETECTED/BROADER/UNKNOWN if ``stmt`` satisfies ``req``, else None."""
    if req.kind == "define":
        if (
            stmt.kind == "define"
            and stmt.define_kind == req.define_kind
            and stmt.define_ocid == req.define_ocid
        ):
            return CheckStatus.DETECTED
        return None
    if stmt.kind != req.kind:
        return None

    broader = False
    via_alias = req.kind == "admit"
    if req.kind == "admit" and (
        _tenancy_key(stmt.source_tenancy, defs) != _tenancy_key(req.source_tenancy, req_defs)
    ):
        return None

    # subjects
    req_subjects = {_subject_key(s, req_defs, names, via_alias) for s in req.subjects}
    stmt_subjects = {_subject_key(s, defs, names, via_alias) for s in stmt.subjects}
    if not req_subjects <= stmt_subjects:
        if any(s.is_wildcard for s in stmt.subjects):
            broader = True
        else:
            return None

    # verb / resource
    if req.verb is None or stmt.verb is None:
        return None
    if VERB_RANK[stmt.verb] < VERB_RANK[req.verb]:
        return None
    if VERB_RANK[stmt.verb] > VERB_RANK[req.verb]:
        broader = True
    if stmt.resource != req.resource:
        if stmt.resource == "all-resources":
            broader = True
        else:
            return None

    # location
    rl, sl = req.location, stmt.location
    if rl is None or sl is None:
        return None
    if req.kind == "endorse":
        if sl.kind == "any-tenancy":
            broader = True
        elif sl.kind != "tenancy" or (
            _tenancy_key(sl.name, defs) != _tenancy_key(rl.name, req_defs)
        ):
            return None
    elif rl.kind == "tenancy" and (sl.kind != "tenancy" or sl.name is not None):
        return None

    if stmt.condition:
        return CheckStatus.UNKNOWN
    return CheckStatus.BROADER if broader else CheckStatus.DETECTED


def check_requirements(
    requirements: Iterable[PolicyRequirement],
    policies: Iterable[PolicyRecord],
    group_ocids_by_name: Mapping[str, str] | None = None,
) -> list[RequirementCheck]:
    """Check ``requirements`` against the policies of the tenancy they must be applied in.

    ``group_ocids_by_name`` maps ``"<domain>/<name>"`` (lower-case, domain ``default`` for the
    Default domain) to an OCID, for groups and dynamic groups of that tenancy.
    """
    reqs = list(requirements)
    names = {k.lower(): v for k, v in (group_ocids_by_name or {}).items()}
    parsed: list[tuple[PolicyRecord, ParsedStatement]] = [
        (p, parse_statement(s)) for p in policies for s in p.statements
    ]
    defs_by_policy = {
        p.id: DefineTable.from_statements([s for q, s in parsed if q.id == p.id]) for p, _ in parsed
    }
    req_parsed = [parse_statement(r.statement) for r in reqs]
    req_defs = DefineTable.from_statements(req_parsed)
    now = utcnow()

    results: list[RequirementCheck] = []
    for req, rp in zip(reqs, req_parsed, strict=True):
        if rp.kind == "unparsed":
            results.append(
                RequirementCheck(
                    requirement_id=req.id,
                    status=CheckStatus.UNKNOWN,
                    detail="statement has unresolved placeholders",
                    checked_at=now,
                )
            )
            continue
        best = _Outcome(CheckStatus.MISSING, "no equivalent statement found")
        for policy, stmt in parsed:
            defs = defs_by_policy[policy.id]
            status = _compare(rp, req_defs, stmt, defs, names)
            # An inconsistently defined alias makes any same-kind grant using it ambiguous,
            # whichever OCID it would resolve to.
            conflicts = (
                defs.conflicting_aliases(stmt)
                if rp.kind != "define" and stmt.kind == rp.kind
                else []
            )
            if conflicts:
                status = CheckStatus.UNKNOWN
            if status is None or _RANK[status] <= _RANK[best.status]:
                continue
            if conflicts:
                best = _Outcome(
                    status,
                    f"policy '{policy.name}' defines {', '.join(conflicts)} more than once with "
                    "different OCIDs",
                    policy.id,
                    stmt.raw,
                )
                continue
            detail = {
                CheckStatus.DETECTED: f"found in policy '{policy.name}'",
                CheckStatus.BROADER: f"satisfied by a broader grant in policy '{policy.name}'",
                CheckStatus.UNKNOWN: f"found in policy '{policy.name}' with a where-clause; "
                "cannot confirm it covers OSC",
            }[status]
            best = _Outcome(status, detail, policy.id, stmt.raw)
            if status is CheckStatus.DETECTED:
                break
        results.append(
            RequirementCheck(
                requirement_id=req.id,
                status=best.status,
                detail=best.detail,
                matched_policy_ocid=best.policy_id,
                matched_statement=best.statement,
                checked_at=now,
            )
        )
    return results


def unknown_checks(
    requirements: Iterable[PolicyRequirement], reason: str
) -> list[RequirementCheck]:
    now = utcnow()
    return [
        RequirementCheck(
            requirement_id=r.id, status=CheckStatus.UNKNOWN, detail=reason, checked_at=now
        )
        for r in requirements
    ]
