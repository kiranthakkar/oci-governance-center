"""OCI IAM policy statement parser and normalizer.

Shared by the control plane (are OSC's required statements present?) and pillar 3 (policy review).
The parser is tolerant: anything it cannot parse comes back as ``kind="unparsed"`` instead of
raising (AGENTS.md §7.3, rule POLICY-PARSE-001).

Supported shapes::

    Allow <subjects> to <verb> <resource>|{PERMS}
          in tenancy|compartment <name>|compartment id <ocid>
          [where <conditions>]
    Endorse <subjects> to <verb> <resource> in tenancy <alias>|any-tenancy [where ...]
    Admit <subjects> of tenancy <alias> to <verb> <resource> in tenancy|compartment ... [where ...]
    Define tenancy|group|dynamic-group <alias> as <ocid>
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

VERB_RANK = {"inspect": 1, "read": 2, "use": 3, "manage": 4}

_WS = re.compile(r"\s+")
_DEFINE = re.compile(r"^define\s+(tenancy|group|dynamic-group)\s+(.+?)\s+as\s+(\S+)$", re.I)
_ALLOW = re.compile(
    r"^allow\s+(?P<subj>.+?)\s+to\s+(?P<act>.+?)\s+in\s+(?P<loc>.+?)(?:\s+where\s+(?P<cond>.+))?$",
    re.I,
)
_ENDORSE = re.compile(
    r"^endorse\s+(?P<subj>.+?)\s+to\s+(?P<act>.+?)\s+in\s+(?P<loc>.+?)"
    r"(?:\s+where\s+(?P<cond>.+))?$",
    re.I,
)
_ADMIT = re.compile(
    r"^admit\s+(?P<subj>.+?)\s+of\s+tenancy\s+(?P<src>\S+)\s+to\s+(?P<act>.+?)\s+in\s+(?P<loc>.+?)"
    r"(?:\s+where\s+(?P<cond>.+))?$",
    re.I,
)
_SUBJECT = re.compile(
    r"^(?P<kind>group|dynamic-group|service|any-user|any-group)"
    r"(?:\s+(?P<id>id)\s+(?P<ocid>\S+)|\s+(?P<name>.+))?$",
    re.I,
)


def _clean(name: str) -> str:
    return name.strip().strip("'\"").strip()


@dataclass(frozen=True)
class Subject:
    kind: str  # group | dynamic-group | service | any-user | any-group
    name: str | None = None  # lower-cased, unquoted
    domain: str | None = None  # lower-cased; None means Default domain
    ocid: str | None = None

    @property
    def is_wildcard(self) -> bool:
        return self.kind in ("any-user", "any-group")


@dataclass(frozen=True)
class Location:
    kind: str  # tenancy | compartment | any-tenancy
    name: str | None = None  # tenancy alias or compartment name/path (lower-cased)
    ocid: str | None = None


@dataclass(frozen=True)
class ParsedStatement:
    raw: str
    kind: str  # allow | endorse | admit | define | unparsed
    subjects: tuple[Subject, ...] = ()
    verb: str | None = None
    resource: str | None = None
    permissions: tuple[str, ...] = ()
    location: Location | None = None
    source_tenancy: str | None = None  # Admit: alias of the endorsing tenancy (lower-cased)
    condition: str | None = None
    define_kind: str | None = None
    define_alias: str | None = None
    define_ocid: str | None = None
    error: str | None = field(default=None, compare=False)


def normalize_whitespace(statement: str) -> str:
    return _WS.sub(" ", statement.strip())


def _parse_subjects(text: str) -> tuple[Subject, ...] | None:
    parts = [
        p.strip() for p in re.split(r",(?=\s*(?:group|dynamic-group|service)\b)", text, flags=re.I)
    ]
    subjects: list[Subject] = []
    for part in parts:
        m = _SUBJECT.match(part)
        if not m:
            return None
        kind = m.group("kind").lower()
        if m.group("id"):
            subjects.append(Subject(kind, ocid=m.group("ocid")))
            continue
        name = m.group("name")
        if name is None:
            if kind not in ("any-user", "any-group"):
                return None
            subjects.append(Subject(kind))
            continue
        domain = None
        if "/" in name:
            dom, _, nm = name.partition("/")
            domain, name = _clean(dom).lower(), nm
        if domain == "default":
            domain = None
        subjects.append(Subject(kind, name=_clean(name).lower(), domain=domain))
    return tuple(subjects)


def _parse_action(text: str) -> tuple[str | None, str | None, tuple[str, ...]] | None:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        perms = tuple(p.strip().upper() for p in text[1:-1].split(",") if p.strip())
        return None, None, perms
    bits = text.split()
    if len(bits) != 2 or bits[0].lower() not in VERB_RANK:
        return None
    return bits[0].lower(), bits[1].lower(), ()


def _parse_location(text: str) -> Location | None:
    bits = text.strip().split(None, 2)
    head = bits[0].lower()
    if head == "any-tenancy" and len(bits) == 1:
        return Location("any-tenancy")
    if head == "tenancy":
        if len(bits) == 1:
            return Location("tenancy")
        return Location("tenancy", name=_clean(" ".join(bits[1:])).lower())
    if head == "compartment" and len(bits) >= 2:
        if bits[1].lower() == "id" and len(bits) == 3:
            return Location("compartment", ocid=bits[2].strip())
        return Location("compartment", name=_clean(" ".join(bits[1:])).lower())
    return None


def parse_statement(statement: str) -> ParsedStatement:
    raw = normalize_whitespace(statement)
    m = _DEFINE.match(raw)
    if m:
        return ParsedStatement(
            raw,
            "define",
            define_kind=m.group(1).lower(),
            define_alias=_clean(m.group(2)).lower(),
            define_ocid=m.group(3),
        )
    for kind, rx in (("admit", _ADMIT), ("endorse", _ENDORSE), ("allow", _ALLOW)):
        m = rx.match(raw)
        if not m:
            continue
        subjects = _parse_subjects(m.group("subj"))
        action = _parse_action(m.group("act"))
        location = _parse_location(m.group("loc"))
        if subjects is None or action is None or location is None:
            return ParsedStatement(raw, "unparsed", error=f"cannot parse {kind} statement")
        verb, resource, perms = action
        cond = m.group("cond")
        return ParsedStatement(
            raw,
            kind,
            subjects=subjects,
            verb=verb,
            resource=resource,
            permissions=perms,
            location=location,
            source_tenancy=_clean(m.group("src")).lower() if kind == "admit" else None,
            condition=cond.strip() if cond else None,
        )
    return ParsedStatement(raw, "unparsed", error="unrecognized statement")


@dataclass
class DefineTable:
    """Aliases from the ``Define`` statements of **one policy document** → OCIDs.

    OCI scopes Define aliases to the policy that contains them; tables must never be merged across
    policies (docs/control-plane.md §5.3). An alias defined twice with different OCIDs in the same
    policy is recorded in ``conflicts`` and must not be treated as resolved.
    """

    tenancies: dict[str, str] = field(default_factory=dict)
    groups: dict[str, str] = field(default_factory=dict)
    dynamic_groups: dict[str, str] = field(default_factory=dict)
    conflicts: set[tuple[str, str]] = field(default_factory=set)  # (define kind, alias)

    @classmethod
    def from_statements(cls, statements: list[ParsedStatement]) -> DefineTable:
        table = cls()
        for s in statements:
            if s.kind != "define" or not s.define_alias or not s.define_ocid:
                continue
            kind = s.define_kind or "tenancy"
            target = {
                "tenancy": table.tenancies,
                "group": table.groups,
                "dynamic-group": table.dynamic_groups,
            }[kind]
            previous = target.get(s.define_alias)
            if previous is not None and previous != s.define_ocid:
                table.conflicts.add((kind, s.define_alias))
            target[s.define_alias] = s.define_ocid
        return table

    def conflicting_aliases(self, stmt: ParsedStatement) -> list[str]:
        """Aliases ``stmt`` relies on that this policy defines inconsistently."""
        used: list[tuple[str, str]] = []
        if stmt.source_tenancy:
            used.append(("tenancy", stmt.source_tenancy))
        if stmt.kind == "endorse" and stmt.location and stmt.location.name:
            used.append(("tenancy", stmt.location.name))
        if stmt.kind == "admit":
            used += [(s.kind, s.name) for s in stmt.subjects if s.name]
        return [alias for kind, alias in used if (kind, alias) in self.conflicts]
