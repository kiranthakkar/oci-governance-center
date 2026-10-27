"""Tolerant, pure parser for OCI IAM policy statements; never calls OCI.

Grammar follows Oracle's policy syntax reference:
https://docs.oracle.com/en-us/iaas/Content/Identity/policysyntax/policysyntax.htm
Unrecognized shapes parse as ``parsed=False`` (POLICY-PARSE-001) instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Kind = Literal["allow", "endorse", "admit", "define", "unknown"]
SubjectKind = Literal["group", "dynamic-group", "any-user", "any-group", "service", "resource"]
VERBS = ("inspect", "read", "use", "manage")

GRANT = re.compile(
    r"^(?P<kind>allow|endorse|admit)\s+(?P<subjects>.+?)\s+to\s+"
    # Either a verb with a resource type, or a permission list such as {INSTANCE_READ}.
    r"(?:(?P<verb>inspect|read|use|manage)\s+(?P<resource>[^\s]+)|(?P<permissions>\{[^}]*\}))\s+"
    r"in\s+(?P<location>.+?)(?:\s+where\s+(?P<condition>.+))?$",
    re.IGNORECASE | re.DOTALL,
)
DEFINE = re.compile(
    r"^define\s+(?P<what>tenancy|group|dynamic-group)\s+(?P<alias>\S+)\s+as\s+(?P<ocid>ocid1\.\S+)$",
    re.IGNORECASE,
)
SUBJECT = re.compile(
    r"^(?P<kind>group|dynamic-group)\s+(?:id\s+(?P<ocid>ocid1\.\S+)|(?P<ref>.+))$", re.IGNORECASE
)
ADMIT_ORIGIN = re.compile(r"\s+of\s+tenancy\s+(?P<alias>\S+)$", re.IGNORECASE)


@dataclass(frozen=True)
class Subject:
    """One principal named by a statement. An empty domain means the Default domain."""

    kind: SubjectKind
    name: str = ""
    domain: str = ""
    ocid: str = ""


@dataclass(frozen=True)
class Location:
    kind: Literal["tenancy", "compartment", "compartment_id", "unknown"]
    value: str = ""  # tenancy alias, compartment path (A:B) or compartment OCID


@dataclass(frozen=True)
class Statement:
    text: str
    normalized: str
    kind: Kind
    parsed: bool
    subjects: tuple[Subject, ...] = ()
    verb: str = ""  # inspect/read/use/manage, or "{PERMISSION,...}"
    resource: str = ""
    location: Location = field(default_factory=lambda: Location("unknown"))
    condition: str = ""
    origin_tenancy: str = ""  # Admit: alias of the granting tenancy
    error: str = ""

    @property
    def manage(self) -> bool:
        return self.verb == "manage"


def normalize(text: str) -> str:
    """Collapse whitespace, unify quotes and lowercase for duplicate comparison."""
    return re.sub(r"\s+", " ", text.replace("’", "'").replace('"', "'")).strip().casefold()


def unquote(value: str) -> str:
    return value.strip().strip("'").strip()


def split_subjects(value: str) -> list[str]:
    """Split a comma-separated subject list, ignoring commas inside quotes."""
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    for char in value:
        if char == "'":
            quoted = not quoted
        if char == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def parse_subject(text: str) -> Subject | None:
    lowered = text.casefold()
    if lowered == "any-user":
        return Subject("any-user")
    if lowered == "any-group":
        return Subject("any-group")
    if lowered.startswith("service "):
        return Subject("service", name=unquote(text[8:]))
    if lowered.startswith("resource "):
        return Subject("resource", name=unquote(text[9:]))
    match = SUBJECT.match(text)
    if not match:
        return None
    kind: SubjectKind = "group" if match["kind"].casefold() == "group" else "dynamic-group"
    if match["ocid"]:
        return Subject(kind, ocid=match["ocid"])
    reference = match["ref"].strip()
    if "/" in reference:
        domain, _, name = reference.partition("/")
        return Subject(kind, name=unquote(name), domain=unquote(domain))
    return Subject(kind, name=unquote(reference))


def parse_location(text: str) -> Location:
    words = text.strip().split(None, 2)
    head = words[0].casefold() if words else ""
    if head == "tenancy":
        return Location("tenancy", unquote(words[1]) if len(words) > 1 else "")
    if head == "compartment" and len(words) > 1:
        if words[1].casefold() == "id" and len(words) > 2:
            return Location("compartment_id", words[2].strip())
        return Location("compartment", unquote(" ".join(words[1:])))
    return Location("unknown", text.strip())


def parse(text: str) -> Statement:
    """Parse one statement; anything not recognized is returned with parsed=False."""
    collapsed = re.sub(r"\s+", " ", text).strip()
    normalized = normalize(text)
    define = DEFINE.match(collapsed)
    if define:
        return Statement(text, normalized, "define", True, resource=define["what"].casefold())
    grant = GRANT.match(collapsed)
    if not grant:
        return Statement(text, normalized, "unknown", False, error="Unrecognized statement shape")
    kind: Kind = grant["kind"].casefold()  # type: ignore[assignment]
    subjects_text = grant["subjects"]
    origin = ""
    if kind == "admit":
        admitted = ADMIT_ORIGIN.search(subjects_text)
        if admitted:
            origin = admitted["alias"]
            subjects_text = subjects_text[: admitted.start()]
    subjects = [parse_subject(part) for part in split_subjects(subjects_text)]
    if not subjects or any(subject is None for subject in subjects):
        return Statement(text, normalized, kind, False, error="Unrecognized subject")
    location = parse_location(grant["location"])
    if location.kind == "unknown":
        return Statement(text, normalized, kind, False, error="Unrecognized location")
    return Statement(
        text,
        normalized,
        kind,
        True,
        subjects=tuple(subject for subject in subjects if subject is not None),
        verb=grant["permissions"].strip() if grant["permissions"] else grant["verb"].casefold(),
        resource=(grant["resource"] or "").casefold(),
        location=location,
        condition=(grant["condition"] or "").strip(),
        origin_tenancy=origin,
    )
