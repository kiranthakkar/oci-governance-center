"""Generate the IAM statements OSC needs (docs/control-plane.md §5). OSC never applies them.

* Organization configuration screen → :func:`parent_requirements` (``osc-parent-access``) and the
  combined ``osc-endorse-children`` roll-up of every child's :func:`endorse_requirements`.
* Child configuration screen → :func:`endorse_requirements` (parent side) and
  :func:`admit_requirements` (child side).

Resource-family names marked ``verify`` must be checked against current OCI docs before release.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

from oci_security_center.config import Settings
from oci_security_center.models import PolicyRequirement, PolicySide, RequirementBlock, Tenancy

POLICY_PARENT_ACCESS = "osc-parent-access"
POLICY_ENDORSE_CHILDREN = "osc-endorse-children"
POLICY_ADMIT_PARENT = "osc-admit-parent"

_PLACEHOLDER = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class PrincipalRef:
    kind: str  # "group" | "dynamic-group"
    name: str
    domain: str | None = None  # None / "Default" = Default domain
    ocid: str | None = None

    @property
    def policy_ref(self) -> str:
        """How the principal is written in an Allow/Endorse statement in its own tenancy."""
        if self.domain and self.domain.lower() != "default":
            return f"{self.kind} '{self.domain}'/'{self.name}'"
        return f"{self.kind} {self.name}"

    @property
    def alias(self) -> str:
        return make_alias(self.name)

    @property
    def ocid_or_placeholder(self) -> str:
        return self.ocid or f"<OCID of {self.kind} {self.name}>"


def make_alias(name: str) -> str:
    """Alias usable in Define statements: letters, digits and underscores only."""
    alias = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    return alias or "tenancy"


def has_placeholder(statement: str) -> bool:
    return bool(_PLACEHOLDER.search(statement))


def scanner_principal(settings: Settings, ocid: str | None = None) -> PrincipalRef:
    if settings.scanner_is_dynamic_group:
        return PrincipalRef(
            "dynamic-group", settings.dynamic_group_scanner, settings.identity_domain_name, ocid
        )
    return PrincipalRef("group", settings.group_scanners, settings.identity_domain_name, ocid)


def admins_principal(settings: Settings, ocid: str | None = None) -> PrincipalRef:
    return PrincipalRef("group", settings.group_admins, settings.identity_domain_name, ocid)


def _req(
    rid: str,
    side: PolicySide,
    block: RequirementBlock,
    where: str,
    target: str,
    policy: str,
    statement: str,
    why: str,
    optional: bool = False,
) -> PolicyRequirement:
    return PolicyRequirement(
        id=rid,
        side=side,
        block=block,
        tenancy_ocid=where,
        target_tenancy_ocid=target,
        policy_name=policy,
        statement=statement,
        why=why,
        optional=optional,
    )


def parent_requirements(
    settings: Settings, parent: Tenancy, scanner: PrincipalRef, admins: PrincipalRef
) -> list[PolicyRequirement]:
    """``osc-parent-access``: admins (discovery/checks) + scanner (read-only scans)."""
    p, a, s = parent.ocid, admins.policy_ref, scanner.policy_ref
    side, block = PolicySide.PARENT, RequirementBlock.PARENT_ACCESS

    def r(slug: str, stmt: str, why: str) -> PolicyRequirement:
        return _req(f"parent_access:{p}:{slug}", side, block, p, p, POLICY_PARENT_ACCESS, stmt, why)

    return [
        r(
            "admins-inspect-tenancies",
            f"Allow {a} to inspect tenancies in tenancy",
            "Connection test and tenancy details for signed-in OSC admins",
        ),
        r(
            "admins-read-org",
            f"Allow {a} to read organizations-family in tenancy",
            "List the Organization and its child tenancies (verify family name)",
        ),
        r(
            "admins-inspect-compartments",
            f"Allow {a} to inspect compartments in tenancy",
            "Resolve compartment names when checking policies",
        ),
        r(
            "admins-read-policies",
            f"Allow {a} to read policies in tenancy",
            "Check whether the statements on this screen are applied",
        ),
        r(
            "admins-inspect-groups",
            f"Allow {a} to inspect groups in tenancy",
            "Resolve group OCIDs for the child Define statements",
        ),
        r(
            "admins-inspect-dynamic-groups",
            f"Allow {a} to inspect dynamic-groups in tenancy",
            "Resolve the scanner dynamic group OCID",
        ),
        r(
            "scanner-read-all",
            f"Allow {s} to read all-resources in tenancy",
            "Read-only scans of the parent tenancy (MVP scope; least-privilege list later)",
        ),
        r(
            "scanner-read-org",
            f"Allow {s} to read organizations-family in tenancy",
            "Scheduled scans re-discover child tenancies (verify family name)",
        ),
    ]


def endorse_requirements(
    settings: Settings,
    parent: Tenancy,
    child: Tenancy,
    scanner: PrincipalRef,
    admins: PrincipalRef,
    include_admin_browse: bool = False,
) -> list[PolicyRequirement]:
    """Parent-side statements for one child (go into ``osc-endorse-children``)."""
    p, c = parent.ocid, child.ocid
    side, block = PolicySide.PARENT, RequirementBlock.ENDORSE

    def r(
        slug: str, stmt: str, why: str, blk: RequirementBlock = block, optional: bool = False
    ) -> PolicyRequirement:
        return _req(
            f"endorse:{c}:{slug}", side, blk, p, c, POLICY_ENDORSE_CHILDREN, stmt, why, optional
        )

    reqs = [
        r(
            "define-child",
            f"Define tenancy {child.alias} as {c}",
            f"Names child tenancy '{child.name}' for the Endorse statement",
        ),
        r(
            "endorse-scanner",
            f"Endorse {scanner.policy_ref} to read all-resources in tenancy {child.alias}",
            "Lets the OSC scanner identity read the child (needs matching Admit in the child)",
        ),
    ]
    if include_admin_browse:
        reqs.append(
            r(
                "endorse-admins",
                f"Endorse {admins.policy_ref} to read all-resources in tenancy {child.alias}",
                "Optional: OSC admins can browse this child with their own sign-in",
                RequirementBlock.ADMIN_BROWSE,
                True,
            )
        )
    return reqs


def admit_requirements(
    settings: Settings,
    parent: Tenancy,
    child: Tenancy,
    scanner: PrincipalRef,
    admins: PrincipalRef,
    include_admin_browse: bool = False,
) -> list[PolicyRequirement]:
    """Child-side statements, applied by the child's IAM admin in the child root compartment."""
    c, palias = child.ocid, parent.alias
    side, block = PolicySide.CHILD, RequirementBlock.ADMIT

    def r(
        slug: str, stmt: str, why: str, blk: RequirementBlock = block, optional: bool = False
    ) -> PolicyRequirement:
        return _req(f"admit:{c}:{slug}", side, blk, c, c, POLICY_ADMIT_PARENT, stmt, why, optional)

    reqs = [
        r(
            "define-parent",
            f"Define tenancy {palias} as {parent.ocid}",
            f"Names the parent tenancy '{parent.name}'",
        ),
        r(
            "define-scanner",
            f"Define {scanner.kind} {scanner.alias} as {scanner.ocid_or_placeholder}",
            "Names the OSC scanner identity from the parent",
        ),
        r(
            "admit-scanner",
            f"Admit {scanner.kind} {scanner.alias} of tenancy {palias} to read all-resources "
            "in tenancy",
            "Allows the OSC scanner to read this tenancy (read-only)",
        ),
    ]
    if include_admin_browse:
        reqs += [
            r(
                "define-admins",
                f"Define group {admins.alias} as {admins.ocid_or_placeholder}",
                "Optional: names the OSC admins group",
                RequirementBlock.ADMIN_BROWSE,
                True,
            ),
            r(
                "admit-admins",
                f"Admit group {admins.alias} of tenancy {palias} to read all-resources in tenancy",
                "Optional: OSC admins can browse this child with their own sign-in",
                RequirementBlock.ADMIN_BROWSE,
                True,
            ),
        ]
    return reqs


def policy_blocks(reqs: list[PolicyRequirement]) -> dict[str, list[PolicyRequirement]]:
    """Group requirements by suggested policy name, preserving order."""
    out: dict[str, list[PolicyRequirement]] = {}
    for req in reqs:
        out.setdefault(req.policy_name, []).append(req)
    return out


def statements_text(reqs: list[PolicyRequirement]) -> str:
    return "\n".join(r.statement for r in reqs)


def cli_command(tenancy_ocid: str, policy_name: str, reqs: list[PolicyRequirement]) -> str:
    """An ``oci iam policy create`` command for a human IAM admin to run. OSC never runs it."""
    statements = json.dumps([r.statement for r in reqs], indent=2)
    return (
        f"cat > {policy_name}.json <<'EOF'\n{statements}\nEOF\n"
        f"oci iam policy create --compartment-id {shlex.quote(tenancy_ocid)} "
        f"--name {shlex.quote(policy_name)} "
        f"--description {shlex.quote('Required by OCI Security Center (read-only)')} "
        f"--statements file://{policy_name}.json"
    )
