from __future__ import annotations

from pathlib import Path

import pytest

from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane import policy_templates as tpl
from oci_security_center.control_plane.checks import PolicyRecord, check_requirements
from oci_security_center.models import CheckStatus, OnboardingStatus, OrgRole, Tenancy

PARENT = Tenancy(
    ocid="ocid1.tenancy.oc1..aaaafakeparent",
    name="Parent",
    alias="osc_parent",
    org_role=OrgRole.PARENT,
    onboarding_status=OnboardingStatus.ACTIVE,
)
CHILD = Tenancy(
    ocid="ocid1.tenancy.oc1..aaaafakechild1",
    name="Child One",
    alias="osc_child_one",
    org_role=OrgRole.CHILD,
    onboarding_status=OnboardingStatus.PENDING,
)
DG_OCID = "ocid1.dynamicgroup.oc1..aaaafakedg"
ADMINS_OCID = "ocid1.group.oc1..aaaafakeadmins"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_root=tmp_path, deployment=DeploymentMode.OCI)


def _principals(s: Settings) -> tuple[tpl.PrincipalRef, tpl.PrincipalRef]:
    return tpl.scanner_principal(s, DG_OCID), tpl.admins_principal(s, ADMINS_OCID)


def _status(checks: list, rid_suffix: str) -> CheckStatus:  # type: ignore[type-arg]
    [c] = [c for c in checks if c.requirement_id.endswith(rid_suffix)]
    return c.status  # type: ignore[no-any-return]


def test_parent_access_detected_in_any_policy_with_formatting_differences(
    settings: Settings,
) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.parent_requirements(settings, PARENT, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "security-team",
            (
                "allow GROUP 'Default'/'OSC-Admins' to inspect tenancies in TENANCY",
                "Allow group OSC-Admins to read organizations-family in tenancy",
            ),
        ),
        PolicyRecord(
            "p2",
            "scanner",
            ("Allow dynamic-group OSC-Scanner-DG to read all-resources in tenancy",),
        ),
    ]
    checks = check_requirements(reqs, policies)
    assert _status(checks, "admins-inspect-tenancies") is CheckStatus.DETECTED
    assert _status(checks, "admins-read-org") is CheckStatus.DETECTED
    assert _status(checks, "scanner-read-all") is CheckStatus.DETECTED
    assert _status(checks, "admins-read-policies") is CheckStatus.MISSING


def test_broader_grant_and_conditional(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.parent_requirements(settings, PARENT, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "too-broad",
            (
                "Allow group OSC-Admins to manage all-resources in tenancy",
                "Allow dynamic-group OSC-Scanner-DG to read all-resources in tenancy "
                "where request.region='iad'",
            ),
        )
    ]
    checks = check_requirements(reqs, policies)
    assert _status(checks, "admins-read-policies") is CheckStatus.BROADER
    assert _status(checks, "scanner-read-all") is CheckStatus.UNKNOWN


def test_compartment_grant_does_not_satisfy_tenancy_requirement(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.parent_requirements(settings, PARENT, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "x",
            ("Allow dynamic-group OSC-Scanner-DG to read all-resources in compartment Sandbox",),
        )
    ]
    assert _status(check_requirements(reqs, policies), "scanner-read-all") is CheckStatus.MISSING


def test_group_name_resolved_via_ocid(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.parent_requirements(settings, PARENT, scanner, admins)
    policies = [
        PolicyRecord("p1", "x", (f"Allow group id {ADMINS_OCID} to read policies in tenancy",))
    ]
    checks = check_requirements(reqs, policies, {"default/osc-admins": ADMINS_OCID})
    assert _status(checks, "admins-read-policies") is CheckStatus.DETECTED


def test_endorse_with_admin_chosen_alias(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.endorse_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "their-own-name",
            (
                f"Define tenancy ChildOne as {CHILD.ocid}",
                "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy ChildOne",
            ),
        )
    ]
    checks = check_requirements(reqs, policies)
    assert {c.status for c in checks} == {CheckStatus.DETECTED}


def test_endorse_wrong_child_is_missing(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.endorse_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "x",
            (
                "Define tenancy Other as ocid1.tenancy.oc1..aaaafakeother",
                "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy Other",
            ),
        )
    ]
    assert _status(check_requirements(reqs, policies), "endorse-scanner") is CheckStatus.MISSING


def test_admit_detected_with_different_aliases(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.admit_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "osc",
            (
                f"Define tenancy HQ as {PARENT.ocid}",
                f"Define dynamic-group Scanner as {DG_OCID}",
                "Admit dynamic-group Scanner of tenancy HQ to read all-resources in tenancy",
            ),
        )
    ]
    checks = check_requirements(reqs, policies)
    assert {c.status for c in checks} == {CheckStatus.DETECTED}


def test_admit_with_wrong_group_ocid_is_missing(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.admit_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "osc",
            (
                f"Define tenancy HQ as {PARENT.ocid}",
                "Define dynamic-group Scanner as ocid1.dynamicgroup.oc1..aaaawrong",
                "Admit dynamic-group Scanner of tenancy HQ to read all-resources in tenancy",
            ),
        )
    ]
    checks = check_requirements(reqs, policies)
    assert _status(checks, "define-scanner") is CheckStatus.MISSING
    assert _status(checks, "admit-scanner") is CheckStatus.MISSING


def test_placeholder_requirement_is_unknown(settings: Settings) -> None:
    scanner = tpl.scanner_principal(settings)  # OCID not resolved
    reqs = tpl.admit_requirements(settings, PARENT, CHILD, scanner, tpl.admins_principal(settings))
    define = next(r for r in reqs if r.id.endswith("define-scanner"))
    assert tpl.has_placeholder(define.statement)
    assert _status(check_requirements(reqs, []), "define-scanner") is CheckStatus.UNKNOWN


def test_workstation_mode_uses_group(tmp_path: Path) -> None:
    s = Settings(data_root=tmp_path, deployment=DeploymentMode.WORKSTATION)
    reqs = tpl.endorse_requirements(
        s, PARENT, CHILD, tpl.scanner_principal(s), tpl.admins_principal(s)
    )
    assert any("Endorse group OSC-Scanners" in r.statement for r in reqs)


def test_named_domain_is_quoted(tmp_path: Path) -> None:
    s = Settings(data_root=tmp_path, identity_domain_name="SecOps")
    assert tpl.admins_principal(s).policy_ref == "group 'SecOps'/'OSC-Admins'"


def test_cli_command_is_quoted() -> None:
    reqs = tpl.parent_requirements(
        Settings(), PARENT, tpl.PrincipalRef("group", "A"), tpl.PrincipalRef("group", "B")
    )
    cmd = tpl.cli_command(PARENT.ocid, tpl.POLICY_PARENT_ACCESS, reqs)
    assert "oci iam policy create" in cmd
    assert "--statements file://osc-parent-access.json" in cmd


# --- policy-local Define aliases (control-plane §5.3) ---------------------------------------------
def test_split_definitions_are_never_detected(settings: Settings) -> None:
    """Define in one policy + Endorse/Admit in another: OCI doesn't resolve that alias."""
    scanner, admins = _principals(settings)
    endorse = tpl.endorse_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord("p1", "defs", (f"Define tenancy ChildOne as {CHILD.ocid}",)),
        PolicyRecord(
            "p2",
            "grants",
            ("Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy ChildOne",),
        ),
    ]
    checks = check_requirements(endorse, policies)
    assert _status(checks, "define-child") is CheckStatus.DETECTED
    assert _status(checks, "endorse-scanner") is CheckStatus.MISSING

    admit = tpl.admit_requirements(settings, PARENT, CHILD, scanner, admins)
    split_admit = [
        PolicyRecord(
            "p1",
            "defs",
            (f"Define tenancy HQ as {PARENT.ocid}", f"Define dynamic-group Scanner as {DG_OCID}"),
        ),
        PolicyRecord(
            "p2",
            "grants",
            ("Admit dynamic-group Scanner of tenancy HQ to read all-resources in tenancy",),
        ),
    ]
    assert _status(check_requirements(admit, split_admit), "admit-scanner") is CheckStatus.MISSING


def test_same_alias_in_two_policies_resolves_per_policy(settings: Settings) -> None:
    """Different policies may reuse an alias for different tenancies."""
    scanner, admins = _principals(settings)
    reqs = tpl.endorse_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "other-child",
            (
                "Define tenancy Kid as ocid1.tenancy.oc1..aaaafakeother",
                "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy Kid",
            ),
        ),
        PolicyRecord(
            "p2",
            "our-child",
            (
                f"Define tenancy Kid as {CHILD.ocid}",
                "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy Kid",
            ),
        ),
    ]
    [check] = [
        c for c in check_requirements(reqs, policies) if c.requirement_id.endswith("scanner")
    ]
    assert check.status is CheckStatus.DETECTED
    assert check.matched_policy_ocid == "p2"


def test_conflicting_definitions_in_one_policy_are_unknown(settings: Settings) -> None:
    scanner, admins = _principals(settings)
    reqs = tpl.endorse_requirements(settings, PARENT, CHILD, scanner, admins)
    policies = [
        PolicyRecord(
            "p1",
            "ambiguous",
            (
                f"Define tenancy Kid as {CHILD.ocid}",
                "Define tenancy Kid as ocid1.tenancy.oc1..aaaafakeother",
                "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy Kid",
            ),
        )
    ]
    [check] = [
        c for c in check_requirements(reqs, policies) if c.requirement_id.endswith("scanner")
    ]
    assert check.status is CheckStatus.UNKNOWN
    assert "more than once" in check.detail
