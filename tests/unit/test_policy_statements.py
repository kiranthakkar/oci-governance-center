from __future__ import annotations

import pytest

from oci_security_center.analyzers.policy.statements import parse_statement


@pytest.mark.parametrize(
    ("stmt", "kind", "verb", "resource", "loc_kind", "loc_name"),
    [
        (
            "Allow group Admins to manage all-resources in tenancy",
            "allow",
            "manage",
            "all-resources",
            "tenancy",
            None,
        ),
        (
            "allow   GROUP   'Default'/'OSC-Admins'  to  read  policies in TENANCY",
            "allow",
            "read",
            "policies",
            "tenancy",
            None,
        ),
        (
            "Allow dynamic-group 'Ops'/'Scanner' to read all-resources in compartment Prod:App",
            "allow",
            "read",
            "all-resources",
            "compartment",
            "prod:app",
        ),
        (
            "Allow group id ocid1.group.oc1..aaaafake to use vcns in compartment id "
            "ocid1.compartment.oc1..aaaafake",
            "allow",
            "use",
            "vcns",
            "compartment",
            None,
        ),
        (
            "Allow any-user to read buckets in tenancy where request.principal.type='instance'",
            "allow",
            "read",
            "buckets",
            "tenancy",
            None,
        ),
        (
            "Endorse dynamic-group OSC-Scanner-DG to read all-resources in tenancy osc_child",
            "endorse",
            "read",
            "all-resources",
            "tenancy",
            "osc_child",
        ),
        (
            "Endorse group X to read all-resources in any-tenancy",
            "endorse",
            "read",
            "all-resources",
            "any-tenancy",
            None,
        ),
        (
            "Admit dynamic-group OSC_Scanner_DG of tenancy osc_parent to read all-resources in "
            "tenancy",
            "admit",
            "read",
            "all-resources",
            "tenancy",
            None,
        ),
    ],
)
def test_parse_shapes(
    stmt: str, kind: str, verb: str, resource: str, loc_kind: str, loc_name: str | None
) -> None:
    p = parse_statement(stmt)
    assert p.kind == kind
    assert p.verb == verb
    assert p.resource == resource
    assert p.location is not None
    assert p.location.kind == loc_kind
    assert p.location.name == loc_name


def test_parse_subjects_domain_and_multi() -> None:
    p = parse_statement("Allow group 'Default'/'A', group 'Ops'/'B' to read logs in tenancy")
    assert [(s.domain, s.name) for s in p.subjects] == [(None, "a"), ("ops", "b")]


def test_parse_condition_and_admit_source() -> None:
    p = parse_statement(
        "Admit group G of tenancy Parent to read all-resources in tenancy "
        "where request.region='iad'"
    )
    assert p.source_tenancy == "parent"
    assert p.condition == "request.region='iad'"


def test_parse_define() -> None:
    p = parse_statement("Define tenancy osc_parent as ocid1.tenancy.oc1..aaaafake0001")
    assert (p.kind, p.define_kind, p.define_alias) == ("define", "tenancy", "osc_parent")


def test_parse_permissions_list() -> None:
    p = parse_statement("Allow group A to {USER_INSPECT, USER_READ} in tenancy")
    assert p.permissions == ("USER_INSPECT", "USER_READ")
    assert p.verb is None


@pytest.mark.parametrize(
    "bad",
    [
        "Allow everyone to do things",
        "Permit group A to read x",
        "Allow group A to fly kites in tenancy",
        "",
    ],
)
def test_unparseable_is_tolerated(bad: str) -> None:
    assert parse_statement(bad).kind == "unparsed"
