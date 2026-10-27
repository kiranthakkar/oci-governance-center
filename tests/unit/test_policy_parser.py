"""Table-driven policy statement parsing with real-world shapes and synthetic names."""

import pytest

from oci_governance_center.analyzers.policy import Location, Subject, normalize, parse


@pytest.mark.parametrize(
    "text,kind,subjects,verb,resource,location,condition",
    [
        (
            "Allow group Administrators to manage all-resources in tenancy",
            "allow",
            (Subject("group", name="Administrators"),),
            "manage",
            "all-resources",
            Location("tenancy"),
            "",
        ),
        (
            "ALLOW GROUP 'Default'/'Network Admins' TO USE virtual-network-family IN TENANCY",
            "allow",
            (Subject("group", name="Network Admins", domain="Default"),),
            "use",
            "virtual-network-family",
            Location("tenancy"),
            "",
        ),
        (
            "Allow group Apps/Developers, group Testers to read buckets in compartment Prod:Web",
            "allow",
            (
                Subject("group", name="Developers", domain="Apps"),
                Subject("group", name="Testers"),
            ),
            "read",
            "buckets",
            Location("compartment", "Prod:Web"),
            "",
        ),
        (
            "Allow group id ocid1.group.oc1..aaaafakegroup to inspect users in tenancy",
            "allow",
            (Subject("group", ocid="ocid1.group.oc1..aaaafakegroup"),),
            "inspect",
            "users",
            Location("tenancy"),
            "",
        ),
        (
            "Allow dynamic-group functions to manage objects in compartment id "
            "ocid1.compartment.oc1..aaaafakeprod where target.bucket.name='logs'",
            "allow",
            (Subject("dynamic-group", name="functions"),),
            "manage",
            "objects",
            Location("compartment_id", "ocid1.compartment.oc1..aaaafakeprod"),
            "target.bucket.name='logs'",
        ),
        (
            "Allow any-user to read buckets in tenancy where request.principal.type = 'fnfunc'",
            "allow",
            (Subject("any-user"),),
            "read",
            "buckets",
            Location("tenancy"),
            "request.principal.type = 'fnfunc'",
        ),
        (
            "Allow service cloudguard to read all-resources in tenancy",
            "allow",
            (Subject("service", name="cloudguard"),),
            "read",
            "all-resources",
            Location("tenancy"),
            "",
        ),
        (
            "Allow group Auditors to {INSTANCE_READ, VOLUME_INSPECT} in tenancy",
            "allow",
            (Subject("group", name="Auditors"),),
            "{INSTANCE_READ, VOLUME_INSPECT}",
            "",
            Location("tenancy"),
            "",
        ),
        (
            "Endorse group NetworkAdmins to manage vcns in tenancy Partner",
            "endorse",
            (Subject("group", name="NetworkAdmins"),),
            "manage",
            "vcns",
            Location("tenancy", "Partner"),
            "",
        ),
        (
            "Admit group PartnerOps of tenancy Partner to read all-resources in tenancy",
            "admit",
            (Subject("group", name="PartnerOps"),),
            "read",
            "all-resources",
            Location("tenancy"),
            "",
        ),
    ],
)
def test_statement_shapes(text, kind, subjects, verb, resource, location, condition):
    statement = parse(text)
    assert statement.parsed, statement.error
    assert statement.kind == kind
    assert statement.subjects == subjects
    assert statement.verb == verb
    assert statement.resource == resource
    assert statement.location == location
    assert statement.condition == condition


def test_permission_lists_are_not_treated_as_manage():
    statement = parse("Allow group Ops to {USER_CREATE} in tenancy")
    assert statement.parsed and not statement.manage and statement.resource == ""


def test_define_statements_are_recognized():
    statement = parse("Define tenancy Partner as ocid1.tenancy.oc1..aaaafakepartner")
    assert statement.parsed and statement.kind == "define" and statement.resource == "tenancy"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "this is not a statement",
        "Allow group to manage all-resources in tenancy",
        "Allow group Ops to manage all-resources in somewhere",
        "Allow wizards Ops to manage all-resources in tenancy",
    ],
)
def test_unrecognized_shapes_are_not_guessed(text):
    statement = parse(text)
    assert not statement.parsed and statement.error


def test_normalization_ignores_case_whitespace_and_quote_style():
    assert normalize('Allow  group "A"  to read  buckets in TENANCY') == normalize(
        "allow group 'A' to read buckets in tenancy"
    )
