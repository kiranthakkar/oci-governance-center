"""Positive and negative cases for every policy and identity analysis rule."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta

import pytest

from oci_governance_center.analyzers.identity import (
    Inventory,
    activity_findings,
    api_key_findings,
    identity_findings,
    policy_findings,
)

TENANCY = "ocid1.tenancy.oc1..aaaafakeparent"
DEFAULT, APPS = "ocid1.domain.oc1..aaaafakedefault", "ocid1.domain.oc1..aaaafakeapps"
PROD, RETIRED = "ocid1.compartment.oc1..aaaafakeprod", "ocid1.compartment.oc1..aaaafakeold"
NOW = datetime(2026, 10, 22, tzinfo=UTC)


def identity_records(tenancy=TENANCY):
    """A synthetic tenancy designed to trigger, and not trigger, each rule."""
    records = defaultdict(list)

    def add(dataset, key, data, domain=""):
        scope = {"tenancy": tenancy, "dataset": dataset, "region": "us-ashburn-1", "domain": domain}
        records[dataset].append({"scope": scope, "key": key, "data": data})

    add("identity.domains", DEFAULT, {"id": DEFAULT, "display_name": "Default"})
    add("identity.domains", APPS, {"id": APPS, "display_name": "Apps"})
    add(
        "identity.compartments",
        PROD,
        {"id": PROD, "compartment_id": tenancy, "name": "Production", "lifecycle_state": "ACTIVE"},
    )
    add(
        "identity.compartments",
        RETIRED,
        {"id": RETIRED, "compartment_id": tenancy, "name": "Retired", "lifecycle_state": "DELETED"},
    )

    def user(key, name, domain=DEFAULT, **extra):
        # Same shape as collectors.inventory.read_users: unreported attributes are None.
        data = {
            "id": key,
            "ocid": f"ocid1.user.oc1..{key}",
            "user_name": name,
            "active": True,
            "mfa_status": None,
            "federated": None,
            "service_user": None,
            "last_successful_login": None,
        }
        add("identity_domains.users", key, data | extra, domain)

    recent, old = (NOW - timedelta(days=3)).isoformat(), (NOW - timedelta(days=200)).isoformat()
    user("u-admin", "admin", mfa_status="ENROLLED", last_successful_login=recent)
    user("u-net", "net", mfa_status="UN_ENROLLED", last_successful_login=old)
    user("u-fed", "fed", federated=True)
    user("u-svc", "svc", service_user=True)
    user("u-dev", "dev", APPS, mfa_status="ENROLLED")
    user("u-off", "off", active=False)

    def group(key, name, members, domain=DEFAULT):
        data = {
            "id": key,
            "ocid": f"ocid1.group.oc1..{key}",
            "display_name": name,
            "members": [{"value": m, "type": "User"} for m in members],
        }
        add("identity_domains.groups", key, data, domain)

    group("g-admins", "Administrators", ["u-admin"])
    group("g-net", "NetworkAdmins", ["u-net"])
    group("g-empty", "EmptyGroup", [])
    group("g-ogc", "ogc_admin", ["u-admin"])
    group("g-dev", "AppDevs", ["u-dev"], APPS)

    def dynamic(key, name, rule):
        data = {
            "id": key,
            "ocid": f"ocid1.dynamicgroup.oc1..{key}",
            "display_name": name,
            "matching_rule": rule,
        }
        add("identity_domains.dynamic_groups", key, data, DEFAULT)

    dynamic("dg-funcs", "funcs", "ALL {resource.type = 'fnfunc'}")
    dynamic("dg-scoped", "scoped", f"ALL {{instance.compartment.id = '{PROD}'}}")
    dynamic("dg-unused", "unused", f"ALL {{instance.compartment.id = '{PROD}'}}")
    add(
        "identity_domains.api_keys",
        "k-old",
        {"id": "k-old", "user_id": "u-net", "created": (NOW - timedelta(days=200)).isoformat()},
        DEFAULT,
    )
    add(
        "identity_domains.api_keys",
        "k-new",
        {"id": "k-new", "user_id": "u-admin", "created": (NOW - timedelta(days=10)).isoformat()},
        DEFAULT,
    )

    def policy(key, name, statements):
        data = {
            "id": key,
            "name": name,
            "compartment_id": tenancy,
            "statements": statements,
            "lifecycle_state": "ACTIVE",
        }
        add("identity.policies", key, data)

    network = [
        "Allow group NetworkAdmins to manage virtual-network-family in compartment Production",
        "Allow group 'Default'/'NetworkAdmins' to manage all-resources in tenancy",
    ]
    policy(
        "p-admin",
        "Tenant Admin Policy",
        ["ALLOW GROUP Administrators to manage all-resources IN TENANCY"],
    )
    policy("p-net", "network", network)
    policy("p-net-copy", "network-copy", [s.upper().replace(" ", "  ") for s in network])
    policy(
        "p-stale",
        "stale",
        [
            "Allow group Ghosts to read all-resources in tenancy",
            "Allow group EmptyGroup to read buckets in compartment Retired",
        ],
    )
    policy(
        "p-iam",
        "iam",
        [
            "Allow group 'Apps'/'AppDevs' to manage users in tenancy",
            "Allow any-user to manage buckets in tenancy",
            "Allow dynamic-group funcs to manage all-resources in compartment Production",
            f"Allow dynamic-group scoped to read buckets in compartment id {PROD}",
            "Endorse group NetworkAdmins to read all-resources in tenancy Partner",
            "Define tenancy Partner as ocid1.tenancy.oc1..aaaafakepartner",
            "this is not a statement",
        ],
    )
    policy("p-repeat", "repeat", [network[0]])
    return records


@pytest.fixture
def inventory():
    return Inventory(TENANCY, identity_records())


def rules(findings):
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.rule_id].append(finding)
    return grouped


@pytest.fixture
def policy(inventory):
    return rules(policy_findings(inventory, "scope"))


def subjects(findings):
    return sorted(f.description.split(":")[0] for f in findings)


def test_manage_all_resources_severity_and_administrator_exception(policy):
    by_policy = {(f.resource_ocid, f.severity) for f in policy["POL-MANAGE-002"]}
    assert by_policy == {
        ("p-admin", "INFO"),
        ("p-net", "CRITICAL"),
        ("p-net-copy", "CRITICAL"),
        ("p-iam", "HIGH"),  # dynamic group, compartment scope
    }


def test_other_manage_grants(policy):
    found = {(f.resource_ocid, f.title, f.severity) for f in policy["POL-MANAGE-001"]}
    assert ("p-net", "Grant to manage virtual-network-family", "LOW") in found
    assert ("p-iam", "Grant to manage users", "MEDIUM") in found
    assert ("p-iam", "Grant to manage buckets", "MEDIUM") in found
    assert not any("read" in title for _, title, _ in found)


def test_iam_resource_access_outside_administrators(policy):
    assert [f.title for f in policy["POL-IAM-001"]] == ["Non-administrator can manage users"]


def test_any_user_grant(policy):
    (finding,) = policy["POL-ANY-001"]
    assert finding.severity == "HIGH" and "any-user" in finding.description


def test_broad_dynamic_group_with_manage_only(policy):
    (finding,) = policy["POL-DG-001"]
    assert "funcs" in finding.description and "scoped" not in finding.description


def test_cross_tenancy_and_unparsed_statements(policy):
    assert len(policy["POL-XTEN-001"]) == 2  # Endorse and Define
    (unparsed,) = policy["POLICY-PARSE-001"]
    assert "this is not a statement" in unparsed.description


def test_stale_references_and_policy_without_effect(policy):
    stale = " ".join(f.description for f in policy["POL-STALE-001"])
    assert "group Ghosts not found" in stale and "compartment Retired is deleted" in stale
    assert [f.resource_ocid for f in policy["POL-UNUSED-001"]] == ["p-stale"]


def test_duplicate_policies_and_statements(policy):
    assert sorted(f.resource_ocid for f in policy["POL-DUP-001"]) == ["p-net", "p-net-copy"]
    (statement,) = policy["POL-DUP-002"]  # repeats only inside duplicate policies are excluded
    assert "virtual-network-family" in statement.description
    assert "3 times" in statement.description


def test_unused_groups_and_dynamic_groups(policy):
    groups = {f.resource_ocid: f.description for f in policy["IAM-GRP-001"]}
    assert set(groups) == {"ocid1.group.oc1..g-empty"}  # application groups are excluded
    assert "has no members" in groups["ocid1.group.oc1..g-empty"]
    assert [f.resource_ocid for f in policy["IAM-DG-001"]] == ["ocid1.dynamicgroup.oc1..dg-unused"]


def test_users_without_groups_and_without_mfa(inventory):
    found = rules(identity_findings(inventory, "scope"))
    assert subjects(found["IAM-USR-001"]) == ["fed (Default)", "svc (Default)"]
    (mfa,) = found["IAM-USR-002"]  # federated, service and inactive users are excluded
    assert mfa.description.startswith("net (Default)") and mfa.severity == "HIGH"


def test_api_keys_older_than_rotation_age(inventory):
    (old,) = api_key_findings(inventory, "scope", NOW, 90)
    assert old.resource_type == "api-key" and "net (Default)" in old.description
    assert "do not expire" in old.description
    assert api_key_findings(inventory, "scope", NOW, 365) == []


def test_inactive_users_and_groups_use_sign_in_and_audit(inventory):
    found = rules(activity_findings(inventory, "scope", NOW, 90, {"ocid1.user.oc1..u-dev"}))
    assert subjects(found["IAM-USR-003"]) == ["fed (Default)", "net (Default)", "svc (Default)"]
    assert [f.resource_ocid for f in found["IAM-GRP-002"]] == ["ocid1.group.oc1..g-net"]
    everyone_active = activity_findings(
        inventory,
        "scope",
        NOW,
        90,
        {f"ocid1.user.oc1..{u}" for u in ("u-net", "u-fed", "u-svc", "u-dev")},
    )
    assert everyone_active == []


def test_finding_identity_is_stable_and_scoped(inventory):
    first = {f.id for f in policy_findings(inventory, "scope")}
    assert first == {f.id for f in policy_findings(inventory, "scope")}
    assert first.isdisjoint({f.id for f in policy_findings(inventory, "other-scope")})


def test_clean_tenancy_raises_nothing():
    records = defaultdict(list)
    scope = {"tenancy": TENANCY, "dataset": "", "region": "r", "domain": DEFAULT}
    records["identity.domains"] = [
        {"scope": scope, "key": DEFAULT, "data": {"display_name": "Default"}}
    ]
    records["identity_domains.users"] = [
        {
            "scope": scope,
            "key": "u",
            "data": {"id": "u", "user_name": "u", "mfa_status": "ENROLLED"},
        }
    ]
    records["identity_domains.groups"] = [
        {
            "scope": scope,
            "key": "g",
            "data": {"id": "g", "display_name": "Readers", "members": [{"value": "u"}]},
        }
    ]
    records["identity.policies"] = [
        {
            "scope": scope,
            "key": "p",
            "data": {
                "id": "p",
                "name": "p",
                "compartment_id": TENANCY,
                "statements": ["Allow group Readers to read buckets in tenancy"],
            },
        }
    ]
    inventory = Inventory(TENANCY, records)
    assert policy_findings(inventory, "s") == []
    assert identity_findings(inventory, "s") == []


def with_apps_policy(records):
    records["identity.policies"].append(
        {
            "scope": {"tenancy": TENANCY, "dataset": "identity.policies", "domain": ""},
            "key": "p-apps",
            "data": {
                "id": "p-apps",
                "name": "apps-only",
                "compartment_id": TENANCY,
                "statements": ["Allow group 'Apps'/'Missing' to read buckets in tenancy"],
                "lifecycle_state": "ACTIVE",
            },
        }
    )
    return records


def test_group_in_scanned_domain_is_still_reported_missing():
    found = rules(policy_findings(Inventory(TENANCY, with_apps_policy(identity_records())), "s"))
    assert any("Apps/Missing not found" in f.description for f in found["POL-STALE-001"])
    assert "p-apps" in {f.resource_ocid for f in found["POL-UNUSED-001"]}


def test_group_in_unscanned_domain_is_unknown_never_stale_or_unused():
    inventory = Inventory(TENANCY, with_apps_policy(identity_records()), {DEFAULT})
    found = rules(policy_findings(inventory, "s"))
    stale = " ".join(f.description for f in found["POL-STALE-001"])
    assert "Apps/" not in stale and "group Ghosts not found" in stale  # Default still judged
    assert "p-apps" not in {f.resource_ocid for f in found["POL-UNUSED-001"]}
    unknown = [i for i in inventory.analyze_statements() if i.unknown]
    assert {i.policy["key"] for i in unknown} == {"p-iam", "p-apps"}
    assert "Apps not scanned" in unknown[0].unknown[0]
    # Subject-independent rules still run on those statements.
    assert any(f.resource_ocid == "p-iam" for f in found["POL-MANAGE-001"])


def test_no_domains_scanned_judges_no_subjects():
    inventory = Inventory(TENANCY, identity_records(), set())
    found = rules(policy_findings(inventory, "s"))
    assert "group Ghosts" not in " ".join(f.description for f in found["POL-STALE-001"])
    assert not found["POL-UNUSED-001"]
    assert found["POL-MANAGE-002"] and found["POL-ANY-001"]
