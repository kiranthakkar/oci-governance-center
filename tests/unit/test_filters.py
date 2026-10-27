"""Findings, Inventory and Activity filters: tenancy plus tab-specific narrowing."""

from datetime import timedelta
from unittest.mock import AsyncMock

import pytest

from oci_governance_center.models import Batch, Identity, Record, Scope, now
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


@pytest.fixture
def organization(settings, service, parent, child, monkeypatch):
    """A parent and child with findings, inventory and Audit events in both tenancies."""
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    parent_id, child_id = parent.domain.tenancy_ocid, child.ocid
    region = "us-ashburn-1"

    def publish(batch):
        service.store.publish(generation, batch)
        service.findings(generation, batch, None)

    publish(
        Batch(
            scope=Scope(tenancy=parent_id, dataset="cloud_guard.configuration", region=region),
            records=[Record(key=parent_id, data={"status": "DISABLED"})],
        )
    )
    publish(
        Batch(
            scope=Scope(tenancy=child_id, dataset="cloud_guard.problems", region=region),
            records=[
                Record(
                    key="problem", data={"risk_level": "CRITICAL", "resource_name": "Open bucket"}
                )
            ],
        )
    )
    service.store.publish(
        generation,
        Batch(
            scope=Scope(tenancy=child_id, dataset="identity_domains.groups", region=region),
            complete=False,
            error="Missing group read access",
        ),
    )
    publish(
        Batch(
            scope=Scope(tenancy=parent_id, dataset="identity_domains.users", region=region),
            records=[
                Record(key="u1", data={"user_name": "alice.admin"}),
                Record(key="u2", data={"user_name": "bob"}),
            ],
        )
    )
    publish(
        Batch(
            scope=Scope(tenancy=child_id, dataset="identity.policies", region="eu-frankfurt-1"),
            records=[Record(key="p1", data={"name": "child-network-policy"})],
        )
    )
    base = now() - timedelta(hours=2)
    events = {
        parent_id: [
            ("e1", "Alice.Admin@example.test", "com.oraclecloud.identity.createpolicy", "200"),
            ("e2", "bob@example.test", "com.oraclecloud.objectstorage.getbucket", "404"),
        ],
        child_id: [("e3", "carol@example.test", "com.oraclecloud.identity.updateuser", "200")],
    }
    for tenancy, items in events.items():
        records = [
            {
                "id": ident,
                # Child events are newest, so Alice's e1 is the oldest event overall.
                "time": (
                    base + timedelta(minutes=index + (10 if tenancy == child_id else 0))
                ).isoformat(),
                "type": kind,
                "principal_name": name,
                "action": "POST",
                "status": status,
            }
            for index, (ident, name, kind, status) in enumerate(items)
        ]
        audit_scope = Scope(tenancy=tenancy, dataset="audit.events", region=region)
        service.store.audit_commit(
            generation, audit_scope, base.isoformat(), now().isoformat(), records
        )
        service.store.publish(generation, Batch(scope=audit_scope))
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    return client, parent_id, child_id


def test_findings_filter_by_severity_type_rule_and_tenancy(organization):
    client, parent_id, child_id = organization
    critical = client.get("/data/findings?severity=CRITICAL").text
    assert "Open bucket" in critical and "Cloud Guard is not enabled" not in critical
    governance = client.get("/data/findings?source=governance").text
    assert "Cloud Guard is not enabled" in governance and "Open bucket" not in governance
    coverage = client.get("/data/findings?rule=OGC-ACCESS-002").text
    assert "Missing group read access" in coverage and "Open bucket" not in coverage
    child_only = client.get(f"/data/findings?tenancy={child_id}").text
    assert "Open bucket" in child_only and "Cloud Guard is not enabled" not in child_only
    combined = client.get(f"/data/findings?tenancy={child_id}&severity=HIGH").text
    assert "Missing group read access" in combined and "Open bucket" not in combined
    assert "1 result match these filters" in combined
    titled = client.get("/data/findings?q=bucket").text
    assert "Open bucket" in titled and "Missing group read access" not in titled


def test_findings_menus_offer_labels_and_sort_most_severe_first(organization):
    client, parent_id, child_id = organization
    page = client.get("/data/findings").text
    assert f'<option value="{child_id}">Synthetic Child</option>' in page
    assert "Synthetic Organization (parent)" in page
    assert '<option value="CG-PROBLEM">CG-PROBLEM</option>' in page
    assert '<option value="security_zone">Security Zone</option>' in page
    assert page.index("Open bucket") < page.index("Cloud Guard is not enabled")
    selected = client.get("/data/findings?severity=HIGH").text
    assert '<option value="HIGH" selected>HIGH</option>' in selected


def test_inventory_filters_by_dataset_tenancy_region_and_name(organization):
    client, parent_id, child_id = organization
    users = client.get("/data/records?dataset=identity_domains.users").text
    assert "alice.admin" in users and "child-network-policy" not in users
    child = client.get(f"/data/records?tenancy={child_id}").text
    assert "child-network-policy" in child and "alice.admin" not in child
    frankfurt = client.get("/data/records?region=eu-frankfurt-1").text
    assert "child-network-policy" in frankfurt and "bob" not in frankfurt
    named = client.get("/data/records?q=ALICE").text
    assert "alice.admin" in named and ">bob<" not in named
    menus = client.get("/data/records").text
    assert '<option value="identity_domains.users">' in menus


def test_coverage_filters_by_dataset_and_result(organization):
    client, _, _ = organization
    failed = client.get("/data/coverage?status=failed").text
    # Dataset names also appear in the filter menu, so check the table cells.
    assert "<td>identity_domains.groups</td>" in failed
    assert "<td>identity.policies</td>" not in failed
    dataset = client.get("/data/coverage?dataset=identity.policies").text
    assert "<td>identity.policies</td>" in dataset
    assert "<td>identity_domains.groups</td>" not in dataset


def test_activity_filters_by_principal_event_result_tenancy_and_region(organization):
    client, parent_id, child_id = organization
    alice = client.get("/activity?principal=alice").text
    assert "Alice.Admin@example.test" in alice and "bob@example.test" not in alice
    by_event = client.get("/activity?event=UpdateUser").text
    assert "carol@example.test" in by_event and "Alice.Admin@example.test" not in by_event
    failures = client.get("/activity?result=failure").text
    assert "bob@example.test" in failures and "carol@example.test" not in failures
    child = client.get(f"/activity?tenancy={child_id}").text
    assert "carol@example.test" in child and "bob@example.test" not in child
    assert "No events" in client.get("/activity?region=eu-frankfurt-1").text
    page = client.get("/activity").text
    assert '<option value="us-ashburn-1">us-ashburn-1</option>' in page


def test_activity_text_filters_treat_sql_wildcards_literally(organization):
    client, _, _ = organization
    for wildcard in ("%", "_"):
        assert "No events" in client.get("/activity", params={"principal": wildcard}).text


def test_activity_filter_runs_before_the_event_limit(service, organization, parent):
    _, parent_id, _ = organization
    generation = service.store.state()[0]
    # Alice's event is the oldest; an unfiltered limit of one would never include it.
    assert [e["id"] for e in service.store.audit_events(generation, limit=1)] != ["e1"]
    matched = service.store.audit_events(generation, limit=1, principal="alice")
    assert [e["id"] for e in matched] == ["e1"]


@pytest.mark.parametrize(
    "url",
    [
        "/data/findings?severity=SEVERE",
        "/data/findings?source=unknown",
        "/data/coverage?status=broken",
        "/activity?result=maybe",
        "/activity?principal=" + "x" * 201,
    ],
)
def test_unsupported_filter_values_are_rejected(organization, url):
    client, _, _ = organization
    assert client.get(url).status_code == 400
