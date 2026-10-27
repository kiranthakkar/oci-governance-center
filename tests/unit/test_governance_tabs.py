"""Cloud Guard and Cloud Advisor tabs, their collection projections and navigation."""

import re
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest

from oci_governance_center.collectors.inventory import inventory
from oci_governance_center.models import Batch, Identity, Record, Scope
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def governance_batches(domain, monkeypatch):
    """Run the governance family against synthetic SDK objects; returns batches by dataset."""
    clients = {
        "identity": NS(list_compartments=lambda *a, **k: []),
        "guard": NS(
            get_configuration=lambda *_: NS(
                data=NS(status="ENABLED", reporting_region="us-phoenix-1")
            ),
            list_problems=lambda *a, **k: [
                NS(
                    id="problem-1",
                    resource_name="bucket-a",
                    risk_level="HIGH",
                    risk_score=7.5,
                    target_id="target-1",
                    resource_type="Bucket",
                )
            ],
            list_security_zones=lambda *a, **k: [],
        ),
        "optimizer": NS(
            list_enrollment_statuses=lambda *_: [NS(id="e", status="ACTIVE", status_reason="")],
            list_categories=lambda *_: [NS(id="cat-1", name="cost-management")],
            list_recommendations=lambda *_: [
                NS(
                    id="rec-1",
                    category_id="cat-1",
                    name="Downsize idle instances",
                    importance="HIGH",
                    status="PENDING",
                    estimated_cost_saving=12.5,
                    resource_counts=[NS(status="PENDING", count=3), NS(status="DONE", count=1)],
                    secret_field="must not be kept",
                )
            ],
        ),
    }
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.client", lambda kind, *_: clients[kind]
    )
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items",
        lambda method, *a, **k: method(*a, **k),
    )
    return {batch.scope.dataset: batch for batch in inventory(object(), domain, "governance")}


def test_collection_keeps_reviewed_problem_and_recommendation_fields(domain, monkeypatch):
    batches = governance_batches(domain, monkeypatch)
    problem = batches["cloud_guard.problems"].records[0].data
    assert problem["risk_score"] == 7.5 and problem["target_id"] == "target-1"
    assert batches["cloud_guard.problems"].scope.region == "us-phoenix-1"
    categories = batches["optimizer.categories"]
    assert categories.complete and categories.records[0].data["name"] == "cost-management"
    recommendation = batches["optimizer.recommendations"].records[0].data
    assert recommendation["estimated_cost_saving"] == 12.5
    assert recommendation["resource_counts"] == {"PENDING": 3, "DONE": 1}
    assert "secret_field" not in recommendation


def test_category_failure_does_not_block_recommendations(domain, monkeypatch):
    batches = governance_batches(domain, monkeypatch)
    assert batches["optimizer.recommendations"].complete
    # Failing categories are their own coverage scope.
    from oci_governance_center.collectors import inventory as module

    clients = module.client("optimizer")
    clients.list_categories = lambda *_: (_ for _ in ()).throw(RuntimeError("denied"))
    batches = {b.scope.dataset: b for b in inventory(object(), domain, "governance")}
    assert not batches["optimizer.categories"].complete
    assert batches["optimizer.recommendations"].complete


@pytest.fixture
def organization(settings, service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    parent_id, child_id = parent.domain.tenancy_ocid, child.ocid

    def publish(tenancy, dataset, records, region="us-ashburn-1"):
        batch = Batch(scope=Scope(tenancy=tenancy, dataset=dataset, region=region), records=records)
        service.store.publish(generation, batch)
        service.findings(generation, batch, None)

    publish(
        parent_id,
        "cloud_guard.configuration",
        [Record(key=parent_id, data={"status": "ENABLED", "reporting_region": "us-ashburn-1"})],
    )
    publish(
        child_id, "cloud_guard.configuration", [Record(key=child_id, data={"status": "DISABLED"})]
    )
    problem = {
        "resource_name": "bucket-public",
        "resource_type": "Bucket",
        "risk_level": "CRITICAL",
        "region": "us-ashburn-1",
        "detector_rule_id": "BUCKET_IS_PUBLIC",
        "resource_id": "ocid1.bucket.oc1..aaaafakebucket",
    }
    zone_problem = {
        "resource_name": "instance-zone",
        "resource_type": "Instance",
        "risk_level": "HIGH",
        "problem_category": "SECURITY_ZONE",
        "region": "us-ashburn-1",
    }
    publish(
        parent_id,
        "cloud_guard.problems",
        [Record(key="p1", data=problem), Record(key="p2", data=zone_problem)],
    )
    # A later snapshot without p2 resolves its finding while p1 stays open.
    publish(parent_id, "cloud_guard.problems", [Record(key="p1", data=problem)])
    publish(
        parent_id,
        "security_zones.zones",
        [
            Record(
                key="z1",
                data={"id": "z1", "display_name": "prod-zone", "lifecycle_state": "ACTIVE"},
            )
        ],
    )
    publish(
        parent_id,
        "optimizer.enrollment",
        [Record(key="e1", data={"status": "ACTIVE"})],
    )
    publish(child_id, "optimizer.enrollment", [])
    publish(
        parent_id,
        "optimizer.categories",
        [Record(key="cat-1", data={"name": "cost-management"})],
    )
    publish(
        parent_id,
        "optimizer.recommendations",
        [
            Record(
                key="r1",
                data={
                    "name": "Downsize idle instances",
                    "category_id": "cat-1",
                    "importance": "HIGH",
                    "status": "PENDING",
                    "estimated_cost_saving": 40.0,
                    "resource_counts": {"PENDING": 2},
                },
            ),
            Record(
                key="r2",
                data={
                    "name": "Delete unattached volumes",
                    "category_id": "cat-1",
                    "importance": "LOW",
                    "status": "DISMISSED",
                    "estimated_cost_saving": 5.0,
                },
            ),
        ],
    )
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    return client, parent_id, child_id


def test_navigation_lists_the_new_tabs_in_order(organization):
    client, _, _ = organization
    nav = re.search(r"<nav>(.*?)</nav>", client.get("/").text, re.S)[1]
    labels = re.findall(r'<a href="[^"]+">([^<]+)</a>', nav)
    assert labels == [
        "Overview",
        "Coverage",
        "Cloud Guard",
        "Cloud Advisor",
        "Cost",
        "Resource organization",
        "Identity",
        "Activity",
        "Scan",
    ]
    assert "Findings</a>" not in nav and "Inventory</a>" not in nav


def test_cloud_guard_tab_shows_status_problems_and_zones(organization):
    client, parent_id, child_id = organization
    page = client.get("/cloud-guard?status=").text  # all statuses; the default is open only
    assert "<script" not in page
    assert "Enabled" in page and "Disabled" in page
    assert 'sev-CRITICAL">CRITICAL 1' in page
    assert "bucket-public" in page and "BUCKET_IS_PUBLIC" in page
    assert "instance-zone" in page and "Resolved" in page  # resolved keeps its details
    assert "prod-zone" in page


def test_cloud_guard_filters(organization):
    client, parent_id, _ = organization
    zones = client.get("/cloud-guard?source=security_zone&status=").text
    assert "instance-zone" in zones and "bucket-public" not in zones
    critical = client.get("/cloud-guard?severity=CRITICAL&status=open").text
    assert "bucket-public" in critical and "instance-zone" not in critical
    by_type = client.get("/cloud-guard?resource_type=Instance&status=").text
    assert "instance-zone" in by_type and "bucket-public" not in by_type
    searched = client.get("/cloud-guard?q=bucket_is").text
    assert "instance-zone" not in client.get("/cloud-guard").text  # resolved hidden by default
    assert "bucket-public" in searched and "instance-zone" not in searched
    assert client.get("/cloud-guard?severity=SEVERE").status_code == 400
    assert client.get("/cloud-guard?source=advisor").status_code == 400


def test_cloud_advisor_tab_shows_enrollment_categories_and_savings(organization):
    client, _, _ = organization
    page = client.get("/cloud-advisor").text
    assert "<script" not in page
    assert "Active" in page and "Not Enrolled" in page
    assert "cost-management" in page and "Downsize idle instances" in page
    assert "Pending estimated saving: 40.00" in page  # dismissed savings are not counted
    assert "PENDING: 2" in page


def test_cloud_advisor_filters(organization):
    client, _, child_id = organization
    pending = client.get("/cloud-advisor?status=PENDING").text
    assert "Downsize idle instances" in pending and "Delete unattached volumes" not in pending
    low = client.get("/cloud-advisor?importance=LOW").text
    assert "Delete unattached volumes" in low and "Downsize idle instances" not in low
    assert "No recommendations match" in client.get(f"/cloud-advisor?tenancy={child_id}").text
    assert '<option value="cat-1">cost-management</option>' in pending
