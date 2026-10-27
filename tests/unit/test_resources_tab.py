"""Resource organization: compartment tree per tenancy without JavaScript."""

from unittest.mock import AsyncMock

import pytest

from oci_governance_center.models import Batch, Identity, Record, ScanSettings, Scope
from oci_governance_center.web import views
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def compartment(ident, parent, name, state="ACTIVE"):
    return Record(
        key=ident,
        data={"id": ident, "compartment_id": parent, "name": name, "lifecycle_state": state},
    )


@pytest.fixture
def organization(settings, service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    root = parent.domain.tenancy_ocid
    service.store.publish(
        generation,
        Batch(
            scope=Scope(tenancy=root, dataset="identity.compartments", region="us-ashburn-1"),
            records=[
                compartment("c-prod", root, "Production"),
                compartment("c-apps", "c-prod", "Applications"),
                compartment("c-db", "c-prod", "Databases"),
                compartment("c-old", "c-prod", "Retired", "DELETED"),
                compartment("c-dev", root, "development"),
                compartment("c-lost", "c-missing", "Orphaned"),
            ],
        ),
    )
    service.store.publish(
        generation,
        Batch(
            scope=Scope(tenancy=child.ocid, dataset="identity.compartments", region="us-ashburn-1"),
            records=[compartment("c-child", child.ocid, "ChildOnly")],
        ),
    )
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    return client, generation, root, child.ocid


def test_tree_nests_sorts_and_counts_descendants(service, organization):
    _, generation, root, _ = organization
    records = views.records_by_dataset(service.store.rows("records", generation))
    tree = views.compartment_tree(records, service.store.rows("coverage"), root, "Parent")["tree"]
    assert [c["name"] for c in tree["children"]] == ["development", "Orphaned", "Production"]
    production = tree["children"][2]
    assert [c["name"] for c in production["children"]] == ["Applications", "Databases"]
    assert tree["descendants"] == 5 and production["descendants"] == 2
    assert tree["children"][1]["orphan"] and not production["orphan"]


def test_resources_tab_defaults_to_parent_and_hides_deleted(organization):
    client, _, root, _ = organization
    page = client.get("/resources").text
    assert "<script" not in page and "Synthetic Organization" in page
    assert page.index("Production") < page.index("Applications") < page.index("Databases")
    assert "<details open>" in page
    assert "Retired" not in page and "ChildOnly" not in page
    assert "parent compartment not collected" in page
    assert "5 compartments" in page


def test_resources_tab_includes_deleted_and_switches_tenancy(organization):
    client, _, _, child_id = organization
    assert "Retired" in client.get("/resources?deleted=true").text
    child_page = client.get(f"/resources?tenancy={child_id}").text
    assert "ChildOnly" in child_page and "Production" not in child_page
    assert client.get("/resources?tenancy=ocid1.tenancy.oc1..unknown").status_code == 400


def test_incomplete_or_missing_collection_is_explicit(service, organization):
    client, generation, root, child_id = organization
    service.store.publish(
        generation,
        Batch(
            scope=Scope(tenancy=root, dataset="identity.compartments", region="us-ashburn-1"),
            complete=False,
            error="Compartment read denied",
        ),
    )
    stale = client.get("/resources").text
    assert "Compartment collection is incomplete" in stale and "Production" in stale
    with service.store.db() as db:
        db.execute("DELETE FROM coverage")
    assert "have not been collected" in client.get("/resources").text


def publish_policies(store, generation, root, compartment, policies, complete=True):
    store.publish(
        generation,
        Batch(
            scope=Scope(
                tenancy=root,
                dataset="identity.policies",
                region="us-ashburn-1",
                compartment=compartment,
            ),
            records=[
                Record(
                    key=ident,
                    data={
                        "id": ident,
                        "compartment_id": compartment,
                        "statements": statements,
                        "lifecycle_state": state,
                    },
                )
                for ident, statements, state in policies
            ],
            complete=complete,
            error="" if complete else "Policy read denied",
        ),
    )


def test_policy_statement_counts_per_compartment_and_hierarchy(service, organization):
    client, generation, root, _ = organization
    store = service.store
    publish_policies(store, generation, root, root, [("p-root", ["a", "b"], "ACTIVE")])
    publish_policies(
        store,
        generation,
        root,
        "c-prod",
        [("p-prod", ["c", "d", "e"], "ACTIVE"), ("p-gone", ["x"], "DELETED")],
    )
    publish_policies(store, generation, root, "c-apps", [("p-apps", ["f"], "ACTIVE")])
    records = views.records_by_dataset(store.rows("records", generation))
    view = views.compartment_tree(records, store.rows("coverage"), root, "Parent")
    tree = view["tree"]
    production = tree["children"][2]
    applications, databases = production["children"]
    assert (tree["own"], tree["hierarchy"]) == (2, 2)
    assert (production["own"], production["hierarchy"]) == (3, 5)  # deleted policy excluded
    assert (applications["own"], applications["hierarchy"]) == (1, 6)
    assert (databases["own"], databases["hierarchy"]) == (0, 5)
    page = client.get("/resources").text
    assert "3 policy statements in compartment" in page
    assert "6 policy statements in hierarchy" in page
    assert "compartment=c-prod" in page and "<script" not in page


def test_policy_counts_are_hidden_when_incomplete_or_disabled(service, organization):
    client, generation, root, _ = organization
    store = service.store
    assert "Policies have not been collected" in client.get("/resources").text
    publish_policies(store, generation, root, root, [("p-root", ["a"], "ACTIVE")])
    publish_policies(store, generation, root, "c-prod", [], complete=False)
    page = client.get("/resources").text
    assert "Policy collection is incomplete" in page and "statements in hierarchy" not in page
    assert "— policy statements" in page
    store.save_scan_settings(generation, root, ScanSettings(policies=False), "admin")
    assert "Policy collection is disabled" in client.get("/resources").text
