"""Organization cost: Usage API collection, scan gating and the Cost tab."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest

from oci_governance_center.collectors import cost as module
from oci_governance_center.models import Batch, Identity, Record, ScanSettings, Scope
from oci_governance_center.web import views
from tests.conftest import install
from tests.unit.test_web import browser, logged_in

CHILD = "ocid1.tenancy.oc1..aaaafakechild"
TODAY = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)


def usage_item(month, tenant, service, compartment, path, amount, currency="USD", **extra):
    return NS(
        time_usage_started=datetime.fromisoformat(f"{month}-01T00:00:00+00:00"),
        tenant_id=tenant,
        tenant_name=f"name-{tenant[-5:]}",
        service=service,
        compartment_id=compartment,
        compartment_path=path,
        computed_amount=amount,
        currency=currency,
        **extra,
    )


@pytest.fixture
def usage_api(monkeypatch):
    calls = []
    items = []

    def request(details, **_):
        calls.append(details)
        return items

    monkeypatch.setattr(module, "client", lambda kind, *_: NS(request_summarized_usages=request))
    monkeypatch.setattr(module, "all_items", lambda method, *a, **k: method(*a, **k))
    return calls, items


def test_request_covers_twelve_whole_months_at_midnight_utc(domain, usage_api):
    calls, _ = usage_api
    module.read_costs(object(), domain, TODAY)
    (details,) = calls
    assert details.time_usage_started == datetime(2025, 4, 1, tzinfo=UTC)
    assert details.time_usage_ended == datetime(2026, 4, 1, tzinfo=UTC)
    assert details.granularity == "MONTHLY" and details.query_type == "COST"
    assert details.tenant_id == domain.tenancy_ocid
    assert details.group_by == ["tenantId", "service", "compartmentId", "compartmentPath"]
    assert details.compartment_depth == 6
    assert len(details.group_by) <= 4  # OCI: "Number of groupBy key is over 4"


def test_window_crosses_year_boundaries():
    assert module.window(datetime(2026, 12, 31, tzinfo=UTC)) == (
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2027, 1, 1, tzinfo=UTC),
    )


def test_projection_keeps_only_cost_dimensions_and_merges_duplicates(domain, usage_api):
    _, items = usage_api
    parent = domain.tenancy_ocid
    items += [
        usage_item("2026-03", parent, "Compute", "c1", "root/Prod", 10.0, resource_id="secret"),
        usage_item("2026-03", parent, "Compute", "c1", "root/Prod", 2.5, tags=["x"]),
        usage_item("2026-03", parent, "Compute", "c1", "root/Prod", None),
    ]
    (record,) = module.read_costs(object(), domain, TODAY)
    assert record.data == {
        "month": "2026-03",
        "tenant_id": parent,
        "tenant_name": f"name-{parent[-5:]}",
        "service": "Compute",
        "compartment_id": "c1",
        "compartment_path": "root/Prod",
        "amount": 12.5,
        "currency": "USD",
    }


def test_denied_read_is_a_coverage_gap(domain, monkeypatch):
    def denied(*_, **__):
        raise RuntimeError("NotAuthorizedOrNotFound")

    monkeypatch.setattr(module, "client", lambda *_: NS(request_summarized_usages=denied))
    monkeypatch.setattr(module, "all_items", lambda method, *a, **k: method(*a, **k))
    batch = module.costs(object(), domain, TODAY)
    assert not batch.complete and batch.scope.dataset == "cost.monthly" and batch.error


@pytest.fixture
def scanned(service, parent, monkeypatch):
    generation = install(service.store, parent)
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    monkeypatch.setattr("oci_governance_center.service.api_signer", lambda *_: object())
    monkeypatch.setattr("oci_governance_center.service.bind_identity", lambda *_: None)
    monkeypatch.setattr("oci_governance_center.service.inventory", lambda *_: iter([]))
    collect = Mock(
        side_effect=lambda signer, domain, today: Batch(
            scope=Scope(tenancy=domain.tenancy_ocid, dataset="cost.monthly", region="r")
        )
    )
    monkeypatch.setattr("oci_governance_center.service.costs", collect)
    return generation, collect


def datasets(store):
    return {json.loads(row["scope"])["dataset"] for row in store.rows("coverage")}


def test_parent_scan_collects_cost_once(service, parent, child, scanned):
    generation, collect = scanned
    service.scan_one(generation, parent, None, "governance")
    assert collect.call_count == 1 and "cost.monthly" in datasets(service.store)
    service.scan_one(generation, parent, None, "identity")
    assert collect.call_count == 1  # identity-only runs do not read cost


def test_cost_setting_off_reads_nothing_and_reports_no_gap(service, parent, scanned):
    generation, collect = scanned
    tenancy = parent.domain.tenancy_ocid
    service.store.save_scan_settings(generation, tenancy, ScanSettings(cost=False), "admin")
    service.scan_one(generation, parent, None, "all")
    assert collect.call_count == 0 and "cost.monthly" not in datasets(service.store)


def rows(parent):
    def record(month, tenant, service, path, amount, currency="USD"):
        data = {
            "month": month,
            "tenant_id": tenant,
            "tenant_name": "Unlisted" if tenant.endswith("other") else "x",
            "service": service,
            "compartment_id": path,
            "compartment_path": path,
            "amount": amount,
            "currency": currency,
        }
        return Record(key=json.dumps([month, tenant, service, path, currency]), data=data)

    return [
        record("2026-02", parent, "Compute", "root/Prod", 100.0),
        record("2026-03", parent, "Compute", "root/Prod", 40.0),
        record("2026-03", parent, "Compute", "root/Prod/Web", 10.0),
        record("2026-03", parent, "Object Storage", "root", 5.0),
        record("2026-03", CHILD, "Database", "croot/Data", 20.0),
        record("2026-03", CHILD, "Database", "croot/Data", 3.0, "EUR"),
        record("2026-03", "ocid1.tenancy.oc1..other", "Compute", "oroot", 1.0),
    ]


@pytest.fixture
def cost_page(settings, service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    tenancy = parent.domain.tenancy_ocid
    scope = Scope(tenancy=tenancy, dataset="cost.monthly", region="us-ashburn-1")
    service.store.publish(generation, Batch(scope=scope, records=rows(tenancy)))
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    return client, generation, tenancy


def model(service, generation, parent_id, view, **filters):
    base = {"tenancy": "", "service": "", "month_from": "", "month_to": "", "q": ""}
    return views.cost(
        views.records_by_dataset(service.store.records(generation, include=("cost.",))),
        service.store.rows("coverage"),
        [(parent_id, "Parent"), (CHILD, "Child")],
        base | filters,
        view,
        parent_id,
    )


def test_totals_by_tenancy_and_service_keep_currencies_apart(service, cost_page):
    _, generation, tenancy = cost_page
    data = model(service, generation, tenancy, "tenancy", month_from="2026-03", month_to="2026-03")
    assert data["total"] == {"USD": 76.0, "EUR": 3.0}
    by_name = {r["name"]: r["amount"] for r in data["rows"]}
    assert by_name == {
        "Parent": {"USD": 55.0},
        "Child": {"USD": 20.0, "EUR": 3.0},
        "Unlisted": {"USD": 1.0},
    }
    services = model(service, generation, tenancy, "service", month_from="2026-03")
    assert services["rows"][0]["name"] == "Compute"
    assert services["rows"][0]["amount"] == {"USD": 51.0}


def test_month_range_defaults_to_latest_two_months_and_filters(service, cost_page):
    _, generation, tenancy = cost_page
    data = model(service, generation, tenancy, "tenancy")
    assert (data["month_from"], data["month_to"]) == ("2026-02", "2026-03")
    assert data["total"]["USD"] == 176.0
    february = model(
        service, generation, tenancy, "tenancy", month_to="2026-02", month_from="2026-02"
    )
    assert february["total"] == {"USD": 100.0}
    assert [t["month"] for t in data["trend"]] == ["2026-02", "2026-03"]


def test_compartment_tree_rolls_cost_up_to_ancestors(service, cost_page):
    _, generation, tenancy = cost_page
    tree = model(service, generation, tenancy, "compartment", month_from="2026-03")["tree"]
    assert tree["own"] == {"USD": 5.0} and tree["rolled"] == {"USD": 55.0}
    (prod,) = tree["children"]
    assert prod["own"] == {"USD": 40.0} and prod["rolled"] == {"USD": 50.0}
    assert prod["children"][0]["name"] == "Web"
    child_tree = model(
        service, generation, tenancy, "compartment", tenancy=CHILD, month_from="2026-03"
    )["tree"]
    assert child_tree["name"] == "Child" and child_tree["rolled"] == {"USD": 20.0, "EUR": 3.0}


def test_cost_tab_renders_for_viewers_without_scripts(cost_page):
    client, _, _ = cost_page
    page = client.get("/cost").text
    assert "<script" not in page and "Organization cost" in page and "<meter" in page
    assert "USD 176.00" in page
    tree = client.get("/cost?view=compartment&month_from=2026-03").text
    assert "Prod" in tree and "with sub-compartments" in tree
    assert client.get("/cost?view=bogus").status_code == 400
    assert client.get("/cost?month_from=2026-13").status_code == 400
    assert client.get("/cost?tenancy=ocid1.tenancy.oc1..unknown").status_code == 400


def test_cost_tab_states_are_explicit(service, cost_page):
    client, generation, tenancy = cost_page
    scope = Scope(tenancy=tenancy, dataset="cost.monthly", region="us-ashburn-1")
    service.store.publish(generation, Batch(scope=scope, complete=False, error="Denied"))
    failed = client.get("/cost").text
    assert "The latest cost read failed" in failed and "USD 176.00" in failed  # last good data
    service.store.save_scan_settings(generation, tenancy, ScanSettings(cost=False), "admin")
    assert "Cost collection is disabled" in client.get("/cost").text
    with service.store.db() as db:
        db.execute("DELETE FROM records")
        db.execute("DELETE FROM coverage")
    service.store.save_scan_settings(generation, tenancy, ScanSettings(), "admin")
    empty = client.get("/cost").text
    assert "Cost has not been collected yet" in empty and "read usage-report" in empty


def test_other_tabs_do_not_load_cost_rows(service, cost_page):
    _, generation, _ = cost_page
    assert service.store.records(generation, exclude=("cost.",)) == []
    assert len(service.store.records(generation, include=("cost.",))) == 7


def test_same_name_tenancies_keep_separate_costs(service, cost_page):
    _, generation, parent_id = cost_page
    data = views.cost(
        views.records_by_dataset(service.store.records(generation, include=("cost.",))),
        service.store.rows("coverage"),
        [(parent_id, "Same name"), (CHILD, "Same name")],
        {"tenancy": "", "service": "", "month_from": "2026-03", "month_to": "2026-03", "q": ""},
        "tenancy",
        parent_id,
    )
    by_id = {row["tenant_id"]: row for row in data["rows"]}
    assert by_id[parent_id]["name"] == by_id[CHILD]["name"] == "Same name"
    assert by_id[parent_id]["amount"] == {"USD": 55.0}
    assert by_id[CHILD]["amount"] == {"USD": 20.0, "EUR": 3.0}
