"""Coverage flags and durable per-scan diagnostics are visible without server log access."""

from unittest.mock import AsyncMock

import pytest

from oci_governance_center.models import Batch, Identity, Scope
from oci_governance_center.scans import ScanControl
from oci_governance_center.storage import StaleWork
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def failing_scope(store, generation, parent):
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid,
        dataset="identity_domains.groups",
        domain=parent.domain.guid,
        region=parent.domain.home_region,
    )
    store.publish(generation, Batch(scope=scope, complete=False, error="Missing group read access"))
    return scope


def test_completed_scan_keeps_snapshot_after_coverage_recovers(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    ident = control.enqueue(generation, "admin")
    control.claim(generation, "worker")
    scope = failing_scope(store, generation, parent)
    control.finish(generation, ident, "worker", "partial", "One scope incomplete")
    store.publish(generation, Batch(scope=scope))
    job, rows = control.details(generation, ident)
    assert job["status"] == "partial"
    assert rows[0]["status"] == "failed"
    assert rows[0]["error"] == "Missing group read access"
    assert store.rows("coverage", generation)[0]["status"] == "complete"
    newer = install(store, parent)
    assert control.details(newer, ident) is None
    with pytest.raises(StaleWork):
        control.details(generation, ident)


def test_wrong_worker_cannot_write_diagnostics_snapshot(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    ident = control.enqueue(generation, "admin")
    control.claim(generation, "worker")
    failing_scope(store, generation, parent)
    control.finish(generation, ident, "wrong-worker", "completed")
    assert control.details(generation, ident)[1] == []
    assert control.details(generation, ident)[0]["status"] == "running"


@pytest.mark.parametrize("role", ["ogc_admin", "ogc_viewer"])
def test_ui_flags_coverage_and_exposes_safe_scan_diagnostics(
    settings, service, parent, child, monkeypatch, role
):
    generation = install(service.store, parent)
    control = ScanControl(service.store)
    ident = control.enqueue(generation, "admin")
    control.claim(generation, "worker")
    failing_scope(service.store, generation, parent)
    service.store.publish(
        generation,
        Batch(scope=Scope(tenancy=child.ocid, dataset="users", region=child.home_region)),
    )
    control.finish(generation, ident, "worker", "partial", "One scope incomplete")
    client = browser(settings, service)
    logged_in(client, service.store, [role])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="synthetic-human", groups=frozenset({role}))),
    )
    page = client.get("/scans/" + ident)
    assert page.status_code == 200
    assert "1 incomplete collection scopes" in page.text
    assert "Missing group read access" in page.text
    assert "identity_domains.groups" in page.text
    assert "OGC-ACCESS-002" in page.text
    assert "Attempted during this scan" in page.text
    assert f"/scans/{ident}" in client.get("/scans").text
    coverage = client.get("/data/coverage?status=failed")
    assert "Incomplete coverage" in coverage.text
    assert child.ocid not in coverage.text
    findings = client.get("/data/findings?source=coverage&status=open")
    assert "Scanner coverage gap" in findings.text
    assert "Missing group read access" in findings.text
    assert parent.private_key.get_secret_value() not in page.text
    assert client.get("/scans/missing-id").status_code == 404
    client.cookies.clear()
    assert client.get("/scans/" + ident).status_code == 401


def test_historical_scan_without_snapshot_does_not_present_current_data_as_history(
    settings, service, parent
):
    generation = install(service.store, parent)
    control = ScanControl(service.store)
    ident = control.enqueue(generation, "admin")
    with service.store.db() as db:
        db.execute("UPDATE scan_jobs SET status='interrupted' WHERE id=?", (ident,))
    failing_scope(service.store, generation, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    page = client.get("/scans/" + ident)
    assert "No scope snapshot was recorded" in page.text
    assert "Missing group read access" not in page.text
