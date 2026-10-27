"""Administrator triage: ignore or mark findings closed, across rescans and in every reader."""

import json
from unittest.mock import AsyncMock

import pytest

from oci_governance_center.analyzers.identity import finding
from oci_governance_center.models import Identity, Scope
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def signed_in(settings, service, parent, monkeypatch, role):
    """A session for the organization already installed by the fixture (no reinstall)."""
    client = browser(settings, service)
    logged_in(client, service.store, [role], generation=service.store.state()[0])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="synthetic-human", groups=frozenset({role}))),
    )
    return client


@pytest.fixture
def evaluated(service, parent):
    """Persist one open finding in a complete scope; returns a rescan helper and its ID."""
    generation = install(service.store, parent)
    tenancy = parent.domain.tenancy_ocid
    scope = Scope(tenancy=tenancy, dataset="analysis.policy", region="us-ashburn-1")
    item = finding(tenancy, scope.key, "POL-ANY-001", "k", "HIGH", "Grant to any-user", "policy")

    def rescan(present=True):
        service.persist_findings(generation, scope, [item] if present else [], None)

    rescan()
    return generation, item.id, rescan


def status(store, ident):
    return next(json.loads(r["data"]) for r in store.rows("findings") if r["id"] == ident)


def test_ignored_finding_stays_ignored_across_rescans(service, evaluated):
    generation, ident, rescan = evaluated
    assert service.store.triage(generation, ident, "ignored", "admin", "Accepted risk")
    rescan()
    current = status(service.store, ident)
    assert current["status"] == "ignored" and current["triage"]["reason"] == "Accepted risk"
    rescan(present=False)
    assert status(service.store, ident)["status"] == "resolved"  # fixed in OCI
    rescan()
    assert status(service.store, ident)["status"] == "ignored"  # reappears still ignored


def test_closed_finding_reopens_only_when_detected_again(service, evaluated):
    generation, ident, rescan = evaluated
    service.store.triage(generation, ident, "closed", "admin")
    assert status(service.store, ident)["status"] == "closed"
    rescan(present=False)
    assert status(service.store, ident)["status"] == "resolved"
    service.store.triage(generation, ident, "closed", "admin")
    rescan()
    assert status(service.store, ident)["status"] == "open"


def test_reopen_removes_triage_and_unknown_finding_is_rejected(service, evaluated):
    generation, ident, _ = evaluated
    service.store.triage(generation, ident, "ignored", "admin")
    service.store.triage(generation, ident, None, "admin")
    assert status(service.store, ident)["status"] == "open"
    assert not service.store.triage(generation, "missing", "ignored", "admin")
    actions = [row["action"] for row in service.store.rows("control_events")]
    assert {"finding_ignored", "finding_reopened"} <= set(actions)


def test_replacement_clears_triage(service, parent, evaluated):
    generation, ident, _ = evaluated
    service.store.triage(generation, ident, "ignored", "admin")
    install(service.store, parent)
    assert service.store.triage_decisions() == {}


def test_admin_triage_route_and_views(settings, service, parent, evaluated, monkeypatch):
    _, ident, _ = evaluated
    client = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    page = client.get("/identity?view=analysis").text
    assert "Mark closed" in page and "<script" not in page
    response = client.post(
        f"/findings/{ident}/triage",
        data={
            "csrf": "synthetic-csrf",
            "action": "ignore",
            "reason": "Owned by partner",
            "next": "/identity?view=analysis",
        },
    )
    assert response.status_code == 303 and response.headers["location"] == "/identity?view=analysis"
    assert "Grant to any-user" not in client.get("/identity?view=analysis").text  # open by default
    ignored = client.get("/identity?view=analysis&status=ignored").text
    assert "Owned by partner" in ignored and "Reopen" in ignored
    assert "Grant to any-user" not in client.get("/data/findings").text
    assert "Grant to any-user" in client.get("/data/findings?status=").text
    exported = client.get("/exports/findings.json").json()
    assert next(r for r in exported if r["id"] == ident)["data"].count('"ignored"')


@pytest.mark.parametrize("target", ["//evil.example/x", "https://evil.example/", "/\\evil", "x"])
def test_triage_redirect_stays_on_site(settings, service, parent, evaluated, monkeypatch, target):
    _, ident, _ = evaluated
    client = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    response = client.post(
        f"/findings/{ident}/triage",
        data={"csrf": "synthetic-csrf", "action": "close", "next": target},
    )
    assert response.headers["location"] == "/data/findings"


def test_triage_requires_admin_csrf_known_finding_and_action(
    settings, service, parent, evaluated, monkeypatch
):
    _, ident, _ = evaluated
    admin = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    assert admin.post(f"/findings/{ident}/triage", data={"action": "ignore"}).status_code == 403
    form = {"csrf": "synthetic-csrf", "action": "ignore"}
    assert admin.post("/findings/missing/triage", data=form).status_code == 404
    bad = {"csrf": "synthetic-csrf", "action": "delete"}
    assert admin.post(f"/findings/{ident}/triage", data=bad).status_code == 400
    long = {**form, "reason": "x" * 501}
    assert admin.post(f"/findings/{ident}/triage", data=long).status_code == 400
    viewer = signed_in(settings, service, parent, monkeypatch, "ogc_viewer")
    assert viewer.post(f"/findings/{ident}/triage", data=form).status_code == 403
    assert "Mark closed" not in viewer.get("/identity?view=analysis").text
