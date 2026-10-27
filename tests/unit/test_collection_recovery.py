"""Audit cadence, coverage recovery, rejoined children, lease renewal and repair errors."""

import json
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest

from oci_governance_center.collectors.inventory import Trace
from oci_governance_center.diagnostics import PublicFailure
from oci_governance_center.models import Batch, ChildCredentials, Identity, Scope, now
from oci_governance_center.service import Cancelled
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def audit_sources(service, monkeypatch):
    """Mock one READY region and record every committed (dataset, start, end) interval."""
    identity = Mock()
    identity.list_compartments = "compartments"
    identity.list_region_subscriptions = "regions"
    monkeypatch.setattr("oci_governance_center.service.client", lambda *_: identity)
    monkeypatch.setattr(
        "oci_governance_center.service.all_items",
        lambda method, *a, **k: (
            [] if method == "compartments" else [NS(region_name="us-ashburn-1", status="READY")]
        ),
    )
    monkeypatch.setattr("oci_governance_center.service.read_interval", lambda *_: [])
    commits = []
    original = service.store.audit_commit

    def record(generation, scope, start, end, *args):
        commits.append((scope.dataset, datetime.fromisoformat(start), datetime.fromisoformat(end)))
        return original(generation, scope, start, end, *args)

    monkeypatch.setattr(service.store, "audit_commit", record)
    return commits


def audit_scope(parent, dataset):
    return Scope(tenancy=parent.domain.tenancy_ocid, dataset=dataset, region="us-ashburn-1")


def coverage_of(store, dataset):
    return next(
        row["status"]
        for row in store.rows("coverage")
        if json.loads(row["scope"])["dataset"] == dataset
    )


def test_daily_scan_catches_forward_audit_up_and_reconciles_previous_day(
    service, parent, monkeypatch
):
    generation = install(service.store, parent)
    previous = now() - timedelta(hours=24)
    service.store.set_checkpoint(
        generation, audit_scope(parent, "audit.events"), previous.isoformat()
    )
    # History already complete, so only the forward and reconciliation cursors run.
    service.store.set_checkpoint(
        generation, audit_scope(parent, "audit.backfill.target"), previous.isoformat()
    )
    service.store.set_checkpoint(
        generation, audit_scope(parent, "audit.backfill"), previous.isoformat()
    )
    commits = audit_sources(service, monkeypatch)
    service.audit(generation, object(), parent.domain, None)
    forward = [c for c in commits if c[0] == "audit.events"]
    assert forward[0][1] == previous - timedelta(minutes=15)
    assert now() - forward[-1][2] < timedelta(minutes=10)
    assert len(forward) > 4  # the former fixed four-hour budget could never catch up daily
    reconcile = [c for c in commits if c[0] == "audit.reconcile"]
    assert reconcile[0][1] == previous - timedelta(hours=24)
    assert reconcile[-1][2] == previous
    assert coverage_of(service.store, "audit.events") == "complete"
    assert coverage_of(service.store, "audit.reconcile") == "complete"
    assert coverage_of(service.store, "audit.backfill") == "complete"


def test_backfill_target_is_fixed_so_history_can_finish(service, parent, monkeypatch):
    generation = install(service.store, parent)
    commits = audit_sources(service, monkeypatch)
    service.audit(generation, object(), parent.domain, None)
    target_scope = audit_scope(parent, "audit.backfill.target")
    target = service.store.checkpoint(target_scope)
    assert target is not None
    assert coverage_of(service.store, "audit.backfill") == "failed"  # 168h of 90 days so far
    assert not any(c[0] == "audit.reconcile" for c in commits)  # nothing earlier to re-read
    service.audit(generation, object(), parent.domain, None)
    assert service.store.checkpoint(target_scope) == target  # later scans never move it
    # Once progress reaches the fixed target, history is complete despite "now" moving on.
    service.store.set_checkpoint(generation, audit_scope(parent, "audit.backfill"), target)
    service.audit(generation, object(), parent.domain, None)
    assert coverage_of(service.store, "audit.backfill") == "complete"


def test_runner_failure_clears_after_next_successful_family(service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: Mock())
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    monkeypatch.setattr(
        "oci_governance_center.service.inventory", Mock(side_effect=RuntimeError("timeout"))
    )
    service.scan_one(generation, parent, child, "identity")
    assert coverage_of(service.store, "identity.runner") == "failed"
    assert service.store.children()[0].status == "partial"
    monkeypatch.setattr("oci_governance_center.service.inventory", lambda *_: iter([]))
    service.scan_one(generation, parent, child, "identity")
    assert coverage_of(service.store, "identity.runner") == "complete"
    assert service.store.children()[0].status == "active"
    findings = [json.loads(row["data"]) for row in service.store.rows("findings")]
    assert all(f["status"] == "resolved" for f in findings if f["source"] == "coverage")


def test_successful_scan_without_prior_failure_records_no_runner_scope(
    service, parent, child, monkeypatch
):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: Mock())
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    monkeypatch.setattr("oci_governance_center.service.inventory", lambda *_: iter([]))
    service.scan_one(generation, parent, child, "identity")
    datasets = {json.loads(row["scope"])["dataset"] for row in service.store.rows("coverage")}
    assert "identity.runner" not in datasets


def test_departure_drops_credentials_and_rejoined_child_needs_configuration(
    service, parent, child, monkeypatch
):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    with service.store.db() as db:
        db.execute(
            "INSERT INTO child_credentials VALUES(?,?)",
            (
                child.ocid,
                service.store.encrypt({"client_id": "c", "client_secret": "synthetic-secret"}),
            ),
        )
    assert isinstance(service.store.child_credentials(generation, child.ocid), ChildCredentials)
    monkeypatch.setattr("oci_governance_center.service.discover", lambda *_: [])
    service.discover()
    departed = service.store.children()[0]
    assert departed.status == "departed"
    assert service.store.child_credentials(generation, child.ocid) is None
    monkeypatch.setattr(
        "oci_governance_center.service.discover",
        lambda *_: [child.model_copy(update={"status": "not_configured", "revision": 0})],
    )
    service.discover()
    rejoined = service.store.children()[0]
    assert rejoined.status == "not_configured"
    assert rejoined.revision == departed.revision + 1
    service.discover()  # an unchanged member is not reset again
    assert service.store.children()[0] == rejoined


def test_lease_renewal_only_extends_the_owners_live_lease(store, parent):
    generation = install(store, parent)
    assert store.lease(generation, "scope", "owner", seconds=1)
    assert store.renew("scope", "owner", 600)
    assert not store.renew("scope", "intruder", 600)
    with store.db() as db:
        db.execute("UPDATE leases SET expires=?", ((now() - timedelta(seconds=1)).isoformat(),))
    assert not store.renew("scope", "owner", 600)


def test_long_collection_keeps_renewing_its_lease(service, monkeypatch):
    monkeypatch.setattr("oci_governance_center.service.LEASE_RENEW_SECONDS", 0.01)
    renewed = threading.Event()

    def renew(*_):
        renewed.set()
        return True

    monkeypatch.setattr(service.store, "renew", renew)
    with service.kept_lease("scope", "owner"):
        assert renewed.wait(2)


def admin_client(settings, service, parent, monkeypatch):
    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_admin"}))),
    )
    return client


def test_key_repair_reports_missing_upload_and_verification_failure_safely(
    settings, service, parent, key, monkeypatch
):
    client = admin_client(settings, service, parent, monkeypatch)
    form = {"csrf": "synthetic-csrf", "fingerprint": parent.fingerprint, "user_ocid": "x"}
    missing = client.post("/configuration/key", data=form)
    assert missing.status_code == 400 and "Upload the replacement" in missing.text
    monkeypatch.setattr(
        service, "repair", Mock(side_effect=PublicFailure("Verification failed at GetUser."))
    )
    failed = client.post(
        "/configuration/key", data=form, files={"private_key": ("key.pem", key.encode())}
    )
    assert failed.status_code == 400 and "Verification failed at GetUser." in failed.text
    assert key not in failed.text


def test_child_resume_verification_failure_is_a_safe_400(
    settings, service, parent, child, monkeypatch
):
    client = admin_client(settings, service, parent, monkeypatch)
    service.store.save_child(1, child.model_copy(update={"status": "paused"}))
    monkeypatch.setattr(
        service, "configure_child", Mock(side_effect=PublicFailure("Trust was removed."))
    )
    response = client.post(f"/children/{child.ocid}/resume", data={"csrf": "synthetic-csrf"})
    assert response.status_code == 400 and "Trust was removed." in response.text


def test_audit_stops_between_hours_and_keeps_committed_progress(service, parent, monkeypatch):
    generation = install(service.store, parent)
    commits = audit_sources(service, monkeypatch)
    reads = []

    def read(*_):
        reads.append(1)
        if len(reads) == 3:
            service.stopping.set()
        return []

    monkeypatch.setattr("oci_governance_center.service.read_interval", read)
    with pytest.raises(Cancelled):  # scan_one catches it and logs the stopped phase
        service.audit(generation, object(), parent.domain, None)
    # The stop is honored before the fourth hour; the three read hours stay committed.
    assert len(reads) == 3 and len(commits) == 3
    assert not service.store.has_coverage(audit_scope(parent, "audit.backfill"))


def test_long_audit_ranges_report_progress(service, parent, monkeypatch, caplog):
    generation = install(service.store, parent)
    audit_sources(service, monkeypatch)
    caplog.set_level("INFO")
    trace = Trace("ktdemos")
    trace.current = "Audit"
    start = datetime(2026, 1, 1, tzinfo=now().tzinfo)
    reached = service.audit_range(
        generation,
        object(),
        parent.domain,
        [],
        audit_scope(parent, "audit.backfill"),
        start,
        start + timedelta(days=5),
        48,
        None,
        None,
        trace,
    )
    assert reached == start + timedelta(hours=48)
    progress = [r.getMessage() for r in caplog.records if "collected through" in r.getMessage()]
    assert progress == [
        "tenancy: ktdemos Audit scan: audit.backfill us-ashburn-1 collected through "
        "2026-01-02 00:00 UTC (24 of 48 hours this scan)",
        "tenancy: ktdemos Audit scan: audit.backfill us-ashburn-1 collected through "
        "2026-01-03 00:00 UTC (48 of 48 hours this scan)",
    ]


def test_stopped_collection_is_not_reported_as_a_failure(service, parent, monkeypatch):
    generation = install(service.store, parent)
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    monkeypatch.setattr("oci_governance_center.service.api_signer", lambda *_: object())
    monkeypatch.setattr("oci_governance_center.service.bind_identity", lambda *_: None)
    scope = Scope(tenancy=parent.domain.tenancy_ocid, dataset="identity.regions", region="r")

    def batches(*_):
        service.stopping.set()
        yield Batch(scope=scope)
        raise AssertionError("collection continued after the stop request")

    monkeypatch.setattr("oci_governance_center.service.inventory", batches)
    service.scan_one(generation, parent, None, "all")
    statuses = {
        json.loads(r["scope"])["dataset"]: r["status"] for r in service.store.rows("coverage")
    }
    assert "all.runner" not in statuses and statuses["identity.regions"] == "complete"
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 0  # lock released


def test_stop_still_runs_analysis_so_findings_match_inventory(service, parent, monkeypatch):
    generation = install(service.store, parent)
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    monkeypatch.setattr("oci_governance_center.service.api_signer", lambda *_: object())
    monkeypatch.setattr("oci_governance_center.service.bind_identity", lambda *_: None)
    tenancy = parent.domain.tenancy_ocid

    def batches(*_):
        yield Batch(scope=Scope(tenancy=tenancy, dataset="identity.compartments", region="r"))
        service.stopping.set()
        yield Batch(scope=Scope(tenancy=tenancy, dataset="identity.domains", region="r"))
        raise AssertionError("collection continued after the stop request")

    monkeypatch.setattr("oci_governance_center.service.inventory", batches)
    service.scan_one(generation, parent, None, "all")
    statuses = {
        json.loads(r["scope"])["dataset"]: (r["status"], r["error"])
        for r in service.store.rows("coverage")
    }
    # Policies were never read, so policy analysis fails closed instead of keeping old findings.
    assert statuses["analysis.policy"][0] == "failed"
    assert "identity.policies" in statuses["analysis.policy"][1]
    assert service.cancelled.is_set()


def test_audit_interval_stops_between_compartments(domain, monkeypatch):
    from oci_governance_center.collectors import audit as module

    read = []
    monkeypatch.setattr(module, "client", lambda *_: NS(list_events="events"))
    monkeypatch.setattr(module, "all_items", lambda *a: read.append(a[1]) or [])

    def check_stop():
        if len(read) == 2:  # stop requested while compartment "b" was being read
            raise Cancelled("stop")

    start = datetime(2026, 1, 1, tzinfo=now().tzinfo)
    with pytest.raises(Cancelled):
        module.read_interval(
            object(),
            domain,
            "r",
            ["a", "b", "c", "d"],
            start,
            start + timedelta(hours=1),
            check_stop,
        )
    assert read == ["a", "b"]
