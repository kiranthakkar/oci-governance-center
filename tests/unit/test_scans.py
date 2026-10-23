"""Calendar, durable queue, worker execution and scan administration regression tests."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from oci_governance_center.models import Identity, now
from oci_governance_center.scans import ScanControl, ScanSchedule
from oci_governance_center.scheduler import ScanWorker
from oci_governance_center.storage import StaleWork
from tests.conftest import install
from tests.unit.test_web import browser, logged_in


def instant(value):
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


@pytest.mark.parametrize(
    "values",
    [
        {"frequency": "hourly", "time_of_day": "09:00"},
        {"frequency": "daily", "time_of_day": "25:00"},
        {"frequency": "weekly", "time_of_day": "09:00"},
        {"frequency": "weekly", "time_of_day": "09:00", "weekday": 7},
        {"frequency": "daily", "time_of_day": "09:00", "timezone": "Invalid/Zone"},
    ],
)
def test_schedule_rejects_invalid_values(values):
    with pytest.raises(ValidationError):
        ScanSchedule(**values)


@pytest.mark.parametrize(
    "schedule,start,expected",
    [
        (
            {"frequency": "daily", "time_of_day": "09:00"},
            "2026-10-22T09:00:00",
            "2026-10-23T09:00:00",
        ),
        (
            {"frequency": "weekly", "time_of_day": "09:00", "weekday": 0},
            "2026-10-22T10:00:00",
            "2026-10-26T09:00:00",
        ),
        (
            {"frequency": "daily", "time_of_day": "02:30", "timezone": "America/New_York"},
            "2026-03-08T06:00:00",
            "2026-03-08T07:00:00",
        ),
        (
            {"frequency": "daily", "time_of_day": "01:30", "timezone": "America/New_York"},
            "2026-11-01T05:40:00",
            "2026-11-02T06:30:00",
        ),
    ],
)
def test_calendar_boundaries_and_dst(schedule, start, expected):
    assert ScanSchedule(**schedule).next_after(instant(start)) == instant(expected)


def test_queue_coalesces_and_claims_one_worker(store, parent):
    generation = install(store, parent)
    first, second = ScanControl(store), ScanControl(store)
    ident = first.enqueue(generation, "admin")
    assert second.enqueue(generation, "admin") == ident
    assert first.claim(generation, "worker-a")["id"] == ident
    assert second.claim(generation, "worker-b") is None
    assert second.enqueue(generation, "admin") == ident
    followup = second.enqueue(generation, "system", followup=True)
    assert followup != ident
    assert first.enqueue(generation, "system", followup=True) == followup
    second.finish(generation, ident, "worker-b", "completed")
    assert next(j for j in first.jobs(generation) if j["id"] == ident)["status"] == "running"
    first.finish(generation, ident, "worker-a", "completed")
    assert second.claim(generation, "worker-b")["id"] == followup


def test_missed_schedules_catch_up_once_and_disable_preserves_jobs(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    control.save(
        generation,
        ScanSchedule(frequency="daily", time_of_day="09:00"),
        instant("2026-10-01T00:00:00"),
    )
    caught_up = instant("2026-10-22T10:00:00")
    ident = control.enqueue_due(generation, caught_up)
    assert ident and control.enqueue_due(generation, caught_up) is None
    assert datetime.fromisoformat(control.schedule(generation)["next_run"]) == instant(
        "2026-10-23T09:00:00"
    )
    control.disable(generation)
    assert control.schedule(generation) is None
    assert control.jobs(generation)[0]["id"] == ident


def test_expired_job_is_interrupted_before_next_claim(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    ident = control.enqueue(generation, "admin")
    control.claim(generation, "dead-worker", now() - timedelta(minutes=3))
    followup = control.enqueue(generation, "admin", followup=True)
    assert control.claim(generation, "new-worker")["id"] == followup
    assert next(j for j in control.jobs(generation) if j["id"] == ident)["status"] == "interrupted"


def test_replacement_clears_schedule_jobs_and_fences_old_requests(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    control.save(generation, ScanSchedule(frequency="daily", time_of_day="09:00"))
    control.enqueue(generation, "admin")
    replacement = install(store, parent)
    assert control.schedule(replacement) is None and control.jobs(replacement) == []
    with pytest.raises(StaleWork):
        control.enqueue(generation, "old-admin")


@pytest.mark.parametrize("fails,expected", [(False, "completed"), (True, "failed")])
def test_worker_runs_all_and_audit_and_records_failure(
    service, parent, monkeypatch, fails, expected
):
    generation = install(service.store, parent)
    worker = ScanWorker(service)
    worker.control.enqueue(generation, "admin")
    calls = []

    def scan(family, expected_generation=None):
        assert expected_generation == generation
        calls.append(family)
        if fails:
            raise RuntimeError("synthetic failure")

    monkeypatch.setattr(service, "scan", scan)
    assert worker.run_once()
    assert calls == (["all"] if fails else ["all", "audit"])
    assert worker.control.jobs(generation)[0]["status"] == expected
    assert worker.control.online()


def signed_in(settings, service, parent, monkeypatch, role):
    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, [role])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="synthetic-human", groups=frozenset({role}))),
    )
    return client


def test_admin_scan_and_weekly_schedule_survive_reload(settings, service, parent, monkeypatch):
    client = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    page = client.get("/scans")
    assert page.status_code == 200 and "Scanner offline" in page.text
    assert client.post("/scans/start", data={}).status_code == 403
    assert client.post("/scans/start", data={"csrf": "synthetic-csrf"}).status_code == 303
    assert (
        client.post(
            "/scans/schedule",
            data={
                "csrf": "synthetic-csrf",
                "frequency": "weekly",
                "time_of_day": "14:35",
                "weekday": "3",
                "timezone": "America/Los_Angeles",
            },
        ).status_code
        == 303
    )
    page = client.get("/scans")
    assert "Thursday" in page.text and "14:35" in page.text and "Next run:" in page.text
    schedule = ScanControl(service.store).schedule(1)
    response = client.post(
        "/scans/schedule",
        data={
            "csrf": "synthetic-csrf",
            "frequency": "hourly",
            "time_of_day": "14:35",
            "timezone": "UTC",
        },
    )
    assert response.status_code == 400
    assert ScanControl(service.store).schedule(1) == schedule
    assert (
        client.post("/scans/schedule/disable", data={"csrf": "synthetic-csrf"}).status_code == 303
    )
    assert ScanControl(service.store).schedule(1) is None


def test_viewer_can_read_but_cannot_start_or_schedule(settings, service, parent, monkeypatch):
    client = signed_in(settings, service, parent, monkeypatch, "ogc_viewer")
    response = client.get("/scans")
    assert response.status_code == 200 and "Configure schedule" not in response.text
    for endpoint in ("/scans/start", "/scans/schedule", "/scans/schedule/disable"):
        assert client.post(endpoint, data={"csrf": "synthetic-csrf"}).status_code == 403


def test_daily_form_ignores_weekday(settings, service, parent, monkeypatch):
    client = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    assert (
        client.post(
            "/scans/schedule",
            data={
                "csrf": "synthetic-csrf",
                "frequency": "daily",
                "time_of_day": "08:15",
                "timezone": "Asia/Kolkata",
                "weekday": "not-used",
            },
        ).status_code
        == 303
    )
    saved = ScanControl(service.store).schedule(1)
    schedule = ScanSchedule.model_validate_json(saved["data"])
    assert schedule.weekday is None and schedule.frequency == "daily"
    assert "08:15" in client.get("/scans").text


def test_blocked_credentials_retain_due_schedule_and_reject_manual(store, parent):
    from oci_governance_center.diagnostics import PublicFailure

    generation = install(store, parent)
    control = ScanControl(store)
    control.save(
        generation,
        ScanSchedule(frequency="daily", time_of_day="09:00"),
        instant("2026-01-01T00:00:00"),
    )
    saved = control.schedule(generation)
    with store.db() as db:
        db.execute("UPDATE state SET blocked=1")
    with pytest.raises(PublicFailure):
        control.enqueue(generation, "admin")
    assert control.enqueue_due(generation) is None
    assert control.schedule(generation) == saved


def test_collection_lease_prevents_overlapping_scan(store, parent):
    generation = install(store, parent)
    control = ScanControl(store)
    control.enqueue(generation, "admin")
    assert store.lease(generation, "tenancy", "existing-reader")
    assert control.claim(generation, "worker") is None
    store.release("tenancy", "existing-reader")
    assert control.claim(generation, "worker") is not None


def test_worker_reports_partial_coverage(service, parent, monkeypatch):
    from oci_governance_center.models import Batch, Scope

    generation = install(service.store, parent)
    service.store.publish(
        generation,
        Batch(
            scope=Scope(tenancy=parent.domain.tenancy_ocid, dataset="test", region="us-ashburn-1"),
            complete=False,
            error="Missing access",
        ),
    )
    monkeypatch.setattr(service, "scan", lambda *args, **kwargs: None)
    worker = ScanWorker(service)
    worker.control.enqueue(generation, "admin")
    assert worker.run_once()
    assert worker.control.jobs(generation)[0]["status"] == "partial"


def test_worker_logs_scan_lifecycle(service, parent, monkeypatch, caplog):
    import logging

    generation = install(service.store, parent)
    monkeypatch.setattr(service, "scan", lambda *args, **kwargs: None)
    worker = ScanWorker(service)
    ident = worker.control.enqueue(generation, "admin")
    with caplog.at_level(logging.INFO, logger="oci_governance_center.scheduler"):
        assert worker.run_once()
    assert f"Scan {ident} started (trigger=manual)" in caplog.text
    assert "collecting Audit" in caplog.text
    assert f"Scan {ident} finished (status=completed)" in caplog.text
    assert parent.private_key.get_secret_value() not in caplog.text
