"""Scheduler loop and the `osc scan` command (no live OCI)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_collectors import FakeWorld, Tenant, _problem
from typer.testing import CliRunner

from oci_security_center import cli
from oci_security_center.collection.scheduler import Job, Scheduler, build_jobs
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import OnboardingStatus, OrgRole, Tenancy
from oci_security_center.runtime import Runtime, build_runtime

P = "ocid1.tenancy.oc1..aaaafakeparent"


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    settings = Settings(data_root=tmp_path, deployment=DeploymentMode.WORKSTATION)
    runtime = build_runtime(settings)
    s = runtime.stores
    s.state.set_setting("parent_tenancy_ocid", P)
    s.state.set_organization_parent(P, 1)
    s.state.upsert_tenancy(
        Tenancy(
            ocid=P,
            name="Parent",
            alias="osc_parent",
            org_role=OrgRole.PARENT,
            onboarding_status=OnboardingStatus.ACTIVE,
            home_region="us-ashburn-1",
        )
    )
    return runtime


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_jobs_run_when_due_and_failures_are_isolated(rt: Runtime) -> None:
    ran: list[str] = []

    def boom() -> None:
        ran.append("boom")
        raise RuntimeError("source down")

    clock = Clock()
    jobs = [Job("a", 60, lambda: ran.append("a")), Job("bad", 30, boom)]
    sched = Scheduler(rt, jobs, clock)
    assert sched.tick() == ["a", "bad"]  # both due at start; the failure doesn't stop "a"
    assert jobs[1].failures == 1
    clock.t = 31
    assert sched.tick() == ["bad"]
    clock.t = 61
    assert sched.tick() == ["a", "bad"]
    assert ran.count("a") == 2


def test_nothing_runs_in_maintenance(rt: Runtime) -> None:
    ran: list[str] = []
    sched = Scheduler(rt, [Job("a", 60, lambda: ran.append("a"))], Clock())
    token = rt.stores.state.begin_maintenance("switch")
    assert sched.tick() == []
    rt.stores.state.end_maintenance(token)
    assert sched.tick() == ["a"]


def test_build_jobs_follows_settings(rt: Runtime) -> None:
    jobs = {j.name: j.interval_s for j in build_jobs(rt)}
    assert jobs == {
        "identity": 360 * 60,
        "governance": 60 * 60,
        "audit": 15 * 60,
        "reconcile": 86_400,
        "retention": 86_400,
    }


def test_cli_scan_reports_outcomes(rt: Runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    world = FakeWorld({P: Tenant(P, problems=[_problem("pr1")])})
    monkeypatch.setattr(cli, "_rt", lambda: rt)
    monkeypatch.setattr(Runtime, "scan_clients", lambda self: world)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "--only",
            "identity.region_subscriptions,cloud_guard.configuration,cloud_guard.problems",
            "--no-audit",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ok" in result.output
    assert "cloud_guard.problems" in result.output
    findings: list[Any] = rt.stores.data.list_findings(rule_id="CG-PROBLEM")
    assert len(findings) == 1
