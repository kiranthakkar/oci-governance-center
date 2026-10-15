"""Coordinated organization switch (docs/control-plane.md §6.1): journal, drain, recovery."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeClients, FakeOrganizations, FakeTenancyData
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane.service import Actor, ControlPlane, ControlPlaneError
from oci_security_center.models import (
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    Envelope,
)
from oci_security_center.storage.errors import MaintenanceError, StaleGenerationError
from oci_security_center.storage.sqlite import open_stores
from oci_security_center.storage.sqlite import reset as reset_mod
from oci_security_center.storage.sqlite.reset import recover_interrupted_switch

OLD = "ocid1.tenancy.oc1..aaaafakeoldparent"
OLD_CHILD = "ocid1.tenancy.oc1..aaaafakeoldchild"
NEW = "ocid1.tenancy.oc1..aaaafakenewparent"
ACTOR = Actor("tester", "admin")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_root=tmp_path, deployment=DeploymentMode.WORKSTATION, switch_drain_seconds=0.3
    )


@pytest.fixture
def world() -> dict[str, FakeTenancyData]:
    return {
        OLD: FakeTenancyData(OLD, "Old"),
        OLD_CHILD: FakeTenancyData(OLD_CHILD, "Old Child"),
        NEW: FakeTenancyData(NEW, "New"),
    }


def _cp(settings: Settings) -> ControlPlane:
    return ControlPlane(settings, open_stores(settings))


def _clients(world: dict[str, FakeTenancyData], parent: str) -> FakeClients:
    children = [(OLD_CHILD, "Old Child")] if parent == OLD else []
    return FakeClients(world, FakeOrganizations(parent, children))


def _old_org(cp: ControlPlane, world: dict[str, FakeTenancyData]) -> int:
    cp.connect_parent(_clients(world, OLD), OLD, None, ACTOR)
    cp.discover_children(_clients(world, OLD), ACTOR)
    gen = cp.state.current_generation()
    event = Envelope(
        schema_id="audit.events.v1",
        tenancy_ocid=OLD_CHILD,
        record_key="e1",
        data={"event_time": "2026-10-01T00:00:00+00:00", "event_type": "x"},
        run_id="r1",
    )
    cp.stores.data.append_events(gen, OLD_CHILD, [event], "r1")
    return gen


def _journal(cp: ControlPlane) -> list[dict[str, Any]]:
    with cp.stores.db.read() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM switch_journal ORDER BY id")]


def _expire_maintenance(cp: ControlPlane) -> None:
    with cp.stores.db.write() as conn:
        conn.execute(
            "UPDATE organization_state SET maintenance_expires_at='2000-01-01T00:00:00+00:00'"
        )


def test_switch_journal_runs_to_cleaned(
    settings: Settings, world: dict[str, FakeTenancyData]
) -> None:
    cp = _cp(settings)
    old_gen = _old_org(cp, world)
    cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    [entry] = _journal(cp)
    assert (entry["phase"], entry["old_generation"], entry["new_generation"]) == (
        "cleaned",
        old_gen,
        old_gen + 1,
    )
    assert (entry["old_parent"], entry["new_parent"]) == (OLD, NEW)
    org = cp.state.organization()
    assert (org.state, org.generation, org.parent_tenancy_ocid) == ("active", old_gen + 1, NEW)
    audit = settings.audit_root
    assert sorted(p.name for p in audit.iterdir()) == [".quarantine"]
    assert list((audit / ".quarantine").iterdir()) == []


def test_drain_timeout_aborts_without_changes(
    settings: Settings, world: dict[str, FakeTenancyData]
) -> None:
    cp = _cp(settings)
    gen = _old_org(cp, world)
    token = cp.state.acquire_lease("in-flight-scope", gen, "collector", 60)
    assert token is not None

    started = time.monotonic()
    with pytest.raises(ControlPlaneError, match="nothing was changed"):
        cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    assert time.monotonic() - started >= 0.3
    org = cp.state.organization()
    assert (org.state, org.generation, org.parent_tenancy_ocid) == ("active", gen, OLD)
    assert _journal(cp) == []  # draining happens before anything is journaled
    assert cp.state.get_tenancy(OLD_CHILD) is not None


def test_crash_after_prepare_rolls_back(
    settings: Settings, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _cp(settings)
    gen = _old_org(cp, world)
    # Simulate the holder dying right after journaling 'prepared': maintenance stays held.
    token = cp.state.begin_maintenance("crashed")
    with cp.stores.db.write() as conn:
        conn.execute(
            "INSERT INTO switch_journal (old_generation, new_generation, old_parent, new_parent, "
            "phase, holder, started_at, updated_at) VALUES (?, ?, ?, ?, 'prepared', 'crashed', "
            "'2026-10-09T00:00:00+00:00', '2026-10-09T00:00:00+00:00')",
            (gen, gen + 1, OLD, NEW),
        )
    assert recover_interrupted_switch(cp.stores.db, cp.state, cp.stores.data) is None  # live
    _expire_maintenance(cp)

    cp2 = _cp(settings)  # a new process starts: recovery runs in open_stores
    org = cp2.state.organization()
    assert (org.state, org.generation, org.parent_tenancy_ocid) == ("active", gen, OLD)
    assert _journal(cp2)[-1]["phase"] == "aborted"
    assert cp2.state.get_tenancy(OLD_CHILD) is not None
    del token


def test_crash_after_commit_is_completed_on_restart(
    settings: Settings, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _cp(settings)
    old_gen = _old_org(cp, world)

    def die(*_: object, **__: object) -> None:
        raise KeyboardInterrupt("process killed")

    monkeypatch.setattr(reset_mod, "_finish", die)
    with pytest.raises(KeyboardInterrupt):
        cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    org = cp.state.organization()
    assert (org.state, org.generation) == ("maintenance", old_gen + 1)  # committed, not active
    assert _journal(cp)[-1]["phase"] == "committed"
    # stale workers are fenced during and after the interrupted switch
    with pytest.raises((StaleGenerationError, MaintenanceError)):
        cp.stores.data.set_watermark(old_gen, OLD_CHILD, "audit.events", "x", "r")

    monkeypatch.undo()
    _expire_maintenance(cp)
    cp2 = _cp(settings)
    org = cp2.state.organization()
    assert (org.state, org.generation, org.parent_tenancy_ocid) == ("active", old_gen + 1, NEW)
    assert _journal(cp2)[-1]["phase"] == "cleaned"
    assert not (settings.audit_root / f"g{old_gen}").exists()


def test_quarantine_failure_keeps_maintenance_until_recovered(
    settings: Settings, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _cp(settings)
    old_gen = _old_org(cp, world)
    original = Path.rename

    def refuse(self: Path, target: Any) -> Any:
        if self.name == f"g{old_gen}":
            raise PermissionError("nope")
        return original(self, target)

    monkeypatch.setattr(Path, "rename", refuse)
    with pytest.raises(ControlPlaneError, match="stays in maintenance"):
        cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    assert cp.state.organization().state == "maintenance"
    entry = _journal(cp)[-1]
    assert entry["phase"] == "committed"
    assert "could not quarantine" in json.loads(entry["errors"])[0]
    assert (settings.audit_root / f"g{old_gen}").exists()  # never visible: OSC is in maintenance

    monkeypatch.undo()
    _expire_maintenance(cp)
    cp2 = _cp(settings)
    assert cp2.state.organization().state == "active"
    assert not (settings.audit_root / f"g{old_gen}").exists()


def test_cleanup_failure_is_retried_on_startup(
    settings: Settings, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> None:
    cp = _cp(settings)
    _old_org(cp, world)

    def refuse(*_: object, **__: object) -> None:
        raise PermissionError("nope")

    monkeypatch.setattr(reset_mod.shutil, "rmtree", refuse)
    cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    assert cp.state.organization().state == "active"  # cleanup never blocks the new org
    assert _journal(cp)[-1]["phase"] == "active"
    assert any("could not delete" in w for w in cp.replace_warnings)

    monkeypatch.undo()
    cp2 = _cp(settings)
    assert _journal(cp2)[-1]["phase"] == "cleaned"
    assert list((settings.audit_root / ".quarantine").iterdir()) == []


def test_requests_started_before_the_switch_cannot_write(
    settings: Settings, world: dict[str, FakeTenancyData]
) -> None:
    cp = _cp(settings)
    old_gen = _old_org(cp, world)
    cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR)
    with pytest.raises(StaleGenerationError):
        cp.state.set_setting("verify:x", "{}", old_gen)
    tenancy = cp.state.get_tenancy(NEW)
    assert tenancy is not None
    with pytest.raises(StaleGenerationError):
        cp.state.upsert_tenancy(tenancy, old_gen)


def test_scan_identity_change_fences_work_and_requires_reverification(
    settings: Settings, world: dict[str, FakeTenancyData]
) -> None:
    cp = _cp(settings)
    gen = _old_org(cp, world)

    def scan(profile: str) -> Connection:
        return Connection(
            id="",
            tenancy_ocid=OLD,
            method=ConnectionMethod.CLI_PROFILE,
            purpose=ConnectionPurpose.SCAN,
            cli_profile=profile,
        )

    cp.save_connection(scan("A"), ACTOR)
    cp.state.record_capability(gen, OLD, "identity.users", "{}", "supported")
    assert cp.state.acquire_lease("scope", gen, "collector", 60) is not None
    cp.save_connection(scan("A"), ACTOR)  # same principal: nothing fenced
    assert cp.state.active_leases() == 1

    cp.save_connection(scan("B"), ACTOR)
    assert cp.state.active_leases() == 0
    [cap] = cp.state.capabilities(gen)
    assert cap["status"] == "untested"


def test_web_refuses_posts_during_maintenance_and_stale_sessions(tmp_path: Path) -> None:
    import re

    from fastapi.testclient import TestClient

    from oci_security_center.runtime import build_runtime
    from oci_security_center.web.app import create_app

    s = Settings(
        data_root=tmp_path,
        secret_key="Kq5vQ9W0m5mX3p2b6f1oQh2wD8yS7cJ0rT4uV6xZ9aE=",
        public_base_url="http://testserver",
    )  # type: ignore[arg-type]
    rt = build_runtime(s)
    world = {OLD: FakeTenancyData(OLD, "Old")}
    rt.control_plane.connect_parent(_clients(world, OLD), OLD, None, ACTOR)
    client = TestClient(create_app(s, rt), base_url="http://testserver")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text)
    assert csrf
    client.post("/login/local", data={"csrf_token": csrf.group(1)})
    assert client.get("/admin/organization").status_code == 200

    token = rt.stores.state.begin_maintenance("switch")
    assert client.get("/admin/organization").status_code == 200  # reads continue
    r = client.post("/admin/settings/admin-browse", data={"csrf_token": "x", "enabled": "true"})
    assert r.status_code == 503
    rt.stores.state.end_maintenance(token, advance_generation=True)

    # the session belongs to the old generation: it's gone
    r = client.get("/admin/organization", follow_redirects=False)
    assert (r.status_code, r.headers["location"]) == (303, "/login")


def _candidate() -> Connection:
    return Connection(
        id="candidate-scan",
        tenancy_ocid=NEW,
        method=ConnectionMethod.CLI_PROFILE,
        purpose=ConnectionPurpose.SCAN,
        cli_profile="synthetic",
    )


def test_candidate_install_failure_rolls_back_old_organization(
    settings: Settings,
    world: dict[str, FakeTenancyData],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cp = _cp(settings)
    gen = _old_org(cp, world)

    def fail(*args: object) -> None:
        raise RuntimeError("candidate storage failure")

    monkeypatch.setattr(cp.state, "save_connection_in", fail)
    with pytest.raises(RuntimeError, match="candidate storage failure"):
        cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR, (_candidate(),))
    assert cp.state.organization().generation == gen
    assert cp.require_parent().ocid == OLD
    assert cp.state.get_tenancy(NEW) is None
    assert cp.stores.data.query_audit(gen, OLD_CHILD, "2026-10")
    assert _journal(cp)[-1]["phase"] == "aborted"


def test_committed_switch_recovers_with_candidate_connections(
    settings: Settings,
    world: dict[str, FakeTenancyData],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cp = _cp(settings)
    _old_org(cp, world)

    def crash(*args: object) -> None:
        raise RuntimeError("stopped after commit")

    monkeypatch.setattr(reset_mod, "_finish", crash)
    with pytest.raises(RuntimeError, match="stopped after commit"):
        cp.connect_parent(_clients(world, NEW), NEW, None, ACTOR, (_candidate(),))
    assert cp.state.organization().state == "maintenance"
    assert cp.state.get_tenancy(NEW) is not None
    assert cp.state.get_connection(NEW, ConnectionPurpose.SCAN).cli_profile == "synthetic"
    monkeypatch.undo()
    _expire_maintenance(cp)
    recover_interrupted_switch(cp.stores.db, cp.state, cp.stores.data)
    assert cp.require_parent().ocid == NEW
    assert cp.state.organization().state == "active"
    assert _journal(cp)[-1]["phase"] == "cleaned"
