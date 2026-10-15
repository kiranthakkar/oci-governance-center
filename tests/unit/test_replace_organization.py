"""One organization per deployment: bootstrapping a new parent removes the previous one's data."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fakes import FakeClients, FakeOrganizations, FakeTenancyData
from oci_security_center import cli
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane.service import (
    SETTING_GROUP_OCIDS,
    SETTING_TOKEN_EXCHANGE_OK,
    Actor,
    ControlPlane,
    ControlPlaneError,
)
from oci_security_center.models import (
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    Envelope,
    OnboardingStatus,
    OrgRole,
    utcnow,
)
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.storage.errors import StaleGenerationError
from oci_security_center.storage.sqlite import open_stores

OLD_PARENT = "ocid1.tenancy.oc1..aaaafakeoldparent"
OLD_CHILD = "ocid1.tenancy.oc1..aaaafakeoldchild"
NEW_PARENT = "ocid1.tenancy.oc1..aaaafakenewparent"
NEW_CHILD = "ocid1.tenancy.oc1..aaaafakenewchild"
ACTOR = Actor("tester@example.com", "admin")


@pytest.fixture
def world() -> dict[str, FakeTenancyData]:
    return {
        OLD_PARENT: FakeTenancyData(
            OLD_PARENT, "Old Org", dynamic_groups={"OSC-Scanner-DG": "ocid1.dynamicgroup.oc1..old"}
        ),
        OLD_CHILD: FakeTenancyData(OLD_CHILD, "Old Child"),
        NEW_PARENT: FakeTenancyData(NEW_PARENT, "New Org"),
        NEW_CHILD: FakeTenancyData(NEW_CHILD, "New Child"),
    }


def _old_clients(world: dict[str, FakeTenancyData]) -> FakeClients:
    return FakeClients(world, FakeOrganizations(OLD_PARENT, [(OLD_CHILD, "Old Child")]))


def _new_clients(world: dict[str, FakeTenancyData]) -> FakeClients:
    return FakeClients(world, FakeOrganizations(NEW_PARENT, [(NEW_CHILD, "New Child")]))


def _audit_event(tenancy: str) -> Envelope:
    return Envelope(
        schema_id="audit.events.v1",
        tenancy_ocid=tenancy,
        record_key="e1",
        region="us-ashburn-1",
        data={"event_time": "2026-10-01T00:00:00+00:00", "event_type": "x"},
        run_id="r1",
    )


@pytest.fixture
def cp(tmp_path: Path) -> ControlPlane:
    s = Settings(data_root=tmp_path, deployment=DeploymentMode.OCI)
    return ControlPlane(s, open_stores(s))


def _populate_old_org(cp: ControlPlane, world: dict[str, FakeTenancyData]) -> None:
    clients = _old_clients(world)
    cp.connect_parent(clients, OLD_PARENT, None, ACTOR)
    cp.state.put_secret_ciphertext("oldsecret", b"ciphertext")
    cp.save_connection(
        Connection(
            id="",
            tenancy_ocid=OLD_PARENT,
            method=ConnectionMethod.API_KEY,
            purpose=ConnectionPurpose.SCAN,
            secret_ref="local:oldsecret",
        ),
        ACTOR,
    )
    cp.discover_children(clients, ACTOR)
    cp.select_child(OLD_CHILD, ACTOR)
    cp.set_admin_browse(True, ACTOR)
    cp.state.set_setting(SETTING_TOKEN_EXCHANGE_OK, "true")
    cp.state.set_setting(f"verify:{OLD_CHILD}", "{}")
    cp.refresh_parent_checks(clients, ACTOR)  # caches group OCIDs, saves checks + findings
    gen = cp.state.current_generation()
    cp.stores.data.append_events(gen, OLD_CHILD, [_audit_event(OLD_CHILD)], "r1")
    cp.stores.data.set_watermark(gen, OLD_CHILD, "audit.events", "2026-10-01", "r1", "us-ashburn-1")
    cp.state.put_session("sess", b"blob", utcnow() + timedelta(minutes=5))


def test_new_parent_removes_previous_organization(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    _populate_old_org(cp, world)
    old_gen = cp.state.current_generation()
    stale_finding = cp.stores.data.list_findings(tenancy_ocid=OLD_PARENT)[0]
    assert cp.replaced_tenancies(NEW_PARENT)

    parent = cp.connect_parent(_new_clients(world), NEW_PARENT, None, ACTOR)

    assert cp.state.current_generation() == old_gen + 1
    org = cp.state.organization()
    assert (org.parent_tenancy_ocid, org.state) == (NEW_PARENT, "active")

    assert parent.alias == "osc_parent"  # default alias is free again
    assert [t.ocid for t in cp.state.list_tenancies()] == [NEW_PARENT]
    assert cp.children() == []
    assert cp.state.get_connection(OLD_PARENT, ConnectionPurpose.SCAN) is None
    assert cp.state.get_secret_ciphertext("oldsecret") is None
    assert cp.stores.data.list_findings() == []
    assert cp.state.get_checks([f"parent_access:{OLD_PARENT}:scanner-read-all"]) == {}
    assert cp.stores.data.get_watermark(old_gen, OLD_CHILD, "audit.events", "us-ashburn-1") is None
    assert not (cp.settings.audit_root / f"g{old_gen}").exists()
    # a worker that started before the switch can't write into the new organization
    with pytest.raises(StaleGenerationError):
        cp.stores.data.set_watermark(old_gen, OLD_CHILD, "audit.events", "x", "r2")
    with pytest.raises(StaleGenerationError):
        cp.stores.data.upsert_findings([stale_finding])
    with pytest.raises(StaleGenerationError):
        cp.stores.data.append_events(old_gen, OLD_CHILD, [_audit_event(OLD_CHILD)], "r2")
    assert cp.state.get_session("sess") is None
    for key in (SETTING_GROUP_OCIDS, SETTING_TOKEN_EXCHANGE_OK, f"verify:{OLD_CHILD}"):
        assert cp.state.get_setting(key) is None
    assert cp.state.get_setting("offer_admin_browse") is None
    # the control-plane activity log survives and records the replacement
    actions = [e["action"] for e in cp.state.list_events()]
    assert "org.replace" in actions
    assert "child.select" in actions

    result = cp.discover_children(_new_clients(world), ACTOR)
    assert [c.ocid for c in result.children] == [NEW_CHILD]


def test_reconnecting_same_parent_keeps_children(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    _populate_old_org(cp, world)
    assert cp.replaced_tenancies(OLD_PARENT) == []

    gen = cp.state.current_generation()
    cp.connect_parent(_old_clients(world), OLD_PARENT, None, ACTOR)
    assert cp.state.current_generation() == gen  # same organization: no switch
    assert cp.stores.data.list_findings(tenancy_ocid=OLD_PARENT)

    child = cp.state.get_tenancy(OLD_CHILD)
    assert child is not None
    assert child.onboarding_status is OnboardingStatus.PENDING
    assert cp.state.get_connection(OLD_PARENT, ConnectionPurpose.SCAN) is not None
    assert cp.state.get_setting(SETTING_GROUP_OCIDS) is not None
    assert cp.state.get_session("sess") is not None
    assert "org.replace" not in [e["action"] for e in cp.state.list_events()]


def test_failed_connection_test_keeps_current_organization(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    _populate_old_org(cp, world)
    world[NEW_PARENT].deny = True

    with pytest.raises(ControlPlaneError):
        cp.connect_parent(_new_clients(world), NEW_PARENT, None, ACTOR)

    parent = cp.parent()
    assert parent is not None
    assert parent.ocid == OLD_PARENT
    assert [c.ocid for c in cp.children()] == [OLD_CHILD]
    assert cp.stores.data.list_findings(tenancy_ocid=OLD_PARENT)


def test_leftover_rows_from_other_parent_are_hidden_and_rejected(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    """Databases written before this fix can hold a stale org; it must not leak into screens."""
    _populate_old_org(cp, world)
    stale = cp.state.get_tenancy(OLD_CHILD)
    assert stale is not None
    cp.state.set_setting("parent_tenancy_ocid", NEW_PARENT)

    assert cp.children() == []
    with pytest.raises(ControlPlaneError, match="unknown child"):
        cp.select_child(OLD_CHILD, ACTOR)
    assert stale.org_role is OrgRole.CHILD


def test_discovery_404_points_at_parent_permissions(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    clients = FakeClients(world, FakeOrganizations(NEW_PARENT, [], fail=True))
    cp.connect_parent(clients, NEW_PARENT, None, ACTOR)
    message = cp.discover_children(clients, ACTOR).message
    assert "organizations-family" in message
    assert "Admit" not in message


# --- CLI -------------------------------------------------------------------------------------
@pytest.fixture
def cli_env(
    tmp_path: Path, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> Runtime:
    settings = Settings(data_root=tmp_path, deployment=DeploymentMode.WORKSTATION)
    rt = build_runtime(settings)
    _populate_old_org(rt.control_plane, world)
    monkeypatch.setattr(cli, "_rt", lambda: build_runtime(settings))
    monkeypatch.setattr("oci_security_center.auth.signers.build_auth", lambda *a, **k: None)
    monkeypatch.setattr(cli, "ClientFactory", lambda auth: _new_clients(world))
    return rt


BOOTSTRAP = ["admin", "bootstrap", "--tenancy-ocid", NEW_PARENT, "--profile", "NEWORG"]


def test_cli_bootstrap_asks_before_replacing(cli_env: Runtime) -> None:
    result = CliRunner().invoke(cli.app, BOOTSTRAP, input="n\n")
    assert result.exit_code == 1
    assert "replaces the current organization" in result.output
    assert "Old Child" in result.output
    parent = cli_env.control_plane.parent()
    assert parent is not None
    assert parent.ocid == OLD_PARENT


def test_cli_bootstrap_yes_replaces(cli_env: Runtime) -> None:
    result = CliRunner().invoke(cli.app, [*BOOTSTRAP, "--yes"])
    assert result.exit_code == 0, result.output
    assert "Discovered 1 child" in result.output
    cp = cli_env.control_plane
    assert {t.ocid for t in cp.state.list_tenancies()} == {NEW_PARENT, NEW_CHILD}
    scan = cp.connection(ConnectionPurpose.SCAN)
    assert scan is not None
    assert scan.cli_profile == "NEWORG"


def test_replace_reports_undeletable_audit_folder(
    cp: ControlPlane, world: dict[str, FakeTenancyData], monkeypatch: pytest.MonkeyPatch
) -> None:
    _populate_old_org(cp, world)

    def refuse(*_: object, **__: object) -> None:
        raise PermissionError("nope")

    monkeypatch.setattr("oci_security_center.storage.sqlite.reset.shutil.rmtree", refuse)
    parent = cp.connect_parent(_new_clients(world), NEW_PARENT, None, ACTOR)

    # the switch still completes; the leftover folder is reported, not fatal
    assert cp.parent() == parent
    assert len(cp.replace_warnings) == 1
    assert "could not delete" in cp.replace_warnings[0]
    replace = next(e for e in cp.state.list_events() if e["action"] == "org.replace")
    assert "could not delete" in replace["detail"]


def test_replace_removes_all_old_generation_collected_data(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    _populate_old_org(cp, world)
    old_gen = cp.state.current_generation()
    with cp.stores.db.write() as conn:
        conn.execute(
            "INSERT INTO scan_runs(run_id, trigger, started_at, status, generation) "
            "VALUES ('run', 'manual', '2026-10-08T00:00:00+00:00', 'ok', ?)",
            (old_gen,),
        )
        # rows of the *new* parent from the old generation go too: the new org starts empty
        conn.execute(
            "INSERT INTO scan_run_items(run_id, generation, tenancy_ocid, dataset, scope_key, "
            "status) VALUES ('run', ?, ?, 'identity.policies', '{}', 'ok')",
            (old_gen, NEW_PARENT),
        )

    cp.connect_parent(_new_clients(world), NEW_PARENT, None, ACTOR)

    with cp.stores.db.read() as conn:
        for table in ("scan_runs", "scan_run_items", "watermarks", "findings"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table


def test_replace_leaves_old_generation_intact_when_maintenance_is_held(
    cp: ControlPlane, world: dict[str, FakeTenancyData]
) -> None:
    _populate_old_org(cp, world)
    gen = cp.state.current_generation()
    token = cp.state.begin_maintenance("someone-else")

    with pytest.raises(ControlPlaneError, match="nothing was changed"):
        cp.connect_parent(_new_clients(world), NEW_PARENT, None, ACTOR)

    cp.state.end_maintenance(token)
    assert cp.state.current_generation() == gen
    parent = cp.parent()
    assert parent is not None
    assert parent.ocid == OLD_PARENT
    assert cp.stores.data.list_findings(tenancy_ocid=OLD_PARENT)


def test_cli_preflight_rejects_vault_api_key_scan_before_anything(cli_env: Runtime) -> None:
    args = [
        "admin",
        "bootstrap",
        "--tenancy-ocid",
        NEW_PARENT,
        "--scan-method",
        "api_key",
        "--user-ocid",
        "ocid1.user.oc1..aaaafakeuser",
        "--fingerprint",
        "aa:bb",
        "--key-secret-ocid",
        "ocid1.vaultsecret.oc1..aaaafake",
        "--yes",
    ]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 1
    assert "its own key" in result.output
    assert "replaces the current organization" not in result.output  # rejected before the prompt
    parent = cli_env.control_plane.parent()
    assert parent is not None
    assert parent.ocid == OLD_PARENT


def test_cli_removes_secrets_it_stored_when_a_later_step_fails(
    cli_env: Runtime, world: dict[str, FakeTenancyData], tmp_path: Path
) -> None:
    key = tmp_path / "key.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")
    world[NEW_PARENT].deny = True  # the connection test fails
    with cli_env.stores.db.read() as conn:
        before = conn.execute("SELECT COUNT(*) FROM local_secrets").fetchone()[0]
    args = [
        "admin",
        "bootstrap",
        "--tenancy-ocid",
        NEW_PARENT,
        "--scan-method",
        "api_key",
        "--user-ocid",
        "ocid1.user.oc1..aaaafakeuser",
        "--fingerprint",
        "aa:bb",
        "--region",
        "us-ashburn-1",
        "--key-file",
        str(key),
        "--yes",
    ]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 1
    assert "NotAuthorizedOrNotFound" in result.output
    with cli_env.stores.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM local_secrets").fetchone()[0] == before
    parent = cli_env.control_plane.parent()
    assert parent is not None
    assert parent.ocid == OLD_PARENT


def test_cli_recover_reports_state(cli_env: Runtime) -> None:
    result = CliRunner().invoke(cli.app, ["admin", "recover"])
    assert result.exit_code == 0
    assert "nothing to recover" in result.output
    assert "organization state: active" in result.output
