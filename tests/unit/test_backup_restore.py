"""Full backup and restore (docs/storage.md §6.1)."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from oci_security_center.auth.secrets import load_fernet_key
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import Envelope, Finding, FindingSource, Severity, utcnow
from oci_security_center.storage.errors import MaintenanceError
from oci_security_center.storage.sqlite import SqliteStores, open_stores
from oci_security_center.storage.sqlite import backup as backup_mod
from oci_security_center.storage.sqlite.backup import (
    BackupError,
    create_backup,
    list_backups,
    restore_backup,
)

P = "ocid1.tenancy.oc1..aaaafakeparent"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_root=tmp_path / "osc", deployment=DeploymentMode.WORKSTATION, switch_drain_seconds=0.2
    )


def _populate(stores: SqliteStores) -> None:
    gen = stores.state.current_generation()
    stores.state.set_setting("parent_tenancy_ocid", P)
    stores.state.set_organization_parent(P, gen)
    stores.data.upsert_findings(
        [
            Finding(
                source=FindingSource.GOVERNANCE,
                tenancy_ocid=P,
                rule_id="GOV-CG-001",
                identity={"rule": "GOV-CG-001", "subject": "cloud_guard"},
                generation=gen,
                severity=Severity.HIGH,
                title="Cloud Guard is not enabled",
            )
        ]
    )
    now = utcnow()
    stores.data.append_events(
        gen,
        P,
        [
            Envelope(
                schema_id="audit.events.v1",
                tenancy_ocid=P,
                record_key="e1",
                data={"event_time": now.isoformat(), "event_type": "x"},
                run_id="r",
                region="us-ashburn-1",
            )
        ],
        "r",
    )
    stores.state.put_session("s1", b"blob", now + timedelta(minutes=5))


def _backup(settings: Settings, stores: SqliteStores, dest: Path) -> Path:
    return create_backup(settings, stores.db, stores.state, load_fernet_key(settings), dest)


def test_round_trip(settings: Settings, tmp_path: Path) -> None:
    stores = open_stores(settings)
    _populate(stores)
    path = _backup(settings, stores, tmp_path / "backups")
    assert path.name.startswith("osc-backup-")
    assert stores.state.organization().state == "active"  # maintenance released
    manifest = json.loads((path / "manifest.json").read_text())
    assert {f["path"] for f in manifest["files"]} == {"osc.db", f"audit/{P}/{utcnow():%Y-%m}.db"}
    assert manifest["key_id"]
    assert "verification" in manifest
    assert all(os.stat(path / f["path"]).st_mode & 0o777 == 0o600 for f in manifest["files"])

    # lose the live data, then restore
    key = load_fernet_key(settings)
    for f in sorted(settings.data_root.rglob("*"), reverse=True):
        if f.name != ".secret_key":
            f.unlink() if f.is_file() else f.rmdir()
    result = restore_backup(settings, path, key, expect_parent=P)
    assert result.generation == 2
    assert result.previous is not None
    restored = open_stores(settings)
    org = restored.state.organization()
    assert (org.generation, org.state, org.parent_tenancy_ocid) == (2, "active", P)
    [finding] = restored.data.list_findings()
    assert finding.rule_id == "GOV-CG-001"
    rows = restored.data.query_audit(2, P, f"{utcnow():%Y-%m}")
    assert [r["event_id"] for r in rows] == ["e1"]
    assert restored.state.get_session("s1") is None  # sessions never survive a restore
    assert not (settings.audit_root / "g1").exists()


def test_tampered_missing_or_wrong_key_is_refused_before_changes(
    settings: Settings, tmp_path: Path
) -> None:
    stores = open_stores(settings)
    _populate(stores)
    path = _backup(settings, stores, tmp_path / "b")
    key = load_fernet_key(settings)
    marker = settings.data_root / "marker"
    marker.write_text("live")

    with pytest.raises(BackupError, match="not the key"):
        restore_backup(settings, path, Fernet.generate_key())

    audit = next(p for p in path.rglob("*.db") if p.name != "osc.db")
    original = audit.read_bytes()
    audit.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(BackupError, match="changed or corrupt"):
        restore_backup(settings, path, key)
    audit.unlink()
    with pytest.raises(BackupError, match="missing"):
        restore_backup(settings, path, key)
    with pytest.raises(BackupError, match="backup is of parent"):
        restore_backup(
            settings, path, key, expect_parent="ocid1.tenancy.oc1..aaaaother", main_db_only=True
        )
    assert marker.read_text() == "live"  # nothing changed


def test_main_db_only_restore_resets_audit_coverage(settings: Settings, tmp_path: Path) -> None:
    stores = open_stores(settings)
    _populate(stores)
    stores.data.set_watermark(
        1, P, "audit.events", "2026-10-01T00:00:00+00:00", "r", "us-ashburn-1"
    )
    path = _backup(settings, stores, tmp_path / "b")
    for p in path.rglob("*.db"):
        if p.name != "osc.db":
            p.unlink()
    result = restore_backup(settings, path, load_fernet_key(settings), main_db_only=True)
    assert any("partial restore" in n for n in result.notes)
    restored = open_stores(settings)
    assert restored.data.get_watermark(result.generation, P, "audit.events", "us-ashburn-1") is None
    assert restored.data.list_findings()  # main database content is back


def test_interrupted_backup_is_never_published(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stores = open_stores(settings)
    _populate(stores)

    def fail(*_: object) -> bool:
        raise OSError("disk full")

    monkeypatch.setattr(backup_mod, "_quick_check", fail)
    with pytest.raises(OSError, match="disk full"):
        _backup(settings, stores, tmp_path / "b")
    assert list_backups(tmp_path / "b") == []
    assert list((tmp_path / "b").iterdir()) == []  # temporary directory removed
    assert stores.state.organization().state == "active"
    with pytest.raises(BackupError, match="no manifest"):
        restore_backup(settings, tmp_path / "b", load_fernet_key(settings))


def test_backup_waits_for_collection_and_gives_up(settings: Settings, tmp_path: Path) -> None:
    stores = open_stores(settings)
    assert stores.state.acquire_lease("scope", 1, "collector", 60)
    started = time.monotonic()
    with pytest.raises(MaintenanceError, match="did not finish"):
        _backup(settings, stores, tmp_path / "b")
    assert time.monotonic() - started >= 0.2
    assert stores.state.organization().state == "active"


def test_newer_schema_and_expiry(settings: Settings, tmp_path: Path) -> None:
    stores = open_stores(settings)
    dest = tmp_path / "b"
    path = _backup(settings, stores, dest)
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["schema_version"] = 999
    (path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(BackupError, match="newer than this OSC"):
        restore_backup(settings, path, load_fernet_key(settings))

    old = datetime(2020, 1, 1, tzinfo=UTC).timestamp()
    os.utime(path / "manifest.json", (old, old))
    fresh = _backup(settings, stores, dest)  # creating a backup expires the old one
    assert list_backups(dest) == [fresh]


def test_restore_rekeys_findings_and_preserves_suppression(
    settings: Settings, tmp_path: Path
) -> None:
    from oci_security_center.models import FindingStatus

    stores = open_stores(settings)
    _populate(stores)
    original = stores.data.list_findings()[0].model_copy(
        update={"status": FindingStatus.SUPPRESSED}
    )
    stores.data.upsert_findings([original])
    path = _backup(settings, stores, tmp_path / "backups")
    key = load_fernet_key(settings)
    result = restore_backup(settings, path, key)
    restored = open_stores(settings)
    [finding] = restored.data.list_findings()
    assert finding.generation == result.generation
    assert finding.finding_id != original.finding_id
    assert finding.first_seen == original.first_seen
    assert finding.status is FindingStatus.SUPPRESSED
    restored.data.upsert_findings(
        [
            original.model_copy(
                update={"generation": result.generation, "status": FindingStatus.OPEN}
            )
        ]
    )
    [again] = restored.data.list_findings()
    assert again.status is FindingStatus.SUPPRESSED
    assert again.first_seen == original.first_seen


def test_restore_updates_manifest_generation_and_never_reuses_live_generation(
    settings: Settings, tmp_path: Path
) -> None:
    from oci_security_center.models import CollectionManifest, CollectionScope

    stores = open_stores(settings)
    _populate(stores)
    gen = stores.state.current_generation()
    scope = CollectionScope(generation=gen, tenancy_ocid=P, dataset="identity.policies")
    lease = stores.state.acquire_lease(scope.lease_key, gen, "snapshot", 60)
    manifest = CollectionManifest(
        scope=scope, run_id="snapshot", lease_token=lease, started_at=utcnow(), pages_complete=True
    )
    stores.data.apply_snapshot(scope, [], manifest)
    stores.state.release_lease(scope.lease_key, lease)
    path = _backup(settings, stores, tmp_path / "backups")
    for _ in range(3):
        token = stores.state.begin_maintenance("advance")
        stores.state.end_maintenance(token, advance_generation=True)
    live_gen = stores.state.current_generation()
    result = restore_backup(settings, path, load_fernet_key(settings))
    assert result.generation > live_gen
    restored = open_stores(settings)
    with restored.db.read() as conn:
        row = conn.execute("SELECT generation, manifest FROM scope_manifests").fetchone()
    assert row["generation"] == result.generation
    assert json.loads(row["manifest"])["scope"]["generation"] == result.generation


def test_backup_holds_barrier_through_all_file_copies(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from contextlib import suppress
    from threading import Event

    from oci_security_center.storage.sqlite.retention import purge

    stores = open_stores(settings)
    _populate(stores)
    entered, proceed = Event(), Event()
    original = backup_mod._sqlite_copy

    def paused(src: Path, dest: Path) -> None:
        entered.set()
        assert proceed.wait(3)
        original(src, dest)

    monkeypatch.setattr(backup_mod, "_sqlite_copy", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        backup = pool.submit(_backup, settings, stores, tmp_path / "backups")
        assert entered.wait(3)
        retention = pool.submit(purge, settings, stores.db, stores.data)
        try:
            with pytest.raises(TimeoutError):
                retention.result(timeout=0.05)
        finally:
            proceed.set()
        assert backup.result(timeout=3).exists()
        # Once copying ends, purge either acquires the released barrier or sees maintenance
        # still owned by backup; neither path can delete files during the copy.
        with suppress(MaintenanceError):
            retention.result(timeout=3)
