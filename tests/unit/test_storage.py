"""State isolation, durable events, recovery and complete-scope behavior."""

import json
import sqlite3

import pytest

from oci_governance_center.models import Batch, Record, Scope
from oci_governance_center.storage import StaleWork
from tests.conftest import install


def test_candidate_is_encrypted_owner_bound_and_not_active(store, parent):
    ident = store.candidate("one", 0, parent)
    assert store.state() == (0, None, False)
    assert store.get_candidate(ident, "one")[1] == parent
    with pytest.raises(ValueError):
        store.get_candidate(ident, "two")
    assert b"synthetic-login-secret" not in store.path.read_bytes()
    with store.db() as db:
        row = db.execute("SELECT data FROM candidates").fetchone()[0]
    assert b"PRIVATE KEY" not in row


def test_install_cleans_old_files_and_fences_all_old_work(store, parent, child):
    generation = install(store, parent)
    store.save_child(generation, child)
    scope = Scope(tenancy=child.ocid, dataset="test", region=child.home_region)
    store.publish(generation, Batch(scope=scope, records=[Record(key="one", data={"value": 1})]))
    store.save_session("old", {"grant": {"access_token": "synthetic"}}, 300)
    for category in ("audit", "backups", "exports"):
        directory = store.root / category / f"g{generation}"
        directory.mkdir(parents=True)
        (directory / "old.txt").write_text("synthetic old organization")
    candidate = store.candidate("new", generation, parent.model_copy(update={"name": "New"}))
    newer = store.install(candidate, "new", "new-admin")
    assert newer == generation + 1
    assert store.children() == []
    assert store.rows("records") == []
    assert store.session("old") is None
    assert all(
        not (store.root / c / f"g{generation}").exists() for c in ("audit", "backups", "exports")
    )
    with pytest.raises(StaleWork):
        store.publish(generation, Batch(scope=scope))


def test_expired_or_competing_candidate_leaves_old_parent(store, parent):
    generation = install(store, parent)
    first = store.candidate("one", generation, parent.model_copy(update={"name": "First"}))
    second = store.candidate("two", generation, parent.model_copy(update={"name": "Second"}))
    store.install(first, "one", "admin")
    with pytest.raises(ValueError):
        store.install(second, "two", "admin")
    assert store.state()[1].name == "First"


def test_failed_read_preserves_snapshot_and_resolution_requires_same_scope(store, parent):
    generation = install(store, parent)
    scope = Scope(tenancy=parent.domain.tenancy_ocid, dataset="users", region="us-ashburn-1")
    store.publish(
        generation, Batch(scope=scope, records=[Record(key="u", data={"name": "Synthetic"})])
    )
    store.publish(generation, Batch(scope=scope, complete=False, error="Read denied"))
    assert len(store.rows("records")) == 1
    finding = json.loads(store.rows("findings")[0]["data"])
    assert finding["status"] == "open"
    store.publish(generation, Batch(scope=scope.model_copy(update={"domain": "other"})))
    assert json.loads(store.rows("findings")[0]["data"])["status"] == "open"
    store.publish(generation, Batch(scope=scope))
    assert store.rows("records") == []
    resolved = json.loads(store.rows("findings")[0]["data"])
    assert resolved["status"] == "resolved" and resolved["resolved_at"]


def test_paused_revision_rejects_inflight_snapshot_and_audit(store, parent, child, service):
    generation = install(store, parent)
    store.save_child(generation, child)
    service.pause(child.ocid)
    scope = Scope(tenancy=child.ocid, dataset="users", region=child.home_region)
    with pytest.raises(StaleWork):
        store.publish(generation, Batch(scope=scope), child.revision)
    with pytest.raises(StaleWork):
        store.audit_commit(
            generation,
            scope,
            "2026-10-01T00:00:00+00:00",
            "2026-10-01T01:00:00+00:00",
            [],
            child.revision,
        )
    assert store.children()[0].status == "paused"


def test_audit_is_durable_before_checkpoint_and_replay_deduplicates(store, parent):
    generation = install(store, parent)
    scope = Scope(tenancy=parent.domain.tenancy_ocid, dataset="audit.events", region="us-ashburn-1")
    events = [{"id": "fake-event", "time": "2026-10-01T00:20:00+00:00"}]
    for _ in range(2):
        store.audit_commit(
            generation, scope, "2026-10-01T00:00:00+00:00", "2026-10-01T01:00:00+00:00", events
        )
    path = next((store.root / "audit").rglob("*.db"))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    assert store.checkpoint(scope) == "2026-10-01T01:00:00+00:00"
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM audit_receipts").fetchone()[0] == 1


def test_cleanup_failure_is_journaled_and_recovered(store, parent, monkeypatch):
    generation = install(store, parent)
    directory = store.root / "backups" / f"g{generation}"
    directory.mkdir(parents=True)
    (directory / "backup.db").write_text("synthetic")
    candidate = store.candidate("owner", generation, parent)
    original = __import__("shutil").rmtree
    monkeypatch.setattr(
        "oci_governance_center.storage.shutil.rmtree",
        lambda *_: (_ for _ in ()).throw(OSError("disk busy")),
    )
    with pytest.raises(OSError):
        store.install(candidate, "owner", "admin")
    with pytest.raises(StaleWork):
        store.lease(generation + 1, "scope", "owner")
    monkeypatch.setattr("oci_governance_center.storage.shutil.rmtree", original)
    recovered = store
    recovered.cleanup()
    assert not directory.exists()
    assert recovered.lease(generation + 1, "scope", "owner")


def test_cross_process_lease_has_one_owner(store, parent):
    generation = install(store, parent)
    assert store.lease(generation, "scope", "a")
    assert not store.lease(generation, "scope", "b")
    store.release("scope", "b")
    assert not store.lease(generation, "scope", "b")
    store.release("scope", "a")
    assert store.lease(generation, "scope", "b")


def test_blocked_key_and_expired_lease_fence_all_publication(store, parent):
    generation = install(store, parent)
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid, dataset="users", region=parent.domain.home_region
    )
    store.block(generation, True)
    with pytest.raises(StaleWork):
        store.publish(generation, Batch(scope=scope))
    store.block(generation, False)
    assert store.lease(generation, "unit", "worker")
    store.release("unit", "worker")
    with pytest.raises(StaleWork):
        store.publish(generation, Batch(scope=scope), lease=("unit", "worker"))
    assert store.rows("records") == []


def test_stale_authorization_cannot_read_new_organization(store, parent):
    previous = install(store, parent)
    install(store, parent.model_copy(update={"name": "New parent"}))
    with pytest.raises(StaleWork):
        store.rows("records", previous)
    with pytest.raises(StaleWork):
        store.children(previous)


def test_snapshot_changes_are_recorded_only_for_complete_reads(store, parent):
    generation = install(store, parent)
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid, dataset="policies", region=parent.domain.home_region
    )
    store.publish(
        generation,
        Batch(scope=scope, records=[Record(key="p", data={"statements": ["synthetic"]})]),
    )
    store.publish(generation, Batch(scope=scope, complete=False, error="Denied"))
    assert [c["kind"] for c in store.rows("changes")] == ["added"]
    store.publish(generation, Batch(scope=scope))
    assert sorted(c["kind"] for c in store.rows("changes")) == ["added", "removed"]


def test_retention_removes_old_events_and_expired_auth_state(store, parent):
    generation = install(store, parent)
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid, dataset="audit.events", region=parent.domain.home_region
    )
    store.audit_commit(
        generation,
        scope,
        "2001-01-01T00:00:00+00:00",
        "2001-01-01T01:00:00+00:00",
        [{"id": "old", "time": "2001-01-01T00:30:00+00:00"}],
    )
    store.purge()
    path = next((store.root / "audit").rglob("*.db"))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_malformed_stored_finding_is_rejected_on_read(store, parent):
    generation = install(store, parent)
    scope = Scope(tenancy=parent.domain.tenancy_ocid, dataset="users", region="us-ashburn-1")
    store.publish(generation, Batch(scope=scope, complete=False, error="Read denied"))
    with store.db() as db:
        row = db.execute("SELECT id,data FROM findings").fetchone()
        data = {**json.loads(row["data"]), "severity": "SEVERE"}
        db.execute("UPDATE findings SET data=? WHERE id=?", (json.dumps(data), row["id"]))
    with pytest.raises(ValueError):
        store.rows("findings")
