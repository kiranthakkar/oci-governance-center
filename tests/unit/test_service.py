"""Monitoring recovery and isolation use synthetic OCI sources."""

import json
from types import SimpleNamespace as NS
from unittest.mock import Mock

import oci
import pytest

from oci_governance_center.models import Batch, Record, Scope
from tests.conftest import install


def test_failed_discovery_does_not_remove_children(service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    monkeypatch.setattr(
        "oci_governance_center.service.discover", Mock(side_effect=RuntimeError("network"))
    )
    service.discover()
    assert service.store.children()[0].status == "active"
    assert service.store.rows("coverage")[0]["status"] == "failed"


def test_confirmed_departure_stops_monitoring_but_preserves_history(
    service, parent, child, monkeypatch
):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    scope = Scope(tenancy=child.ocid, dataset="users", region=child.home_region)
    service.store.publish(
        generation, Batch(scope=scope, records=[Record(key="u", data={"name": "Synthetic"})])
    )
    monkeypatch.setattr("oci_governance_center.service.discover", lambda *_: [])
    service.discover()
    assert service.store.children()[0].status == "departed"
    assert len(service.store.rows("records")) == 1


def test_partial_child_collects_accessible_data_and_recovers(service, parent, child, monkeypatch):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    exchange = Mock()
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: exchange)
    monkeypatch.setattr(service, "confirm_key", lambda *_: True)
    good = Batch(
        scope=Scope(tenancy=child.ocid, dataset="users", region=child.home_region),
        records=[Record(key="u", data={"name": "Synthetic"})],
    )
    bad = Batch(
        scope=Scope(tenancy=child.ocid, dataset="groups", region=child.home_region),
        complete=False,
        error="Denied",
    )
    monkeypatch.setattr("oci_governance_center.service.inventory", lambda *_: iter([good, bad]))
    service.scan_one(generation, parent, child, "identity")
    assert service.store.children()[0].status == "partial"
    assert len(service.store.rows("records")) == 1
    monkeypatch.setattr(
        "oci_governance_center.service.inventory",
        lambda *_: iter([good, bad.model_copy(update={"complete": True, "error": ""})]),
    )
    service.scan_one(generation, parent, child, "identity")
    assert service.store.children()[0].status == "active"
    assert all(
        json.loads(r["data"])["status"] == "resolved" for r in service.store.rows("findings")
    )


def test_parent_key_401_blocks_organization_but_child_denial_does_not(service, parent, monkeypatch):
    generation = install(service.store, parent)
    identity = Mock()
    identity.get_tenancy.side_effect = oci.exceptions.ServiceError(
        401, "NotAuthenticated", {}, "synthetic"
    )
    monkeypatch.setattr("oci_governance_center.service.client", lambda *_: identity)
    with pytest.raises(oci.exceptions.ServiceError):
        service.confirm_key(generation, parent)
    assert service.store.state()[2]
    service.store.block(generation, False)
    identity.get_tenancy.side_effect = oci.exceptions.ServiceError(500, "Internal", {}, "synthetic")
    with pytest.raises(oci.exceptions.ServiceError):
        service.confirm_key(generation, parent)
    assert not service.store.state()[2]


def test_cloud_guard_finding_resolves_only_on_complete_same_scope(service, parent):
    generation = install(service.store, parent)
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid,
        dataset="cloud_guard.configuration",
        region=parent.domain.home_region,
    )
    disabled = Batch(scope=scope, records=[Record(key="config", data={"status": "DISABLED"})])
    service.findings(generation, disabled, None)
    finding = json.loads(service.store.rows("findings")[0]["data"])
    assert finding["rule_id"] == "GOV-CG-001" and finding["status"] == "open"
    enabled = disabled.model_copy(
        update={"records": [Record(key="config", data={"status": "ENABLED"})]}
    )
    service.findings(generation, enabled, None)
    assert json.loads(service.store.rows("findings")[0]["data"])["status"] == "resolved"


def test_stale_admin_cannot_pause_child_in_replacement_organization(service, parent, child):
    from oci_governance_center.storage import StaleWork

    generation = install(service.store, parent)
    newer = install(service.store, parent.model_copy(update={"name": "New parent"}))
    service.store.save_child(newer, child)
    with pytest.raises(StaleWork):
        service.pause(child.ocid, expected_generation=generation)
    assert service.store.children()[0].status == "active"


def test_successful_family_does_not_hide_failed_other_dataset(service, parent, child):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    scope = Scope(tenancy=child.ocid, dataset="audit.backfill", region=child.home_region)
    service.store.publish(generation, Batch(scope=scope, complete=False, error="History pending"))
    service.child_status(generation, child, "active", "")
    assert service.store.children()[0].status == "partial"


def test_audit_collects_recent_events_before_historical_backfill(service, parent, monkeypatch):
    from datetime import timedelta

    from oci_governance_center.models import now

    generation = install(service.store, parent)
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
    calls = []

    def read(signer, domain, region, compartments, start, end, check_stop=None):
        calls.append((start, end))
        return []

    monkeypatch.setattr("oci_governance_center.service.read_interval", read)
    service.audit(generation, object(), parent.domain, None)
    assert now() - calls[0][0] < timedelta(hours=2)
    assert any(now() - start > timedelta(days=80) for start, end in calls)
    coverage = service.store.rows("coverage")
    assert any(
        json.loads(row["scope"])["dataset"] == "audit.backfill" and row["status"] == "failed"
        for row in coverage
    )
