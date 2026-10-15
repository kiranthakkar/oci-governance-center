"""Tier 1 dashboards: coverage is always visible and unknown is never shown as healthy."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_audit_ingestion import FakeSource, _event
from test_collectors import D1, FakeWorld, Tenant, _problem

from oci_security_center.collection.audit import AuditIngestor
from oci_security_center.collection.registry import collectors_for_tier
from oci_security_center.collection.runner import ScanRunner
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import OnboardingStatus, OrgRole, Tenancy, utcnow
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.web import dashboards
from oci_security_center.web.app import create_app
from oci_security_center.web.sessions import COOKIE

P = "ocid1.tenancy.oc1..aaaafakeparent"
C = "ocid1.tenancy.oc1..aaaafakechild1"
KEY = "Kq5vQ9W0m5mX3p2b6f1oQh2wD8yS7cJ0rT4uV6xZ9aE="


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    s = Settings(
        data_root=tmp_path,
        deployment=DeploymentMode.WORKSTATION,
        secret_key=KEY,
        public_base_url="http://testserver",
    )  # type: ignore[arg-type]
    runtime = build_runtime(s)
    st = runtime.stores.state
    st.set_setting("parent_tenancy_ocid", P)
    st.set_organization_parent(P, 1)
    for ocid, name, role in ((P, "Parent", OrgRole.PARENT), (C, "Child", OrgRole.CHILD)):
        st.upsert_tenancy(
            Tenancy(
                ocid=ocid,
                name=name,
                alias=f"a{ocid[-6:]}",
                org_role=role,
                onboarding_status=OnboardingStatus.ACTIVE,
                home_region="us-ashburn-1",
                parent_tenancy_ocid=P if role is OrgRole.CHILD else None,
            )
        )
    return runtime


@pytest.fixture
def world() -> FakeWorld:
    return FakeWorld(
        {
            P: Tenant(
                P,
                problems=[_problem("pr1")],
                users={D1: [("u1", "alice", ["g1"])]},
                groups={D1: [("g1", "Admins", ["u1"])]},
            ),
            C: Tenant(C, cloud_guard="DISABLED", enrolled=False, domains={}),
        }
    )


def _viewer(rt: Runtime) -> TestClient:
    token = "viewer-token"
    rt.stores.state.put_session(
        hashlib.sha256(token.encode()).hexdigest(),
        rt.secrets.encrypt(
            json.dumps(
                {
                    "user": {"name": "v", "role": "viewer", "via": "oidc"},
                    "csrf": "c",
                    "__created__": time.time(),
                    "generation": rt.stores.state.current_generation(),
                }
            ).encode()
        ),
        utcnow() + timedelta(minutes=30),
    )
    client = TestClient(create_app(rt.settings, rt), base_url="http://testserver")
    client.cookies.set(COOKIE, token)
    return client


def test_before_any_scan_everything_says_never_collected(rt: Runtime) -> None:
    rows = dashboards.coverage(rt)
    assert rows
    assert {r.state for r in rows} == {"never"}
    client = _viewer(rt)
    assert "never" in client.get("/coverage").text
    access = client.get("/access").text
    assert "not been collected completely" in access
    assert "not an effective-permissions view" in access
    gov = client.get("/governance").text
    assert "unknown" in gov


def test_pages_after_a_scan(rt: Runtime, world: FakeWorld) -> None:
    ScanRunner(rt.settings, rt.stores, world, collectors_for_tier(1)).scan()
    source = FakeSource()
    now = utcnow()
    source.events[P] = [_event("e1", now - timedelta(minutes=20))]
    AuditIngestor(rt.settings, rt.stores, world, source=source, now=lambda: now).ingest()
    client = _viewer(rt)

    coverage = client.get("/coverage").text
    assert "identity_domains.users" in coverage
    assert "domain " + D1 in coverage
    states = {(r.tenancy_ocid, r.dataset): r.state for r in dashboards.coverage(rt)}
    assert states[(P, "identity.policies")] == "complete"
    assert states[(C, "cloud_guard.problems")] == "not_applicable"
    assert states[(P, "audit.events")] == "complete"

    access = client.get(f"/access?tenancy={P}").text
    assert "Admins" in access
    assert "alice" in access  # member names resolved from users
    assert "Allow group A to read all-resources in tenancy" in access

    tree = client.get(f"/compartments?tenancy={P}").text
    assert "Prod" in tree

    gov = client.get("/governance").text
    assert "DISABLED" in gov
    assert "BUCKET_IS_PUBLIC" in gov
    assert "Cloud Guard is not enabled" in gov

    activity = client.get("/activity").text
    assert "us-ashburn-1" in activity
    assert ": 1" in activity  # one event today

    assert client.get("/access?tenancy=ocid1.tenancy.oc1..aaaaunknown").status_code == 404


def test_failed_scope_is_shown_as_a_gap_not_as_current(rt: Runtime, world: FakeWorld) -> None:
    runner = ScanRunner(rt.settings, rt.stores, world, collectors_for_tier(1))
    runner.scan()
    world.tenants[P].fail["list_policies"] = 403
    runner.scan(only={"identity.policies"})
    states = {(r.tenancy_ocid, r.dataset): r for r in dashboards.coverage(rt)}
    row = states[(P, "identity.policies")]
    assert row.state == "partial"
    assert row.pill == "missing"
    assert row.last_success is not None  # the last complete collection stays visible


def test_stale_scope(rt: Runtime, world: FakeWorld) -> None:
    ScanRunner(rt.settings, rt.stores, world, collectors_for_tier(1)).scan(
        only={"identity.region_subscriptions"}
    )
    with rt.stores.db.write() as conn:
        conn.execute("UPDATE scope_manifests SET finished_at='2000-01-01T00:00:00+00:00'")
    states = {(r.tenancy_ocid, r.dataset): r.state for r in dashboards.coverage(rt)}
    assert states[(P, "identity.region_subscriptions")] == "stale"
