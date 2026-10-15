from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fakes import FakeClients, FakeOrganizations, FakeTenancyData
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane.service import Actor
from oci_security_center.models import utcnow
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.web.app import create_app
from oci_security_center.web.security import role_from_groups
from oci_security_center.web.sessions import COOKIE

PARENT = "ocid1.tenancy.oc1..aaaafakeparent"
CHILD = "ocid1.tenancy.oc1..aaaafakechild1"
ACTOR = Actor("t", "admin")
# TestClient sends Host: testserver; oci mode requires an https public URL.
BASE = {
    DeploymentMode.WORKSTATION: "http://testserver",
    DeploymentMode.OCI: "https://testserver",
}


def _client(rt: Runtime) -> TestClient:
    return TestClient(create_app(rt.settings, rt), base_url=rt.settings.public_base_url)


def _runtime(
    tmp_path: Path, mode: DeploymentMode = DeploymentMode.WORKSTATION, with_parent: bool = True
) -> Runtime:
    settings = Settings(
        data_root=tmp_path,
        deployment=mode,
        secret_key="Kq5vQ9W0m5mX3p2b6f1oQh2wD8yS7cJ0rT4uV6xZ9aE=",
        public_base_url=BASE[mode],
    )  # type: ignore[arg-type]
    rt = build_runtime(settings)
    if with_parent:
        world = {PARENT: FakeTenancyData(PARENT, "Parent"), CHILD: FakeTenancyData(CHILD, "Kid")}
        clients = FakeClients(world, FakeOrganizations(PARENT, [(CHILD, "Kid")]))
        rt.control_plane.connect_parent(clients, PARENT, None, ACTOR)
        rt.control_plane.discover_children(clients, ACTOR)
        rt.control_plane.select_child(CHILD, ACTOR)
    return rt


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token in page"
    return m.group(1)


def _local_login(client: TestClient) -> str:
    page = client.get("/login")
    token = _csrf(page.text)
    r = client.post("/login/local", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    return _csrf(client.get("/admin/organization").text)


def test_setup_required_without_parent(tmp_path: Path) -> None:
    client = _client(_runtime(tmp_path, with_parent=False))
    assert "Setup required" in client.get("/").text
    r = client.get("/admin/organization", follow_redirects=False)
    assert r.status_code == 303


def test_admin_pages_require_login(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    r = client.get("/admin/organization", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_local_login_and_organization_screen(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    _local_login(client)
    page = client.get("/admin/organization").text
    assert "osc-parent-access" in page
    assert "osc-endorse-children" in page
    assert f"Define tenancy osc_kid as {CHILD}" in page
    assert "Allow group OSC-Scanners to read all-resources in tenancy" in page  # workstation


def test_child_screen_shows_endorse_and_admit(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    _local_login(client)
    page = client.get(f"/admin/children/{CHILD}").text
    assert "Endorse, in the parent tenancy" in page
    assert "Define and Admit, in the child tenancy" in page
    assert "Admit group OSC_Scanners of tenancy osc_parent to read all-resources in tenancy" in page
    dl = client.get(f"/admin/download?view=child-admit&ocid={CHILD}")
    assert dl.status_code == 200
    assert "attachment" in dl.headers["content-disposition"]
    assert dl.text.startswith("Define tenancy osc_parent as")


def test_post_without_csrf_is_rejected(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    _local_login(client)
    r = client.post(f"/admin/children/{CHILD}/select", data={"alias": "x"})
    assert r.status_code == 403


def test_local_login_disabled_in_oci_mode(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, DeploymentMode.OCI)
    client = _client(rt)
    page = client.get("/login")
    assert "Local sign-in" not in page.text
    r = client.post(
        "/login/local", data={"csrf_token": _csrf(page.text) if "csrf_token" in page.text else "x"}
    )
    assert r.status_code == 403


def test_viewer_cannot_open_admin(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    token = "viewer-session-token"
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
        utcnow() + timedelta(minutes=5),
    )
    client = _client(rt)
    client.cookies.set(COOKIE, token)
    assert client.get("/findings").status_code == 200
    assert client.get("/admin/organization").status_code == 403


def test_secrets_never_rendered(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    csrf = _local_login(client)
    r = client.post(
        "/admin/connections/admin",
        data={
            "csrf_token": csrf,
            "method": "oidc_token_exchange",
            "region": "us-ashburn-1",
            "domain_url": "https://idcs-fake.identity.oraclecloud.com",
            "client_id": "abc",
            "client_secret": "SUPER-SECRET-VALUE",
        },
        follow_redirects=True,
    )
    assert "Saved admin connection" in r.text
    assert "SUPER-SECRET-VALUE" not in r.text
    conn = rt.control_plane.connection(
        __import__(
            "oci_security_center.models", fromlist=["ConnectionPurpose"]
        ).ConnectionPurpose.ADMIN
    )
    assert conn is not None
    assert conn.secret_ref is not None
    assert conn.secret_ref.startswith("local:")
    raw = (tmp_path / "osc.db").read_bytes()
    assert b"SUPER-SECRET-VALUE" not in raw


def test_scan_connection_cannot_be_oidc(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    csrf = _local_login(client)
    r = client.post(
        "/admin/connections/scan",
        data={"csrf_token": csrf, "method": "oidc_token_exchange"},
        follow_redirects=True,
    )
    assert "not supported" in r.text


def test_security_headers_and_cookie_flags(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    r = client.get("/login")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


@pytest.mark.parametrize(
    ("groups", "role"),
    [
        (["OSC-Admins"], "admin"),
        ([{"name": "osc-viewers"}], "viewer"),
        (["Everyone"], None),
        (None, None),
    ],
)
def test_role_from_groups(groups: object, role: str | None) -> None:
    assert role_from_groups(groups, Settings()) == role
