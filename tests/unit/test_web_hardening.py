"""Web security hardening: Host/Origin allow-list, session lifetimes, error handling, re-checks."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from fakes import FakeClients, FakeOrganizations, FakeTenancyData
from oci_security_center.auth.signers import AuthError
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.control_plane.service import Actor
from oci_security_center.models import utcnow
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.web.app import create_app
from oci_security_center.web.security import LoginRateLimiter, jwt_provider_for
from oci_security_center.web.sessions import COOKIE

PARENT = "ocid1.tenancy.oc1..aaaafakeparent"
KEY = "Kq5vQ9W0m5mX3p2b6f1oQh2wD8yS7cJ0rT4uV6xZ9aE="
BASE = "http://testserver"


def _runtime(tmp_path: Path, **overrides: Any) -> Runtime:
    settings = Settings(
        data_root=tmp_path,
        deployment=DeploymentMode.WORKSTATION,
        secret_key=KEY,
        public_base_url=BASE,
        **overrides,
    )  # type: ignore[arg-type]
    rt = build_runtime(settings)
    world = {PARENT: FakeTenancyData(PARENT, "Parent")}
    rt.control_plane.connect_parent(
        FakeClients(world, FakeOrganizations(PARENT, [])), PARENT, None, Actor("t", "admin")
    )
    return rt


def _client(rt: Runtime, base_url: str = BASE, **kw: Any) -> TestClient:
    return TestClient(create_app(rt.settings, rt), base_url=base_url, **kw)


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token in page"
    return m.group(1)


def _login(client: TestClient) -> str:
    client.post("/login/local", data={"csrf_token": _csrf(client.get("/login").text)})
    return _csrf(client.get("/admin/organization").text)


def _session_rows(rt: Runtime) -> int:
    with rt.stores.db.read() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])


# --- Host / Origin -----------------------------------------------------------------------------
def test_dns_rebinding_host_is_refused(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    evil = _client(rt, base_url="http://evil.example:8000")
    r = evil.get("/login")
    assert r.status_code == 400
    assert r.headers["x-frame-options"] == "DENY"  # security headers on refusals too
    assert evil.post("/login/local", data={"csrf_token": "x"}).status_code == 400
    assert _session_rows(rt) == 0


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "testserver"])
def test_allowed_hosts_in_workstation_mode(tmp_path: Path, host: str) -> None:
    rt = _runtime(tmp_path)
    assert _client(rt, base_url=f"http://{host}:8000").get("/login").status_code == 200


def test_trusted_hosts_setting_and_oci_mode(tmp_path: Path) -> None:
    s = Settings(
        deployment=DeploymentMode.OCI,
        public_base_url="https://osc.example.com",
        trusted_hosts=["LB.internal"],
    )
    assert s.allowed_hosts == ["lb.internal", "osc.example.com"]  # no localhost in oci mode


def test_cross_origin_post_is_refused(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    csrf = _login(client)
    url = "/admin/settings/admin-browse"
    form = {"csrf_token": csrf, "enabled": "true"}
    assert (
        client.post(url, data=form, headers={"Origin": "https://evil.example"}).status_code == 403
    )
    assert client.post(url, data=form, headers={"Origin": "null"}).status_code == 403
    ok = client.post(url, data=form, headers={"Origin": BASE}, follow_redirects=False)
    assert ok.status_code == 303


def test_oci_mode_requires_https_public_url(tmp_path: Path) -> None:
    s = Settings(data_root=tmp_path, deployment=DeploymentMode.OCI, secret_key=KEY)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="https"):
        create_app(s)


# --- sessions ------------------------------------------------------------------------------------
def test_anonymous_pages_do_not_create_sessions(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt)
    client.get("/", follow_redirects=False)
    client.get("/no-such-page")
    assert _session_rows(rt) == 0
    client.get("/login")  # the sign-in form needs a CSRF token
    assert _session_rows(rt) == 1
    with rt.stores.db.read() as conn:
        expires = conn.execute("SELECT expires_at FROM sessions").fetchone()[0]
    assert expires <= (utcnow() + timedelta(minutes=10, seconds=5)).isoformat()


def test_expired_sessions_are_pruned(tmp_path: Path) -> None:
    rt = _runtime(tmp_path)
    rt.stores.state.put_session("old", b"x", utcnow() - timedelta(minutes=1))
    _client(rt).get("/login")
    assert rt.stores.state.get_session("old") is None
    assert _session_rows(rt) == 1


def _plant_session(rt: Runtime, created: float) -> str:
    token = "planted-session-token"
    data = {
        "user": {"name": "a", "role": "admin", "via": "local"},
        "csrf": "c",
        "__created__": created,
        "generation": rt.stores.state.current_generation(),
    }
    rt.stores.state.put_session(
        hashlib.sha256(token.encode()).hexdigest(),
        rt.secrets.encrypt(json.dumps(data).encode()),
        utcnow() + timedelta(minutes=30),
    )
    return token


def test_session_absolute_lifetime(tmp_path: Path) -> None:
    rt = _runtime(tmp_path, session_max_hours=1)
    client = _client(rt)
    client.cookies.set(COOKIE, _plant_session(rt, time.time() - 1800))
    assert client.get("/admin/organization", follow_redirects=False).status_code == 200

    stale = _client(rt)
    stale.cookies.set(COOKIE, _plant_session(rt, time.time() - 7200))
    r = stale.get("/admin/organization", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


# --- errors --------------------------------------------------------------------------------------
def test_unexpected_errors_render_generic_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rt = _runtime(tmp_path)
    client = _client(rt, raise_server_exceptions=False)
    csrf = _login(client)

    def boom(*_: Any) -> None:
        raise RuntimeError("SECRET-DETAIL from deep inside")

    monkeypatch.setattr(rt, "admin_clients", lambda *_: None)
    monkeypatch.setattr(rt.control_plane, "discover_children", boom)
    r = client.post("/admin/organization/discover", data={"csrf_token": csrf})
    assert r.status_code == 500
    assert "SECRET-DETAIL" not in r.text
    assert "server log" in r.text


# --- OIDC refresh re-checks group membership -----------------------------------------------------
class _Req:
    def __init__(self, role: str) -> None:
        self.session: dict[str, Any] = {
            "user": {"name": "a", "role": role, "via": "oidc"},
            "tokens": {
                "access_token": "old",
                "refresh_token": "r",
                "expires_at": 0,  # expired -> refresh
                "token_endpoint": "https://idcs.example/oauth2/v1/token",
                "userinfo_endpoint": "https://idcs.example/oauth2/v1/userinfo",
            },
        }


def _idp(monkeypatch: pytest.MonkeyPatch, groups: object, userinfo_status: int = 200) -> list[str]:
    seen: list[str] = []

    def post(url: str, **_: Any) -> httpx.Response:
        seen.append("token")
        return httpx.Response(200, json={"access_token": "new", "expires_in": 3600})

    def get(url: str, headers: dict[str, str], **_: Any) -> httpx.Response:
        seen.append(headers["Authorization"])
        return httpx.Response(userinfo_status, json={"groups": groups})

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(httpx, "get", get)
    return seen


def test_refresh_keeps_member(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _idp(monkeypatch, ["OSC-Admins"])
    req = _Req("admin")
    assert jwt_provider_for(req, "id", "secret", Settings())() == "new"  # type: ignore[arg-type]
    assert seen == ["token", "Bearer new"]
    assert req.session["tokens"]["access_token"] == "new"


@pytest.mark.parametrize(("groups", "status"), [(["Everyone"], 200), (None, 200), ([], 500)])
def test_refresh_ends_session_when_membership_is_gone_or_unknown(
    monkeypatch: pytest.MonkeyPatch, groups: object, status: int
) -> None:
    _idp(monkeypatch, groups, status)
    req = _Req("admin")
    with pytest.raises(AuthError, match="sign in again"):
        jwt_provider_for(req, "id", "secret", Settings())()  # type: ignore[arg-type]
    assert req.session.get("__clear__") is True
    assert "user" not in req.session


def test_refresh_downgrades_role(monkeypatch: pytest.MonkeyPatch) -> None:
    _idp(monkeypatch, ["OSC-Viewers"])
    req = _Req("admin")
    with pytest.raises(AuthError, match="role changed to viewer"):
        jwt_provider_for(req, "id", "secret", Settings())()  # type: ignore[arg-type]
    assert req.session["user"]["role"] == "viewer"


# --- rate limiter memory -------------------------------------------------------------------------
def test_rate_limiter_forgets_idle_ips() -> None:
    limiter = LoginRateLimiter(max_ips=3, window_s=60)
    limiter.hits = {f"10.0.0.{i}": [time.time() - 120] for i in range(3)}

    class R:
        client = type("C", (), {"host": "10.0.0.9"})()

    limiter.check(R())  # type: ignore[arg-type]
    assert list(limiter.hits) == ["10.0.0.9"]


def test_same_site_form_posts_carry_a_real_origin(tmp_path: Path) -> None:
    """Regression: with Referrer-Policy no-referrer, browsers send Origin: null on same-site
    form posts, which the Origin check (correctly) refuses — sign-in broke."""
    rt = _runtime(tmp_path)
    client = _client(rt)
    page = client.get("/login")
    assert page.headers["referrer-policy"] == "same-origin"
    r = client.post(
        "/login/local",
        data={"csrf_token": _csrf(page.text)},
        headers={"Origin": BASE},  # what a browser sends under same-origin
        follow_redirects=False,
    )
    assert r.status_code == 303
    # a null origin (sandboxed/cross-site context) is still refused
    r = client.post("/login/local", data={"csrf_token": "x"}, headers={"Origin": "null"})
    assert r.status_code == 403
