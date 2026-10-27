"""Exercise HTTP enrollment, authorization, CSRF and organization-switch behavior."""

import re
import secrets
import time
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from oci_governance_center.models import Identity
from oci_governance_center.web.app import COOKIE, create_app
from tests.conftest import install


def browser(settings, service):
    return TestClient(
        create_app(settings, service), base_url=settings.public_base_url, follow_redirects=False
    )


def csrf(response):
    return re.search(r'name="csrf" value="([^"]+)"', response.text)[1]


def logged_in(client, store, groups, generation=1):
    ident = secrets.token_urlsafe(32)
    store.save_session(
        ident,
        {
            "generation": generation,
            "groups": groups,
            "grant": {"subject": "synthetic-human", "access_token": "synthetic-human-token"},
            "csrf": "synthetic-csrf",
            "created": time.time(),
            "checked": time.time(),
        },
        3600,
    )
    client.cookies.set(COOKIE, ident)


def test_setup_requires_password_and_csrf(settings, service):
    client = browser(settings, service)
    page = client.get("/setup")
    assert page.status_code == 200 and "Unlock initial setup" in page.text
    assert client.post("/setup/unlock", data={"password": "anything"}).status_code == 403
    token = csrf(page)
    rejected = client.post("/setup/unlock", data={"csrf": token, "password": "wrong"})
    assert rejected.status_code == 403
    accepted = client.post(
        "/setup/unlock",
        data={"csrf": token, "password": settings.setup_password.get_secret_value()},
    )
    assert accepted.status_code == 303
    assert "Step 1 of 3" in client.get("/setup").text
    cookie = accepted.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "default-src 'none'" in accepted.headers["content-security-policy"]


def test_setup_password_is_permanently_disabled_after_enrollment(settings, service, parent):
    install(service.store, parent)
    client = browser(settings, service)
    page = client.get("/")
    assert "Sign in with OCI" in page.text
    ident = secrets.token_urlsafe(32)
    service.store.save_session(ident, {"csrf": "synthetic-csrf", "created": time.time()}, 3600)
    client.cookies.set(COOKIE, ident)
    response = client.post(
        "/setup/unlock",
        data={"csrf": "synthetic-csrf", "password": settings.setup_password.get_secret_value()},
    )
    assert response.status_code == 403
    assert client.get("/setup").status_code == 401


def test_anonymous_and_viewer_cannot_manage_configuration(settings, service, parent, monkeypatch):
    install(service.store, parent)
    client = browser(settings, service)
    assert client.get("/configuration").status_code == 401
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    assert client.get("/").status_code == 200
    assert client.get("/data/records").status_code == 200
    assert client.get("/exports/records.json").status_code == 200
    assert client.get("/configuration").status_code == 403
    assert client.post("/configuration/replace", data={"csrf": "synthetic-csrf"}).status_code == 403
    assert client.get("/setup/package/child").status_code == 403


def test_role_downgrade_is_enforced_before_configuration(settings, service, parent, monkeypatch):
    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    assert client.get("/configuration").status_code == 403
    assert client.get("/").status_code == 200
    assert "Organization configuration" not in client.get("/").text


def test_group_removal_ends_session_and_verification_failure_denies_admin(
    settings, service, parent, monkeypatch
):
    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(side_effect=RuntimeError("network")),
    )
    assert client.get("/configuration").status_code == 503
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(side_effect=ValueError("removed")),
    )
    assert client.get("/configuration").status_code == 403
    assert "Sign in with OCI" in client.get("/").text


def test_initial_enrollment_requires_admin_oidc_before_install(
    settings, service, parent, key, monkeypatch
):
    client = browser(settings, service)
    token = csrf(client.get("/setup"))
    client.post(
        "/setup/unlock",
        data={"csrf": token, "password": settings.setup_password.get_secret_value()},
    )
    token = csrf(client.get("/setup"))
    prepared = client.post(
        "/setup/metadata", data={"csrf": token, "name": parent.name, **parent.domain.model_dump()}
    )
    assert prepared.status_code == 200 and "Download Terraform ZIP" in prepared.text
    assert service.store.state()[1] is None
    monkeypatch.setattr(
        service, "candidate", lambda owner, candidate, *_: service.store.candidate(owner, 0, parent)
    )
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.begin",
        AsyncMock(
            return_value=(
                parent.domain.url + "/authorize",
                {
                    "state": "fake-state",
                    "nonce": "fake-nonce",
                    "verifier": "fake-verifier",
                    "metadata": {},
                },
            )
        ),
    )
    response = client.post(
        "/setup/credentials",
        data={
            "csrf": token,
            "user_ocid": parent.user_ocid,
            "fingerprint": parent.fingerprint,
            "client_id": parent.client_id,
            "client_secret": parent.client_secret.get_secret_value(),
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    assert response.status_code == 303
    assert service.store.state()[1] is None
    login = client.get(response.headers["location"])
    assert login.status_code == 303
    assert "synthetic-login-secret" not in login.headers["set-cookie"]
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.finish",
        AsyncMock(
            return_value=(
                Identity(subject="fake-human", groups=frozenset({"ogc_admin"})),
                {"access_token": "fake-human-token", "subject": "fake-human"},
            )
        ),
    )
    completed = client.get("/auth/callback?state=fake-state&code=fake-code")
    assert completed.status_code == 303
    assert service.store.state()[1] == parent
    assert client.get("/").status_code == 200
    assert client.get("/auth/callback?state=fake-state&code=fake-code").status_code == 403


def test_replacement_starts_fresh_and_cancel_keeps_current_parent(
    settings, service, parent, monkeypatch
):
    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_admin"}))),
    )
    assert client.post("/configuration/replace", data={"csrf": "synthetic-csrf"}).status_code == 303
    page = client.get("/setup")
    assert "Replace the parent organization" in page.text
    assert parent.user_ocid not in page.text
    assert parent.domain.url not in page.text
    assert service.store.state()[1] == parent
    assert client.post("/configuration/cancel", data={"csrf": "synthetic-csrf"}).status_code == 303
    assert service.store.state()[1] == parent
    assert client.get("/setup").status_code == 403


def test_scanner_failure_does_not_prevent_human_login_or_history(settings, service, parent):
    generation = install(service.store, parent)
    service.store.block(generation, True)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    response = client.get("/")
    assert response.status_code == 200
    assert "Collection is stopped" in response.text


def test_invalid_metadata_and_cross_origin_are_safe(settings, service):
    client = browser(settings, service)
    token = csrf(client.get("/setup"))
    assert (
        client.post(
            "/setup/unlock",
            data={"csrf": token, "password": "synthetic-password"},
            headers={"Origin": "https://evil.test"},
        ).status_code
        == 403
    )
    assert client.get("/", headers={"Host": "evil.test"}).status_code == 400


def test_oversized_chunked_request_is_rejected(settings, service):
    client = browser(settings, service)
    client.get("/setup")
    response = client.post(
        "/setup/unlock",
        content=iter([b"x" * 70000, b"y" * 70000]),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413


def test_nonempty_inventory_and_findings_render_as_observed_data(settings, service, parent):
    from oci_governance_center.models import Batch, Record, Scope

    generation = install(service.store, parent)
    scope = Scope(
        tenancy=parent.domain.tenancy_ocid,
        dataset="identity_domains.users",
        region=parent.domain.home_region,
    )
    service.store.publish(
        generation,
        Batch(
            scope=scope,
            records=[Record(key="synthetic-user", data={"user_name": "Synthetic Reader"})],
        ),
    )
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    page = client.get("/data/records")
    assert page.status_code == 200 and "Synthetic Reader" in page.text
    assert client.get("/activity").status_code == 200
    assert parent.client_secret.get_secret_value() not in page.text


def session_rows(store):
    with store.db() as db:
        return db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]


def test_cookieless_probes_do_not_persist_sessions(settings, service, parent):
    install(service.store, parent)
    client = browser(settings, service)
    for path in ("/health", "/static/app.css", "/"):
        response = client.get(path)
        assert response.status_code == 200
        assert "set-cookie" not in response.headers
    assert session_rows(service.store) == 0


def test_page_rendering_a_form_persists_its_csrf_session(settings, service):
    client = browser(settings, service)
    page = client.get("/setup")
    assert "set-cookie" in page.headers and session_rows(service.store) == 1
    assert service.store.session(client.cookies.get(COOKIE))["csrf"] == csrf(page)


def test_setup_throttle_counts_only_failures(settings, service):
    client = browser(settings, service)
    token = csrf(client.get("/setup"))
    for _ in range(10):
        assert (
            client.post("/setup/unlock", data={"csrf": token, "password": "wrong"}).status_code
            == 403
        )
    locked = client.post(
        "/setup/unlock",
        data={"csrf": token, "password": settings.setup_password.get_secret_value()},
    )
    assert locked.status_code == 429


def test_successful_unlocks_do_not_consume_failed_attempt_budget(settings, service):
    for _ in range(12):
        client = browser(settings, service)
        token = csrf(client.get("/setup"))
        accepted = client.post(
            "/setup/unlock",
            data={"csrf": token, "password": settings.setup_password.get_secret_value()},
        )
        assert accepted.status_code == 303


def test_healthcheck_returns_plain_ok_without_login_before_and_after_enrollment(
    settings, service, parent
):
    client = browser(settings, service)
    for enrolled in (False, True):
        if enrolled:
            install(service.store, parent)
        response = client.get("/healthcheck")
        assert response.status_code == 200
        assert response.text == "OK"
        assert response.headers["content-type"].startswith("text/plain")
        assert "set-cookie" not in response.headers
    with service.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
