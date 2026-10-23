"""Failed enrollment preserves encrypted inputs without returning secrets to the browser."""

from unittest.mock import Mock

from fastapi.testclient import TestClient

from oci_governance_center.diagnostics import PublicFailure
from oci_governance_center.web.app import COOKIE, create_app
from tests.unit.test_web import browser, csrf


def prepare(client, settings, parent):
    page = client.get("/setup")
    assert (
        client.post(
            "/setup/unlock",
            data={
                "csrf": csrf(page),
                "password": settings.setup_password.get_secret_value(),
            },
        ).status_code
        == 303
    )
    page = client.get("/setup")
    return client.post(
        "/setup/metadata",
        data={
            "csrf": csrf(page),
            "name": parent.name,
            **parent.domain.model_dump(),
        },
    )


def fields(page, parent):
    return {
        "csrf": csrf(page),
        "user_ocid": parent.user_ocid,
        "fingerprint": parent.fingerprint,
        "client_id": parent.client_id,
        "exchange_scope": parent.exchange_scope,
    }


def test_failed_credentials_survive_reload_restart_and_retry(
    settings, service, parent, key, monkeypatch
):
    client = browser(settings, service)
    page = prepare(client, settings, parent)
    candidate = Mock(side_effect=PublicFailure("Synthetic failed verification"))
    monkeypatch.setattr(service, "candidate", candidate)
    response = client.post(
        "/setup/credentials",
        data={
            **fields(page, parent),
            "client_secret": parent.client_secret.get_secret_value(),
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    assert response.status_code == 400
    assert "Synthetic failed verification" in response.text
    assert f'value="{parent.user_ocid}"' in response.text
    assert f'value="{parent.fingerprint}"' in response.text
    assert f'value="{parent.client_id}"' in response.text
    assert "Private key saved" in response.text and "Client secret saved" in response.text
    assert key not in response.text and parent.client_secret.get_secret_value() not in response.text
    assert key not in response.headers["set-cookie"]
    with service.store.db() as db:
        encrypted = db.execute(
            "SELECT data FROM sessions WHERE id=?", (client.cookies.get(COOKIE),)
        ).fetchone()[0]
    assert key.encode() not in encrypted
    assert parent.client_secret.get_secret_value().encode() not in encrypted
    # Build a fresh application/store to simulate a restart; keep only the browser cookie.
    restarted = TestClient(
        create_app(settings), base_url=settings.public_base_url, follow_redirects=False
    )
    restarted.cookies.update(client.cookies)
    page = restarted.get("/setup")
    assert "Private key saved" in page.text and parent.user_ocid in page.text
    candidate = Mock(return_value="synthetic-candidate")
    monkeypatch.setattr(restarted.app.state.service, "candidate", candidate)
    response = restarted.post("/setup/credentials", data=fields(page, parent))
    assert response.status_code == 303
    submitted = candidate.call_args.args[1]
    assert submitted.private_key.get_secret_value() == key
    assert submitted.client_secret == parent.client_secret
    assert service.store.state()[1] is None


def test_save_draft_never_verifies_and_discard_removes_secrets(
    settings, service, parent, key, monkeypatch
):
    client = browser(settings, service)
    page = prepare(client, settings, parent)
    candidate = Mock()
    monkeypatch.setattr(service, "candidate", candidate)
    response = client.post(
        "/setup/credentials",
        data={
            **fields(page, parent),
            "client_secret": parent.client_secret.get_secret_value(),
            "action": "save",
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    assert response.status_code == 200 and "draft saved" in response.text
    candidate.assert_not_called()
    assert client.post("/setup/discard", data={"csrf": csrf(response)}).status_code == 303
    page = client.get("/setup")
    assert "Parent details" in page.text and parent.user_ocid not in page.text
    saved = service.store.session(client.cookies.get(COOKIE))
    assert "setup_credentials" not in saved and "setup_metadata" not in saved


def test_changing_parent_metadata_clears_saved_credentials(settings, service, parent, key):
    client = browser(settings, service)
    page = prepare(client, settings, parent)
    client.post(
        "/setup/credentials",
        data={
            **fields(page, parent),
            "client_secret": parent.client_secret.get_secret_value(),
            "action": "save",
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    page = client.get("/setup?edit=true")
    assert f'value="{parent.domain.tenancy_ocid}"' in page.text
    response = client.post(
        "/setup/metadata",
        data={
            "csrf": csrf(page),
            "name": "Another parent",
            **parent.domain.model_dump(),
            "tenancy_ocid": "ocid1.tenancy.oc1..aaaaanother",
        },
    )
    assert response.status_code == 200
    assert "Private key saved" not in response.text
    assert "setup_credentials" not in service.store.session(client.cookies.get(COOKIE))


def test_other_browser_cannot_read_saved_enrollment(settings, service, parent):
    client = browser(settings, service)
    prepare(client, settings, parent)
    stranger = browser(settings, service)
    page = stranger.get("/setup")
    assert "Unlock initial setup" in page.text
    assert parent.domain.domain_ocid not in page.text
    assert stranger.post("/setup/discard", data={"csrf": csrf(page)}).status_code == 401
