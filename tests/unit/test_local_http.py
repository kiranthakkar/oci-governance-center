"""Local HTTP supports enrollment sessions without weakening remote HTTPS settings."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from oci_governance_center.config import Settings
from oci_governance_center.web.app import create_app
from tests.unit.test_web import csrf


@pytest.mark.parametrize(
    "origin", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000/"]
)
def test_local_http_origin_is_accepted(settings, origin):
    configured = Settings(**{**settings.model_dump(), "public_base_url": origin})
    assert configured.public_base_url == origin.rstrip("/")


@pytest.mark.parametrize(
    "origin",
    [
        "http://ogc.example.com",
        "http://0.0.0.0:8000",
        "http://localhost.evil.test:8000",
        "http://localhost@evil.test:8000",
        "http://localhost:8000/path",
        "http://localhost:8000?query=1",
        "http://localhost:8000#fragment",
        "https://:8443",
        "https://localhost:invalid",
        "https://localhost:99999",
    ],
)
def test_invalid_or_remote_http_origin_is_rejected(settings, origin):
    with pytest.raises(ValidationError):
        Settings(**{**settings.model_dump(), "public_base_url": origin})


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "https://ogc.example.test"])
def test_setup_session_and_logout_follow_origin_scheme(settings, origin):
    configured = Settings(**{**settings.model_dump(), "public_base_url": origin})
    secure = origin.startswith("https:")
    name = "__Host-ogc" if secure else "ogc-dev"
    with TestClient(create_app(configured), base_url=origin, follow_redirects=False) as client:
        page = client.get("/setup")
        assert page.status_code == 200
        assert page.headers["referrer-policy"] == "same-origin"
        cookie = page.headers["set-cookie"]
        assert cookie.startswith(name + "=")
        assert ("Secure" in cookie) == secure
        assert "HttpOnly" in cookie and "SameSite=lax" in cookie
        assert ("strict-transport-security" in page.headers) == secure
        accepted = client.post(
            "/setup/unlock",
            data={"csrf": csrf(page), "password": settings.setup_password.get_secret_value()},
            headers={"Origin": origin},
        )
        assert accepted.status_code == 303
        setup = client.get("/setup")
        assert "Parent details" in setup.text
        logged_out = client.post("/auth/logout", data={"csrf": csrf(setup)})
        assert logged_out.status_code == 303
        assert logged_out.headers["set-cookie"].startswith(name + "=")
        assert "Max-Age=0" in logged_out.headers["set-cookie"]
        assert ("Secure" in logged_out.headers["set-cookie"]) == secure


@pytest.mark.parametrize(
    ("configured_origin", "browser_origin"),
    [
        ("https://ogc.example.test:443", "https://ogc.example.test"),
        ("https://OGC.EXAMPLE.TEST", "https://ogc.example.test"),
        ("http://127.0.0.1:80", "http://127.0.0.1"),
    ],
)
def test_equivalent_origins_can_submit_setup(settings, configured_origin, browser_origin):
    configured = Settings(**{**settings.model_dump(), "public_base_url": configured_origin})
    with TestClient(
        create_app(configured), base_url=browser_origin, follow_redirects=False
    ) as client:
        page = client.get("/setup")
        response = client.post(
            "/setup/unlock",
            data={"csrf": csrf(page), "password": settings.setup_password.get_secret_value()},
            headers={"Origin": browser_origin},
        )
        assert response.status_code == 303


@pytest.mark.parametrize(
    "browser_origin",
    ["http://127.0.0.1:8001", "https://127.0.0.1:8000", "null", "http://evil.test"],
)
def test_origin_mismatch_explains_expected_base_url(settings, browser_origin):
    configured = Settings(**{**settings.model_dump(), "public_base_url": "http://127.0.0.1:8000"})
    with TestClient(
        create_app(configured), base_url=configured.public_base_url, follow_redirects=False
    ) as client:
        page = client.get("/setup")
        response = client.post(
            "/setup/unlock",
            data={"csrf": csrf(page), "password": settings.setup_password.get_secret_value()},
            headers={"Origin": browser_origin},
        )
        assert response.status_code == 403
        assert "OGC_PUBLIC_BASE_URL" in response.text
        assert "http://127.0.0.1:8000" in response.text


def test_public_base_url_rejects_setup_path_with_example(settings):
    with pytest.raises(ValidationError, match="without a path"):
        Settings(**{**settings.model_dump(), "public_base_url": "http://127.0.0.1:8000/setup"})
