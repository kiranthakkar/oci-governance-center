"""Enrollment failures identify the failed operation without exposing credentials."""

import oci
import pytest
import requests

from oci_governance_center.auth.scanner import verify_parent
from oci_governance_center.collectors.inventory import public_error
from oci_governance_center.diagnostics import PublicFailure, verification_step


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (oci.exceptions.ServiceError(401, "NotAuthenticated", {}, "SECRET"), "HTTP 401"),
        (oci.exceptions.ServiceError(403, "Forbidden", {}, "SECRET"), "HTTP 403"),
        (oci.exceptions.ServiceError(404, "NotAuthorizedOrNotFound", {}, "SECRET"), "HTTP 404"),
        (requests.exceptions.ConnectionError("SECRET"), "Connection failed"),
        (requests.exceptions.Timeout("SECRET"), "timed out"),
        (ValueError("SECRET"), "ValueError"),
        (RuntimeError("SECRET"), "RuntimeError"),
    ],
)
def test_verification_error_names_step_without_raw_message(error, expected, caplog):
    with pytest.raises(PublicFailure) as caught:
        with verification_step("GetTenancy"):
            raise error
    message = public_error(caught.value)
    assert "GetTenancy" in message
    assert expected in message
    assert "SECRET" not in message
    assert "SECRET" not in caplog.text


def test_bad_fingerprint_has_actionable_enrollment_error(parent):
    candidate = parent.model_copy(update={"fingerprint": "00:" * 15 + "00"})
    with pytest.raises(PublicFailure) as caught:
        verify_parent(candidate)
    message = public_error(caught.value)
    assert "API-key validation" in message
    assert "does not match" in message
    assert parent.private_key.get_secret_value() not in message


def test_parent_setup_page_shows_actual_local_key_failure(settings, service, parent, key):
    from tests.unit.test_web import browser, csrf

    client = browser(settings, service)
    token = csrf(client.get("/setup"))
    unlocked = client.post(
        "/setup/unlock",
        data={
            "csrf": token,
            "password": settings.setup_password.get_secret_value(),
        },
    )
    assert unlocked.status_code == 303
    token = csrf(client.get("/setup"))
    prepared = client.post(
        "/setup/metadata",
        data={
            "csrf": token,
            "name": parent.name,
            **parent.domain.model_dump(),
        },
    )
    assert prepared.status_code == 200
    response = client.post(
        "/setup/credentials",
        data={
            "csrf": token,
            "user_ocid": parent.user_ocid,
            "fingerprint": "00:" * 15 + "00",
            "client_id": parent.client_id,
            "client_secret": parent.client_secret.get_secret_value(),
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    assert response.status_code == 400
    assert "API-key validation" in response.text
    assert "does not match" in response.text
    assert key not in response.text
    assert parent.client_secret.get_secret_value() not in response.text
    assert service.store.state()[1] is None


def test_user_read_failure_reports_get_user_step(parent, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from oci_governance_center.auth.scanner import bind_identity

    identity = Mock()
    identity.get_tenancy.return_value.data = SimpleNamespace(id=parent.domain.tenancy_ocid)
    identity.get_user.side_effect = oci.exceptions.ServiceError(403, "Forbidden", {}, "SECRET")
    monkeypatch.setattr("oci_governance_center.auth.scanner.client", lambda *_: identity)
    with pytest.raises(PublicFailure) as caught:
        bind_identity(object(), parent.domain, parent.user_ocid)
    message = public_error(caught.value)
    assert "GetUser" in message and "HTTP 403" in message
    assert "SECRET" not in message
    identity.get_domain.assert_not_called()
