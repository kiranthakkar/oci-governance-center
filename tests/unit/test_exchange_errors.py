"""Expose actionable OAuth categories without leaking remote bodies or credentials."""

import logging
from unittest.mock import Mock

import pytest

from oci_governance_center.auth.scanner import Exchange, ScanAccessFailure


@pytest.mark.parametrize(
    "code,description,expected",
    [
        ("invalid_grant", "No matching impersonation rule", "subject mapping or impersonation"),
        ("unauthorized_client", "Client not authorized", "client authorization"),
        ("invalid_request", "Invalid public_key format", "public key"),
        ("invalid_client", "Client authentication failed", "caller authentication"),
    ],
)
def test_exchange_error_is_actionable_and_does_not_echo_remote_secrets(
    parent, monkeypatch, caplog, code, description, expected
):
    transport = Mock()
    transport.post.return_value.status_code = 400
    transport.post.return_value.headers = {"opc-request-id": "synthetic-request/123"}
    transport.post.return_value.json.return_value = {
        "error": code,
        "error_description": description + " secret-parent-jwt-token",
        "access_token": "secret-response-token",
    }
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    exchange = Exchange(parent)
    with caplog.at_level(logging.WARNING):
        with pytest.raises(ScanAccessFailure) as caught:
            exchange._post(parent.domain, {"subject_token": "secret-request-token"})
    message = str(caught.value)
    assert code in message and expected in message
    assert "synthetic-request/123" in message
    for secret in ("secret-parent-jwt-token", "secret-response-token", "secret-request-token"):
        assert secret not in message and secret not in caplog.text
    exchange.close()


@pytest.mark.parametrize("body", [["unexpected"], {"error": "untrusted-secret-string"}, None])
def test_unknown_error_payload_is_not_displayed(parent, monkeypatch, body):
    transport = Mock()
    response = transport.post.return_value
    response.status_code = 400
    response.headers = {}
    response.json.return_value = body
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    exchange = Exchange(parent)
    with pytest.raises(ScanAccessFailure, match="no recognized OAuth error code") as caught:
        exchange._post(parent.domain, {})
    assert "untrusted-secret-string" not in str(caught.value)
    exchange.close()
