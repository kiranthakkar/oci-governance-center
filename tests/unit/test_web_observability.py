"""Actionable parser and web diagnostics exclude request secrets and raw parser errors."""

import asyncio
import logging
from unittest.mock import Mock

import pytest
import uvicorn
from fastapi.testclient import TestClient
from uvicorn.server import ServerState

from oci_governance_center.web.app import create_app
from oci_governance_center.web.observability import DiagnosticHTTPProtocol
from tests.unit.test_jwt_and_analysis import signed


@pytest.mark.parametrize(
    "packet,reason",
    [
        (b"\x16\x03\x01\x00\x10secret-tls-data\r\n\r\n", "TLS handshake"),
        (b"PROXY TCP4 1.2.3.4 5.6.7.8 123 80\r\n\r\n", "PROXY protocol"),
        (b"GET /?code=secret-code HTTP/1.1\r\n\r\n", "missing its required Host"),
        (b"GET / HTTP/1.1\r\nHost: one\r\nHost: secret-host\r\n\r\n", "Multiple Host"),
        (b"not-http secret-request-token\r\n\r\n", "Malformed HTTP request line"),
    ],
)
def test_invalid_connections_have_safe_reason(packet, reason, caplog):
    async def run():
        async def app(scope, receive, send):
            raise AssertionError("Invalid request should not reach ASGI")

        config = uvicorn.Config(app, log_config=None, access_log=False)
        protocol = DiagnosticHTTPProtocol(
            config, ServerState(), {}, _loop=asyncio.get_running_loop()
        )
        transport = Mock()
        transport.get_extra_info.side_effect = lambda name: {
            "peername": ("10.0.0.5", 1234),
            "sockname": ("10.0.0.220", 8010),
        }.get(name)
        protocol.connection_made(transport)
        protocol.data_received(packet)
        assert transport.write.called
        protocol.connection_lost(None)

    with caplog.at_level(logging.WARNING):
        asyncio.run(run())
    assert reason in caplog.text
    assert "10.0.0.5" in caplog.text
    for secret in ("secret-tls-data", "secret-code", "secret-host", "secret-request-token"):
        assert secret not in caplog.text


def test_web_logs_status_route_request_id_and_no_query_or_body_secrets(
    settings, service, key, caplog
):
    token, _ = signed(key)
    app = create_app(settings, service)
    client = TestClient(app, base_url=settings.public_base_url)
    with caplog.at_level(logging.INFO, logger="oci_governance_center.web.observability"):
        response = client.get("/healthcheck?access_token=" + token)
        rejected = client.get("/?code=secret-auth-code", headers={"Host": "wrong.example"})
    assert response.status_code == 200
    ident = response.headers["x-ogc-request-id"]
    assert ident in caplog.text and "route=/healthcheck" in caplog.text
    assert "duration_ms=" in caplog.text and "status=200" in caplog.text
    assert rejected.status_code == 400 and "expected application host" in caplog.text
    assert token not in caplog.text and "secret-auth-code" not in caplog.text


def test_unhandled_exception_is_correlated_without_logging_exception_message(
    settings, service, caplog
):
    app = create_app(settings, service)

    @app.get("/synthetic-error")
    async def broken():
        raise RuntimeError("client_secret=never-log-this")

    client = TestClient(app, base_url=settings.public_base_url)
    with caplog.at_level(logging.INFO, logger="oci_governance_center.web.observability"):
        response = client.get("/synthetic-error")
    assert response.status_code == 500
    assert response.headers["x-ogc-request-id"] in response.text
    assert response.headers["x-ogc-request-id"] in caplog.text
    assert "RuntimeError" in caplog.text and "broken" in caplog.text
    assert "never-log-this" not in caplog.text and "never-log-this" not in response.text
