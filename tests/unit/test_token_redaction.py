"""Token exchange never logs bearer tokens or client credentials (AGENTS.md §2)."""

import io
import json
import logging
from unittest.mock import Mock

from oci_governance_center.auth.scanner import Exchange
from oci_governance_center.logging import Redaction, Structured
from oci_governance_center.models import ChildCredentials
from tests.unit.test_jwt_and_analysis import signed


def test_child_exchange_logs_neither_subject_token_nor_client_secret(parent, key, monkeypatch):
    token, _ = signed(key)
    transport = Mock()
    transport.post.return_value.status_code = 200
    transport.post.return_value.json.return_value = {"token": "synthetic-upst"}
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    credentials = ChildCredentials(client_id="child-client", client_secret="never-log-this-secret")
    exchange = Exchange(parent, credentials)
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(Redaction())
    handler.setFormatter(Structured())
    root = logging.getLogger()
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.DEBUG)
    try:
        exchange._post(
            parent.domain.url,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:oci:token-type:oci-upst",
                "subject_token_type": "jwt",
                "subject_token": token,
                "public_key": "synthetic-public-key",
            },
        )
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
        exchange.close()
    logged = output.getvalue()
    assert logged, "exchange should log its safe lifecycle events"
    for line in logged.splitlines():
        json.loads(line)
    assert token not in logged
    assert "never-log-this-secret" not in logged
    assert "synthetic-public-key" not in logged


def test_former_debug_logger_and_marker_cannot_disable_token_redaction(key):
    token, _ = signed(key)
    for name in ("oci_governance_center.auth.scanner.token_exchange_debug", "other.logger"):
        record = logging.LogRecord(name, logging.WARNING, "", 0, token, (), None)
        record.ogc_explicit_token_debug = True
        assert Redaction().filter(record)
        assert token not in record.getMessage()
