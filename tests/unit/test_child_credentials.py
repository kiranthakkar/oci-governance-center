"""Child OAuth authentication is separate from parent signing, with encrypted persistence."""

import hashlib
import logging
from unittest.mock import Mock

import pytest
import requests

from oci_governance_center.auth.scanner import Exchange, ScanAccessFailure
from oci_governance_center.models import ChildCredentials
from oci_governance_center.storage import StaleWork
from tests.conftest import install


def test_upst_request_uses_child_basic_auth_and_logs_only_token_fingerprint(
    parent, monkeypatch, caplog
):
    transport = Mock()
    transport.post.return_value.status_code = 200
    transport.post.return_value.json.return_value = {"token": "synthetic-upst"}
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    credentials = ChildCredentials(client_id="child-client", client_secret="synthetic-child-secret")
    exchange = Exchange(parent, credentials)
    assertion = "synthetic-parent-bearer-token"
    with caplog.at_level(logging.INFO):
        exchange._post(
            parent.domain.url,
            {
                "requested_token_type": "urn:oci:token-type:oci-upst",
                "subject_token": assertion,
            },
        )
    auth = transport.post.call_args.kwargs["auth"]
    assert isinstance(auth, requests.auth.HTTPBasicAuth)
    assert auth.username == "child-client" and auth.password == "synthetic-child-secret"
    assert "stage=child_jwt_to_upst" in caplog.text
    assert "authentication=confidential_client_basic" in caplog.text
    assert hashlib.sha256(assertion.encode()).hexdigest()[:12] in caplog.text
    assert assertion not in caplog.text and "synthetic-child-secret" not in caplog.text
    exchange.close()


def test_child_exchange_without_credentials_does_not_fall_back_to_parent_signature(
    parent, monkeypatch
):
    transport = Mock()
    monkeypatch.setattr("oci_governance_center.auth.scanner.requests.Session", lambda: transport)
    exchange = Exchange(parent)
    with pytest.raises(ScanAccessFailure, match="client ID and secret"):
        exchange._post(parent.domain.url, {"requested_token_type": "urn:oci:token-type:oci-upst"})
    transport.post.assert_not_called()
    exchange.close()


def test_verified_child_credentials_are_encrypted_reusable_and_cleared_on_replacement(
    service, parent, child, monkeypatch
):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    exchanges = []

    def construct(parent, credentials, *args):
        exchange = Mock()
        exchange.discover_child.return_value = child.domain, child.user_ocid
        exchanges.append(credentials)
        return exchange

    monkeypatch.setattr("oci_governance_center.service.Exchange", construct)
    service.configure_child(
        child.ocid, child.domain.url, generation, "child-client", "synthetic-child-secret"
    )
    saved = service.store.child_credentials(generation, child.ocid)
    assert saved.client_id == "child-client"
    assert saved.client_secret.get_secret_value() == "synthetic-child-secret"
    with service.store.db() as db:
        encrypted = db.execute("SELECT data FROM child_credentials").fetchone()[0]
        metadata = db.execute("SELECT data FROM children").fetchone()[0]
    assert b"synthetic-child-secret" not in encrypted
    assert "synthetic-child-secret" not in metadata
    service.configure_child(child.ocid, child.domain.url, generation)
    assert exchanges[-1] == saved
    with pytest.raises(ScanAccessFailure):
        service.configure_child(child.ocid, child.domain.url, generation, "other-client", "")
    assert service.store.child_credentials(generation, child.ocid) == saved
    with pytest.raises(ScanAccessFailure):
        service.configure_child(
            child.ocid, "https://idcs-" + "c" * 32 + ".identity.oraclecloud.com", generation
        )
    assert service.store.child_credentials(generation, child.ocid) == saved
    replacement = install(service.store, parent)
    assert service.store.child_credentials(replacement, child.ocid) is None
    with pytest.raises(StaleWork):
        service.store.child_credentials(generation, child.ocid)


def test_unverified_credentials_do_not_replace_saved_credentials(
    service, parent, child, monkeypatch
):
    generation = install(service.store, parent)
    service.store.save_child(generation, child)
    exchange = Mock()
    exchange.discover_child.return_value = child.domain, child.user_ocid
    monkeypatch.setattr("oci_governance_center.service.Exchange", lambda *_: exchange)
    service.configure_child(
        child.ocid, child.domain.url, generation, "child-client", "original-secret"
    )
    exchange.discover_child.side_effect = ScanAccessFailure("synthetic exchange failure")
    with pytest.raises(ScanAccessFailure):
        service.configure_child(
            child.ocid, child.domain.url, generation, "child-client", "wrong-secret"
        )
    assert service.store.child_credentials(
        generation, child.ocid
    ).client_secret.get_secret_value() == ("original-secret")
