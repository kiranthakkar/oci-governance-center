"""Synthetic identities and ephemeral test keys; no live OCI access."""

import socket

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from oci_governance_center.auth.scanner import fingerprint
from oci_governance_center.config import Settings
from oci_governance_center.models import Child, Domain, Parent
from oci_governance_center.service import Service
from oci_governance_center.storage import Store


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("Unit tests must not make live network calls")

    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture(scope="session")
def key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@pytest.fixture
def domain():
    return Domain(
        tenancy_ocid="ocid1.tenancy.oc1..aaaafakeparent",
        domain_ocid="ocid1.domain.oc1..aaaafakedefault",
        guid="a" * 32,
        url="https://idcs-" + "a" * 32 + ".identity.oraclecloud.com",
        home_region="us-ashburn-1",
    )


@pytest.fixture
def parent(domain, key):
    return Parent(
        name="Synthetic Organization",
        domain=domain,
        user_ocid="ocid1.user.oc1..aaaafakescanner",
        fingerprint=fingerprint(key),
        private_key=SecretStr(key),
        client_id="synthetic-login-client",
        client_secret=SecretStr("synthetic-login-secret"),
        admin_group_id="fake-admin-group",
        viewer_group_id="fake-viewer-group",
    )


@pytest.fixture
def child(domain):
    child_domain = domain.model_copy(
        update={
            "tenancy_ocid": "ocid1.tenancy.oc1..aaaafakechild",
            "domain_ocid": "ocid1.domain.oc1..aaaafakechilddefault",
            "guid": "b" * 32,
            "url": "https://idcs-" + "b" * 32 + ".identity.oraclecloud.com",
        }
    )
    return Child(
        ocid=child_domain.tenancy_ocid,
        name="Synthetic Child",
        home_region="us-ashburn-1",
        domain=child_domain,
        user_ocid="ocid1.user.oc1..aaaafakechildscanner",
        status="active",
    )


@pytest.fixture
def settings(tmp_path):
    return Settings(
        data_root=tmp_path / "ogc",
        public_base_url="https://ogc.example.test",
        encryption_key=SecretStr(Fernet.generate_key().decode()),
        setup_password=SecretStr("synthetic-operator-password"),
    )


@pytest.fixture
def store(settings):
    return Store(settings.data_root, settings.encryption_key.get_secret_value())


@pytest.fixture
def service(settings, store):
    return Service(settings, store)


def install(store, parent):
    generation, _, _ = store.state()
    candidate = store.candidate("synthetic-owner", generation, parent)
    return store.install(candidate, "synthetic-owner", "synthetic-admin")
