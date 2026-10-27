"""Provisioning packages never contain scanner private keys or child API credentials."""

import io
import json
import zipfile

import pytest

from oci_governance_center.provisioning.bundle import (
    bundle,
    deploy_url,
    manual,
    policies,
    terraform,
)


@pytest.mark.parametrize("kind", ["parent", "child"])
def test_bundles_parse_and_offer_equivalent_manual_read_policies(kind):
    archive = zipfile.ZipFile(io.BytesIO(bundle(kind)))
    config = json.loads(archive.read("main.tf.json"))
    guide = archive.read("README.md").decode()
    assert json.loads(archive.read("schema.yaml"))["schemaVersion"] == "1.1.0"
    assert "private_key" not in config["variable"]
    assert "client_secret" not in config["output"]
    statements = config["resource"]["oci_identity_policy"]["scanner"]["statements"]
    assert all(" to read " in s and " in tenancy" in s for s in statements)
    assert all(s in guide for s in statements)
    assert not any("Endorse" in s or "Admit" in s for s in statements)


def test_child_uses_service_user_exact_subject_and_no_api_keys():
    config = terraform("child")
    assert "oci_identity_api_key" not in config["resource"]
    app = config["resource"]["oci_identity_domains_app"]["exchange"]
    assert app["active"] and app["is_oauth_client"]
    assert app["client_type"] == "confidential"
    assert app["allowed_grants"] == ["client_credentials"]
    user = config["resource"]["oci_identity_domains_user"]["scanner"]
    assert user["urnietfparamsscimschemasoracleidcsextensionuser_user"][0]["service_user"]
    trust = config["resource"]["oci_identity_domains_identity_propagation_trust"]["parent"]
    assert trust["impersonation_service_users"][0]["rule"] == "sub eq ${var.parent_subject}"
    assert "*" not in json.dumps(trust)
    assert trust["oauth_clients"] == ["${oci_identity_domains_app.exchange.name}"]
    assert trust["subject_mapping_attribute"] == "userName"
    assert trust["subject_claim_name"] == "sub"
    assert config["output"]["exchange_client_id"]["value"] == (
        "${oci_identity_domains_app.exchange.name}"
    )
    group = config["resource"]["oci_identity_domains_group"]["scanner"]
    assert group["members"][0]["value"] == "${oci_identity_domains_user.scanner.id}"


def test_child_trust_subject_is_parent_ogc_username_not_scim_id():
    child, parent = terraform("child"), terraform("parent")
    assert child["variable"]["parent_subject"]["default"] == "ogc"
    assert "username" in child["variable"]["parent_subject"]["description"]
    assert parent["output"]["scanner_username"]["value"] == (
        "${oci_identity_domains_user.scanner.user_name}"
    )
    assert not any("scanner.id}" in output["value"] for output in parent["output"].values())
    guide = manual("child")
    assert "sub eq ogc" in guide and "not its SCIM ID" in guide
    schema = json.loads(zipfile.ZipFile(io.BytesIO(bundle("child"))).read("schema.yaml"))
    assert schema["variables"]["parent_subject"]["default"] == "ogc"


def test_parent_has_login_roles_and_public_key_only():
    config = terraform("parent")
    groups = config["resource"]["oci_identity_domains_group"]
    assert {g["display_name"] for g in groups.values()} == {
        "ogc_scanner",
        "ogc_admin",
        "ogc_viewer",
    }
    assert groups["admin"]["members"][0]["value"] == "${var.initial_admin_id}"
    assert (
        config["resource"]["oci_identity_api_key"]["scanner"]["key_value"]
        == "${var.scanner_public_key}"
    )
    assert "No child" in manual("child")


def test_deploy_button_rejects_unpublished_or_insecure_package():
    assert "zipUrl=" in deploy_url("https://example.test/releases/parent.zip")
    with pytest.raises(ValueError):
        deploy_url("http://example.test/package.zip")


def test_admin_downloads_updated_child_bundle(settings, service, parent, monkeypatch):
    from unittest.mock import AsyncMock

    from oci_governance_center.models import Identity
    from tests.conftest import install
    from tests.unit.test_web import browser, logged_in

    install(service.store, parent)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_admin"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(
            return_value=Identity(subject="synthetic-human", groups=frozenset({"ogc_admin"}))
        ),
    )
    response = client.get("/setup/package/child")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        config = json.loads(archive.read("main.tf.json"))
        trust = config["resource"]["oci_identity_domains_identity_propagation_trust"]["parent"]
        assert trust["oauth_clients"] == ["${oci_identity_domains_app.exchange.name}"]
        assert "OGC Parent Token Exchange" in archive.read("README.md").decode()


def test_only_the_parent_reads_organizations_and_cost():
    usage = "Allow group 'Default'/'ogc_scanner' to read usage-report in tenancy"
    assert usage in policies(True) and usage not in policies(False)
    assert all(" to read " in statement for statement in policies(True))
