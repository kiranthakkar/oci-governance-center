from __future__ import annotations

from pathlib import Path

import pytest

from oci_security_center.auth.secrets import SecretError, SecretResolver, load_fernet
from oci_security_center.auth.signers import AuthError, build_auth
from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.logging import redact, redact_mapping
from oci_security_center.models import Connection, ConnectionMethod, ConnectionPurpose
from oci_security_center.storage.sqlite import open_stores

T = "ocid1.tenancy.oc1..aaaafake0001"


def test_redact_patterns() -> None:
    text = (
        "Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl client_secret=abc123 "
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
    )
    out = redact(text)
    assert "abc123" not in out
    assert "eyJhbGciOi" not in out
    assert "MIIE" not in out
    assert redact_mapping({"refresh_token": "x", "nested": {"password": "p"}, "ok": 1}) == {
        "refresh_token": "[REDACTED]",
        "nested": {"password": "[REDACTED]"},
        "ok": 1,
    }


def test_local_secret_roundtrip_and_key_file(tmp_path: Path) -> None:
    s = Settings(data_root=tmp_path)
    stores = open_stores(s)
    resolver = SecretResolver(load_fernet(s), stores.state)
    ref = resolver.store_local("pem-contents")
    assert ref.startswith("local:")
    assert resolver.resolve(ref) == "pem-contents"
    assert (tmp_path / ".secret_key").stat().st_mode & 0o777 == 0o600
    with pytest.raises(SecretError):
        resolver.resolve("vault:ocid1.vaultsecret.oc1..x")  # no reader configured


def test_oci_mode_requires_secret_key(tmp_path: Path) -> None:
    with pytest.raises(SecretError):
        load_fernet(Settings(data_root=tmp_path, deployment=DeploymentMode.OCI))


def _conn(method: ConnectionMethod, purpose: ConnectionPurpose) -> Connection:
    return Connection(id="c", tenancy_ocid=T, method=method, purpose=purpose)


def test_auth_rules(tmp_path: Path) -> None:
    s = Settings(
        data_root=tmp_path,
        deployment=DeploymentMode.OCI,
        secret_key="Kq5vQ9W0m5mX3p2b6f1oQh2wD8yS7cJ0rT4uV6xZ9aE=",
    )  # type: ignore[arg-type]
    resolver = SecretResolver(load_fernet(s), open_stores(s).state)
    for method, purpose in (
        (ConnectionMethod.CLI_PROFILE, ConnectionPurpose.SCAN),
        (ConnectionMethod.API_KEY, ConnectionPurpose.SCAN),
        (ConnectionMethod.CLI_PROFILE, ConnectionPurpose.ADMIN),
        (ConnectionMethod.API_KEY, ConnectionPurpose.ADMIN),
    ):
        with pytest.raises(AuthError, match=r"not supported .* in oci mode"):
            build_auth(_conn(method, purpose), s, resolver)
    with pytest.raises(AuthError, match="cannot be the scan identity"):
        build_auth(_conn(ConnectionMethod.OIDC_TOKEN_EXCHANGE, ConnectionPurpose.SCAN), s, resolver)
    with pytest.raises(AuthError, match="signed-in admin"):
        build_auth(
            _conn(ConnectionMethod.OIDC_TOKEN_EXCHANGE, ConnectionPurpose.ADMIN), s, resolver
        )


# --- review fixes ------------------------------------------------------------------------------
def _cli_conn(path: Path) -> Connection:
    return Connection(
        id="c",
        tenancy_ocid=T,
        method=ConnectionMethod.CLI_PROFILE,
        purpose=ConnectionPurpose.SCAN,
        cli_config_path=str(path),
        cli_profile="DEFAULT",
    )


def test_cli_profile_errors_do_not_leak_file_contents(tmp_path: Path) -> None:
    s = Settings(data_root=tmp_path)
    resolver = SecretResolver(load_fernet(s), open_stores(s).state)
    not_config = tmp_path / "notes.txt"
    not_config.write_text("TOP-SECRET-FIRST-LINE\nmore\n")
    with pytest.raises(AuthError) as exc:
        build_auth(_cli_conn(not_config), s, resolver)
    assert "TOP-SECRET" not in str(exc.value)
    assert exc.value.__cause__ is None

    incomplete = tmp_path / "config"
    incomplete.write_text("[DEFAULT]\nuser=x\n")
    with pytest.raises(AuthError, match="incomplete"):  # was an unhandled InvalidConfig
        build_auth(_cli_conn(incomplete), s, resolver)


def test_failed_token_exchange_is_an_auth_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import oci
    from oci._vendor import requests  # what the SDK's signer actually raises

    def fail(*_: object, **__: object) -> None:
        raise requests.HTTPError("400 Client Error for url: https://idcs.example/token")

    monkeypatch.setattr(oci.auth.signers, "TokenExchangeSigner", fail)
    s = Settings(data_root=tmp_path)
    resolver = SecretResolver(load_fernet(s), open_stores(s).state)
    conn = Connection(
        id="c",
        tenancy_ocid=T,
        method=ConnectionMethod.OIDC_TOKEN_EXCHANGE,
        purpose=ConnectionPurpose.ADMIN,
        domain_url="https://idcs.example",
        client_id="app",
        secret_ref=resolver.store_local("client-secret"),
        region="us-ashburn-1",
    )
    with pytest.raises(AuthError, match="token exchange failed"):
        build_auth(conn, s, resolver, jwt_provider=lambda: "jwt")


def test_redacts_oauth_values_in_urls() -> None:
    line = '127.0.0.1 - "GET /auth/callback?code=abc123&state=st4te HTTP/1.1" 303'
    out = redact(line)
    assert "abc123" not in out
    assert "st4te" not in out
    assert "/auth/callback?code=[REDACTED]&state=[REDACTED]" in out
    assert redact("status code: 404") == "status code: 404"


# --- connection policy and secret dependencies (control-plane §2.3, §3.1) -----------------------
def test_connection_policy() -> None:
    from oci_security_center.auth.policy import ConnectionConfigError, validate_connections

    ws = Settings(deployment=DeploymentMode.WORKSTATION)

    def conn(method: ConnectionMethod, purpose: ConnectionPurpose, ref: str | None) -> Connection:
        return Connection(id="c", tenancy_ocid=T, method=method, purpose=purpose, secret_ref=ref)

    vault = "vault:ocid1.vaultsecret.oc1..aaaafake"
    api_scan_vault = conn(ConnectionMethod.API_KEY, ConnectionPurpose.SCAN, vault)
    api_scan_local = conn(ConnectionMethod.API_KEY, ConnectionPurpose.SCAN, "local:x")
    cli_scan = conn(ConnectionMethod.CLI_PROFILE, ConnectionPurpose.SCAN, None)
    oidc_vault = conn(ConnectionMethod.OIDC_TOKEN_EXCHANGE, ConnectionPurpose.ADMIN, vault)
    oidc_local = conn(ConnectionMethod.OIDC_TOKEN_EXCHANGE, ConnectionPurpose.ADMIN, "local:y")

    with pytest.raises(ConnectionConfigError, match="its own key"):
        validate_connections(ws, api_scan_vault, None)
    with pytest.raises(ConnectionConfigError, match="keyless scan identity"):
        validate_connections(ws, api_scan_local, oidc_vault)
    with pytest.raises(ConnectionConfigError, match="keyless scan identity"):
        validate_connections(ws, None, oidc_vault)
    validate_connections(ws, cli_scan, oidc_vault)
    validate_connections(ws, api_scan_local, oidc_local)

    oci_mode = Settings(deployment=DeploymentMode.OCI)
    ip_scan = conn(ConnectionMethod.INSTANCE_PRINCIPAL, ConnectionPurpose.SCAN, None)
    validate_connections(oci_mode, ip_scan, oidc_vault)
    with pytest.raises(ConnectionConfigError, match="not supported"):
        validate_connections(oci_mode, api_scan_local, None)
