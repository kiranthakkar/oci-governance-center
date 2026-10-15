"""Signer factory: one place that turns a :class:`Connection` into OCI SDK credentials.

Methods (docs/control-plane.md §3):

* A. ``oidc_token_exchange`` — ``oci.auth.signers.TokenExchangeSigner`` (UPST from the signed-in
  admin's access token). Admin/interactive use only.
* B. ``cli_profile`` — ``~/.oci/config`` profile (API key or ``security_token_file``). Only path and
  profile name are stored. Disabled in ``oci`` deployment mode.
* C. ``api_key`` — user OCID + fingerprint + private key resolved from a secret reference.
* ``instance_principal`` / ``resource_principal`` — preferred scan identity in ``oci`` mode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import oci

from oci_security_center.auth.policy import ConnectionConfigError, check_method
from oci_security_center.auth.secrets import SecretResolver
from oci_security_center.config import Settings
from oci_security_center.logging import get_logger
from oci_security_center.models import Connection, ConnectionMethod, ConnectionPurpose

log = get_logger(__name__)


class AuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class OciAuth:
    """Everything an SDK client needs. ``signer`` is None when ``config`` alone is sufficient."""

    config: dict[str, Any]
    signer: Any | None
    tenancy_ocid: str | None
    region: str | None
    method: ConnectionMethod


def _cli_profile(conn: Connection) -> OciAuth:
    path = str(Path(conn.cli_config_path or oci.config.DEFAULT_LOCATION).expanduser())
    profile = conn.cli_profile or oci.config.DEFAULT_PROFILE
    try:
        return _load_cli_profile(conn, path, profile)
    except oci.exceptions.InvalidConfig as exc:
        # Only key names and "missing"/"malformed" — no file contents.
        raise AuthError(f"OCI CLI profile {profile!r} in {path} is incomplete: {exc}") from exc
    except Exception as exc:  # the SDK and configparser raise many types here
        # Their messages can quote lines of the file (any file the admin pointed us at), so
        # the user only gets a generic message.
        log.warning("cannot load OCI CLI profile: %s", type(exc).__name__)
        raise AuthError(
            f"cannot load OCI CLI profile {profile!r} from {path} "
            "(missing file, not an OCI config file, or unreadable key/token file)"
        ) from None


def _load_cli_profile(conn: Connection, path: str, profile: str) -> OciAuth:
    config: dict[str, Any] = oci.config.from_file(path, profile)
    if conn.region:
        config["region"] = conn.region
    token_file = config.get("security_token_file")
    if token_file:
        token = Path(token_file).expanduser().read_text().strip()
        key = oci.signer.load_private_key_from_file(config["key_file"], config.get("pass_phrase"))
        signer = oci.auth.signers.SecurityTokenSigner(token, key)
        return OciAuth(
            {"region": config["region"]},
            signer,
            config.get("tenancy"),
            config["region"],
            conn.method,
        )
    oci.config.validate_config(config)
    return OciAuth(config, None, config.get("tenancy"), config.get("region"), conn.method)


def _api_key(conn: Connection, secrets: SecretResolver) -> OciAuth:
    if not (conn.user_ocid and conn.fingerprint and conn.secret_ref and conn.region):
        raise AuthError("api_key connection needs user_ocid, fingerprint, region and secret_ref")
    pem = secrets.resolve(conn.secret_ref)
    signer = oci.signer.Signer(
        tenancy=conn.tenancy_ocid,
        user=conn.user_ocid,
        fingerprint=conn.fingerprint,
        private_key_file_location=None,
        private_key_content=pem,
    )
    return OciAuth(
        {"region": conn.region, "tenancy": conn.tenancy_ocid},
        signer,
        conn.tenancy_ocid,
        conn.region,
        conn.method,
    )


def _instance_principal(conn: Connection) -> OciAuth:
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    region = conn.region or signer.region
    return OciAuth({"region": region}, signer, signer.tenancy_id, region, conn.method)


def _resource_principal(conn: Connection) -> OciAuth:
    signer = oci.auth.signers.get_resource_principals_signer()
    region = conn.region or signer.region
    return OciAuth({"region": region}, signer, signer.tenancy_id, region, conn.method)


def _token_exchange(
    conn: Connection, secrets: SecretResolver, jwt_provider: Callable[[], str] | None
) -> OciAuth:
    if jwt_provider is None:
        raise AuthError("OIDC connection requires a signed-in admin session")
    if not (conn.domain_url and conn.client_id and conn.secret_ref and conn.region):
        raise AuthError("OIDC connection needs domain_url, client_id, client secret and region")
    client_secret = secrets.resolve(conn.secret_ref)
    try:
        # The constructor performs the exchange (access token -> UPST) straight away.
        signer = oci.auth.signers.TokenExchangeSigner(
            jwt_provider,
            conn.domain_url.rstrip("/"),
            conn.client_id,
            client_secret,
            region=conn.region,
        )
    except AuthError:
        raise
    except Exception as exc:  # requests.HTTPError, RuntimeError, ...
        log.warning("OCI token exchange failed: %s", type(exc).__name__)
        raise AuthError(
            "OCI token exchange failed — check the Identity Propagation Trust and the "
            "integrated app's client ID and secret, then sign in again"
        ) from None
    return OciAuth({"region": conn.region}, signer, conn.tenancy_ocid, conn.region, conn.method)


def build_auth(
    conn: Connection,
    settings: Settings,
    secrets: SecretResolver,
    jwt_provider: Callable[[], str] | None = None,
) -> OciAuth:
    """Create SDK credentials for ``conn``, enforcing deployment-mode rules."""
    method = conn.method
    if conn.purpose is ConnectionPurpose.SCAN and method is ConnectionMethod.OIDC_TOKEN_EXCHANGE:
        raise AuthError("OIDC/UPST is interactive and cannot be the scan identity")
    try:
        check_method(settings, conn)
    except ConnectionConfigError as exc:
        raise AuthError(str(exc)) from exc
    if method is ConnectionMethod.CLI_PROFILE:
        return _cli_profile(conn)
    if method is ConnectionMethod.API_KEY:
        return _api_key(conn, secrets)
    if method is ConnectionMethod.INSTANCE_PRINCIPAL:
        return _instance_principal(conn)
    if method is ConnectionMethod.RESOURCE_PRINCIPAL:
        return _resource_principal(conn)
    if method is ConnectionMethod.OIDC_TOKEN_EXCHANGE:
        return _token_exchange(conn, secrets, jwt_provider)
    raise AuthError(f"unsupported connection method {method}")
