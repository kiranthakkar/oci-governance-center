"""Supported connection methods and secret-dependency rules (docs/control-plane.md §2.3, §3.1).

One place for these rules, used by the CLI, the web forms and the signer factory:

* ``workstation`` mode: scan = CLI profile or API key (instance/resource principal tolerated for
  development on an OCI host); admin = OIDC, CLI profile or API key.
* ``oci`` mode: scan = instance principal (resource principal: gated, control-plane R1);
  admin = OIDC only. CLI profiles and API keys are unsupported for both purposes.
* OIDC/UPST is interactive and never the scan identity.
* Vault (``vault:``) references are resolved with the scan identity, so they need a *keyless* scan
  identity. A Vault-backed API-key scan identity is rejected: the key can't authorize retrieval of
  itself. Checked before any connection test or destructive change.
"""

from __future__ import annotations

from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.models import Connection, ConnectionMethod, ConnectionPurpose

KEYLESS = frozenset(
    {
        ConnectionMethod.CLI_PROFILE,
        ConnectionMethod.INSTANCE_PRINCIPAL,
        ConnectionMethod.RESOURCE_PRINCIPAL,
    }
)


class ConnectionConfigError(ValueError):
    """A connection or combination of connections OSC doesn't support."""


def allowed_methods(settings: Settings) -> dict[ConnectionPurpose, list[ConnectionMethod]]:
    if settings.deployment is DeploymentMode.OCI:
        return {
            ConnectionPurpose.ADMIN: [ConnectionMethod.OIDC_TOKEN_EXCHANGE],
            ConnectionPurpose.SCAN: [
                ConnectionMethod.INSTANCE_PRINCIPAL,
                ConnectionMethod.RESOURCE_PRINCIPAL,
            ],
        }
    return {
        ConnectionPurpose.ADMIN: [
            ConnectionMethod.OIDC_TOKEN_EXCHANGE,
            ConnectionMethod.CLI_PROFILE,
            ConnectionMethod.API_KEY,
        ],
        ConnectionPurpose.SCAN: [
            ConnectionMethod.CLI_PROFILE,
            ConnectionMethod.API_KEY,
            ConnectionMethod.INSTANCE_PRINCIPAL,
            ConnectionMethod.RESOURCE_PRINCIPAL,
        ],
    }


def check_method(settings: Settings, conn: Connection) -> None:
    if conn.method not in allowed_methods(settings)[conn.purpose]:
        raise ConnectionConfigError(
            f"{conn.method.value} is not supported for the {conn.purpose.value} connection "
            f"in {settings.deployment.value} mode"
        )


def _is_vault(conn: Connection | None) -> bool:
    return bool(conn and conn.secret_ref and conn.secret_ref.startswith("vault:"))


def validate_connections(
    settings: Settings, scan: Connection | None, admin: Connection | None
) -> None:
    """Validate the scan/admin pair that *would* be in effect. Raises ConnectionConfigError."""
    for conn in (scan, admin):
        if conn is not None:
            check_method(settings, conn)
    if scan is not None and scan.method is ConnectionMethod.API_KEY and _is_vault(scan):
        raise ConnectionConfigError(
            "an API-key scan identity can't use a Vault secret for its own key; store the key "
            "locally (encrypted) or use a keyless scan identity"
        )
    if _is_vault(admin) and (scan is None or scan.method not in KEYLESS):
        raise ConnectionConfigError(
            "Vault secret references need a keyless scan identity (CLI profile, instance or "
            "resource principal) to read them; store the admin secret locally instead"
        )
