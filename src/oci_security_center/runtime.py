"""Wires settings, storage, secrets and the control plane together (used by CLI and web)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import oci

from oci_security_center.auth.secrets import SecretError, SecretResolver, load_fernet
from oci_security_center.auth.signers import AuthError, build_auth
from oci_security_center.config import Settings
from oci_security_center.control_plane.service import ControlPlane
from oci_security_center.models import ConnectionMethod, ConnectionPurpose
from oci_security_center.oci_clients import ClientFactory, ClientMaker
from oci_security_center.storage.sqlite import SqliteStores, open_stores

_KEYLESS = {
    ConnectionMethod.INSTANCE_PRINCIPAL,
    ConnectionMethod.RESOURCE_PRINCIPAL,
    ConnectionMethod.CLI_PROFILE,
}


@dataclass
class Runtime:
    settings: Settings
    stores: SqliteStores
    secrets: SecretResolver
    control_plane: ControlPlane

    def clients_for(
        self, purpose: ConnectionPurpose, jwt_provider: Callable[[], str] | None = None
    ) -> ClientMaker:
        conn = self.control_plane.connection(purpose)
        if conn is None:
            raise AuthError(f"no {purpose.value} connection configured")
        return ClientFactory(build_auth(conn, self.settings, self.secrets, jwt_provider))

    def scan_clients(self) -> ClientMaker:
        return self.clients_for(ConnectionPurpose.SCAN)

    def admin_clients(self, jwt_provider: Callable[[], str] | None = None) -> ClientMaker:
        """Admin identity if usable here; otherwise fall back to the scan identity (read-only)."""
        conn = self.control_plane.connection(ConnectionPurpose.ADMIN)
        if conn is None or (
            conn.method is ConnectionMethod.OIDC_TOKEN_EXCHANGE and jwt_provider is None
        ):
            return self.scan_clients()
        return self.clients_for(ConnectionPurpose.ADMIN, jwt_provider)


def build_runtime(settings: Settings) -> Runtime:
    stores = open_stores(settings)
    holder: dict[str, Runtime] = {}

    def vault_reader(secret_ocid: str) -> str:
        """Read a Vault secret using a keyless scan identity (avoids chicken-and-egg)."""
        rt = holder["rt"]
        conn = rt.control_plane.connection(ConnectionPurpose.SCAN)
        if conn is None or conn.method not in _KEYLESS:
            raise SecretError(
                "vault: references need a keyless scan identity "
                "(instance/resource principal or CLI profile)"
            )
        auth = build_auth(conn, settings, rt.secrets)
        client = ClientFactory(auth)(oci.secrets.SecretsClient)
        from oci_security_center.auth.secrets import make_vault_reader

        return make_vault_reader(client)(secret_ocid)

    secrets = SecretResolver(load_fernet(settings), stores.state, vault_reader)
    rt = Runtime(settings, stores, secrets, ControlPlane(settings, stores))
    holder["rt"] = rt
    return rt
