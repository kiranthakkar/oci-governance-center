"""Secret references and resolution (AGENTS.md §2.3, docs/storage.md §6).

A connection stores only a *reference*:

* ``vault:<secret_ocid>`` — read at use time from OCI Vault (``SecretsClient.get_secret_bundle``,
  a read-only call). Preferred.
* ``local:<id>`` — Fernet-encrypted ciphertext in ``osc.db``; key from ``OSC_SECRET_KEY``.

Plaintext secrets are never written to the database, logs or the browser.
"""

from __future__ import annotations

import base64
import os
import secrets as pysecrets
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken

from oci_security_center.config import DeploymentMode, Settings
from oci_security_center.logging import get_logger

log = get_logger(__name__)


# Placeholder reference for a local secret that is stored only after validation passes.
PENDING_LOCAL_REF = "local:pending"


class SecretError(RuntimeError):
    pass


class CiphertextStore(Protocol):
    def put_secret_ciphertext(self, secret_id: str, ciphertext: bytes) -> None: ...
    def get_secret_ciphertext(self, secret_id: str) -> bytes | None: ...


def load_fernet_key(settings: Settings) -> bytes:
    """The raw local encryption key (for backup key identification and verification)."""
    load_fernet(settings)  # creates the workstation key file if needed
    if settings.secret_key is not None:
        return settings.secret_key.get_secret_value().encode()
    return (settings.data_root / ".secret_key").read_bytes().strip()


def load_fernet(settings: Settings) -> Fernet:
    """Return the local encryption key.

    ``oci`` mode: the key must be provided (``OSC_SECRET_KEY``, typically injected from Vault).
    ``workstation`` mode: if absent, a key file is generated under the data root with 0600.
    """
    if settings.secret_key is not None:
        return Fernet(settings.secret_key.get_secret_value().encode())
    if settings.deployment is DeploymentMode.OCI:
        raise SecretError("OSC_SECRET_KEY is required in oci deployment mode")
    key_file: Path = settings.data_root / ".secret_key"
    if key_file.exists():
        return Fernet(key_file.read_bytes().strip())
    settings.data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Fernet.generate_key()
    fd = os.open(key_file, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    log.warning("generated local secret key (workstation mode); back it up securely")
    return Fernet(key)


class SecretResolver:
    def __init__(
        self,
        fernet: Fernet,
        store: CiphertextStore,
        vault_reader: Callable[[str], str] | None = None,
    ) -> None:
        self._fernet = fernet
        self._store = store
        self._vault_reader = vault_reader

    def store_local(self, plaintext: str) -> str:
        secret_id = pysecrets.token_hex(16)
        self._store.put_secret_ciphertext(secret_id, self._fernet.encrypt(plaintext.encode()))
        return f"local:{secret_id}"

    def resolve(self, ref: str) -> str:
        kind, _, ident = ref.partition(":")
        if kind == "local":
            blob = self._store.get_secret_ciphertext(ident)
            if blob is None:
                raise SecretError("local secret not found")
            try:
                return self._fernet.decrypt(blob).decode()
            except InvalidToken as exc:
                raise SecretError("cannot decrypt local secret (wrong OSC_SECRET_KEY?)") from exc
        if kind == "vault":
            if self._vault_reader is None:
                raise SecretError("no OCI Vault reader configured")
            return self._vault_reader(ident)
        raise SecretError(f"unsupported secret reference type {kind!r}")

    # Session encryption reuses the same key.
    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, blob: bytes) -> bytes:
        return self._fernet.decrypt(blob)


def make_vault_reader(secrets_client: Any) -> Callable[[str], str]:
    """Build a reader for ``vault:`` refs from an ``oci.secrets.SecretsClient`` (read-only)."""

    def _read(secret_ocid: str) -> str:
        bundle = secrets_client.get_secret_bundle(secret_ocid).data
        content = bundle.secret_bundle_content.content
        return base64.b64decode(content).decode()

    return _read
