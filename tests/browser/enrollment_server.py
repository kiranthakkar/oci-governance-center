"""Browser fixture with real enrollment routes and synthetic OCI/OIDC responses."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oci_governance_center.auth.scanner import fingerprint
from oci_governance_center.config import Settings
from oci_governance_center.service import Service
from oci_governance_center.storage import Store
from oci_governance_center.web.app import create_app


def main():
    settings = Settings()
    store = Store(settings.data_root, settings.encryption_key.get_secret_value())
    service = Service(settings, store)
    domain = "https://idcs-" + "a" * 32 + ".identity.oraclecloud.com"
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    path = Path(os.environ["OGC_BROWSER_KEY_FILE"])
    path.write_text(key)
    path.chmod(0o600)
    path.with_suffix(".json").write_text(
        json.dumps(
            {
                "name": "Synthetic organization",
                "tenancy_ocid": "ocid1.tenancy.oc1..aaaafakeparent",
                "domain_ocid": "ocid1.domain.oc1..aaaafakedefault",
                "guid": "a" * 32,
                "url": domain,
                "home_region": "us-ashburn-1",
                "user_ocid": "ocid1.user.oc1..aaaafakescanner",
                "fingerprint": fingerprint(key),
                "client_id": "synthetic-client",
                "client_secret": "synthetic-client-secret",
            }
        )
    )

    def candidate(owner, parent, generation):
        return store.candidate(owner, generation, parent)

    discovery = {"authorization_endpoint": domain + "/oauth2/v1/authorize"}
    with (
        patch.object(service, "candidate", candidate),
        patch("oci_governance_center.auth.oidc.metadata", AsyncMock(return_value=discovery)),
    ):
        uvicorn.run(
            create_app(settings, service), host="127.0.0.1", port=int(sys.argv[1]), access_log=False
        )


if __name__ == "__main__":
    main()
