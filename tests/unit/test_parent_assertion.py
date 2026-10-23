"""Verify signed parent assertions against the OCID-selected scanner's SCIM identity."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from oci_governance_center.auth.scanner import Exchange, ScanAccessFailure
from tests.unit.test_jwt_and_analysis import signed


@pytest.mark.parametrize(
    "claims,accepted",
    [
        ({"sub": "ogc", "sub_mappingattr": "userName", "sub_type": "user"}, True),
        ({"sub": "ogc", "user_id": "scanner-scim-id"}, True),
        ({"sub": "scanner-scim-id", "sub_mappingattr": "id"}, True),
        ({"sub": "ocid1.user.oc1..aaaafakescanner", "sub_mappingattr": "ocid"}, True),
        ({"sub": "other-user", "sub_mappingattr": "userName"}, False),
        ({"sub": "ogc", "user_id": "different-scim-id"}, False),
        ({"sub": "ogc", "sub_type": "client"}, False),
        ({"sub": "ogc", "sub_mappingattr": "email"}, False),
        ({"sub": "ogc", "sub_mappingattr": "id"}, False),
    ],
)
def test_parent_assertion_subject_formats(parent, key, monkeypatch, claims, accepted):
    token, keys = signed(key, iss=parent.domain.url, **claims)
    exchange = Exchange(parent)
    monkeypatch.setattr(exchange, "_post", lambda *args: {"access_token": token})
    exchange.http.get = Mock(
        side_effect=[
            SimpleNamespace(status_code=200, json=lambda: keys),
            SimpleNamespace(status_code=200, json=lambda: {"issuer": parent.domain.url}),
        ]
    )
    monkeypatch.setattr("oci_governance_center.auth.scanner.client", lambda *args: Mock())
    monkeypatch.setattr(
        "oci_governance_center.auth.scanner.all_items",
        lambda *args, **kwargs: [
            SimpleNamespace(id="scanner-scim-id", ocid=parent.user_ocid, user_name="ogc")
        ],
    )
    if accepted:
        assert exchange.parent_jwt() == token
    else:
        with pytest.raises(ScanAccessFailure):
            exchange.parent_jwt()
    exchange.close()
