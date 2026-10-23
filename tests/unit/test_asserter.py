"""Asserter membership is bound to verified access-token identity and persisted group IDs."""

import asyncio
import json
import time

import httpx
import pytest

from oci_governance_center.auth import oidc


def grant(**changes):
    return {
        "access_token": "synthetic-human-access-token",
        "subject": "synthetic-human",
        "assertion_attribute": "id",
        "assertion_value": "synthetic-human-guid",
        "access_token_expires_at": time.time() + 300,
        **changes,
    }


def configure(parent, monkeypatch, response):
    expected = parent.model_copy(
        update={"admin_group_id": "synthetic-admin", "viewer_group_id": "synthetic-viewer"}
    )
    calls = []

    def handle(request):
        calls.append(request)
        assert request.method == "POST"
        assert str(request.url).startswith(parent.domain.url + "/admin/v1/Asserter?")
        assert request.headers["Authorization"] == "Bearer synthetic-human-access-token"
        assert request.url.params["attributes"] == "id,userName,ocid,type,groups"
        payload = json.loads(request.content)
        assert payload["includeMemberships"] is True
        assert payload["schemas"] == ["urn:ietf:params:scim:schemas:oracle:idcs:Asserter"]
        assert payload["subjectType"] == "user"
        assert payload["mappingAttribute"] == "id"
        assert payload["mappingAttributeValue"] == "synthetic-human-guid"
        assert "client_secret" not in payload and "password" not in payload
        return httpx.Response(200, json=response)

    original = httpx.AsyncClient
    monkeypatch.setattr(
        oidc.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(handle), **kw),
    )
    return expected, calls


@pytest.mark.parametrize("group,admin", [("synthetic-admin", True), ("synthetic-viewer", False)])
def test_asserter_groups_allow_correct_application_role(parent, monkeypatch, group, admin):
    expected, calls = configure(
        parent,
        monkeypatch,
        {
            "id": "synthetic-human-guid",
            "userName": "synthetic-human",
            "type": "User",
            "groups": [{"value": group, "display": "Human-readable group name"}],
        },
    )
    identity = asyncio.run(oidc.membership(expected, grant()))
    assert identity.allowed and identity.admin == admin
    assert len(calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"id": "wrong-guid", "groups": [{"value": "synthetic-admin"}]},
        {"id": "synthetic-human-guid", "type": "App", "groups": [{"value": "synthetic-admin"}]},
        {"id": "synthetic-human-guid", "groups": []},
        {"id": "synthetic-human-guid", "groups": [{"value": "wrong", "display": "ogc_admin"}]},
        {"id": "synthetic-human-guid", "groups": "ogc_admin"},
        {"id": "synthetic-human-guid"},
    ],
)
def test_asserter_wrong_identity_or_missing_membership_denies_access(parent, monkeypatch, response):
    expected, _ = configure(parent, monkeypatch, response)
    with pytest.raises(ValueError):
        asyncio.run(oidc.membership(expected, grant()))


@pytest.mark.parametrize(
    "saved",
    [
        {"subject": "synthetic-human", "id_token": "old-human-id-token"},
        grant(access_token_expires_at=1),
    ],
)
def test_missing_or_expired_identity_token_requires_fresh_login(parent, saved):
    with pytest.raises(ValueError, match="sign in again"):
        asyncio.run(oidc.membership(parent, saved))


def test_username_assertion_binds_user_case_insensitively(parent, monkeypatch):
    expected = parent.model_copy(update={"admin_group_id": "synthetic-admin"})
    original = httpx.AsyncClient

    def response(request):
        payload = json.loads(request.content)
        assert payload["mappingAttribute"] == "userName"
        assert payload["mappingAttributeValue"] == "Synthetic-Human"
        return httpx.Response(
            200,
            json={
                "id": "synthetic-guid",
                "userName": "synthetic-human",
                "groups": [{"value": "synthetic-admin"}],
            },
        )

    monkeypatch.setattr(
        oidc.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(response), **kw),
    )
    identity = asyncio.run(
        oidc.membership(
            expected,
            grant(
                assertion_attribute="userName",
                assertion_value="Synthetic-Human",
            ),
        )
    )
    assert identity.admin


@pytest.mark.parametrize("status", [401, 403])
def test_asserter_denial_does_not_fall_back_to_other_credentials(parent, monkeypatch, status):
    original = httpx.AsyncClient
    calls = []

    def response(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer synthetic-human-access-token"
        return httpx.Response(status, json={"detail": "DO-NOT-LOG"})

    monkeypatch.setattr(
        oidc.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(response), **kw),
    )
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        asyncio.run(oidc.membership(parent, grant()))
    assert len(calls) == 1
