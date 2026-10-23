"""Cryptographic token rejection and positive/negative governance analysis."""

import time

import pytest
from joserfc import jwk, jwt
from joserfc.errors import JoseError
from pydantic import ValidationError

from oci_governance_center.analyzers import governance
from oci_governance_center.auth.tokens import verify_jwt
from oci_governance_center.models import Batch, Finding, Record, Scope
from oci_governance_center.severity import advisor_severity, cloud_guard_severity


def signed(key, **overrides):
    private = jwk.import_key(key, "RSA")
    private.ensure_kid()
    claims = {
        "iss": "https://synthetic.example",
        "sub": "synthetic-user",
        "aud": "synthetic-client",
        "nonce": "synthetic-nonce",
        "exp": int(time.time()) + 300,
        **overrides,
    }
    token = jwt.encode({"alg": "RS256", "kid": private.kid}, claims, private)
    return token, {"keys": [private.as_dict(private=False)]}


def test_valid_jwt_signature_and_all_oidc_claims(key):
    token, keys = signed(key)
    claims = verify_jwt(
        token, keys, "https://synthetic.example", "synthetic-client", "synthetic-nonce"
    )
    assert claims["sub"] == "synthetic-user"


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://wrong.example"},
        {"aud": "other-client"},
        {"nonce": "wrong"},
        {"exp": 1},
        {"azp": "wrong"},
        {"aud": ["synthetic-client", "other"]},
    ],
)
def test_wrong_issuer_audience_nonce_expiry_or_party_rejected(key, overrides):
    token, keys = signed(key, **overrides)
    with pytest.raises((JoseError, ValueError)):
        verify_jwt(token, keys, "https://synthetic.example", "synthetic-client", "synthetic-nonce")


def test_wrong_signing_key_cannot_use_claims_to_gain_access(key):
    token, keys = signed(key)
    other = jwk.RSAKey.generate_key(2048)
    other.ensure_kid()
    keys["keys"] = [other.as_dict(private=False)]
    with pytest.raises((JoseError, ValueError)):
        verify_jwt(token, keys, "https://synthetic.example", "synthetic-client", "synthetic-nonce")


@pytest.mark.parametrize(
    "dataset,positive,negative,rule",
    [
        ("cloud_guard.configuration", {"status": "DISABLED"}, {"status": "ENABLED"}, "GOV-CG-001"),
        ("optimizer.enrollment", {"status": "DISABLED"}, {"status": "ACTIVE"}, "GOV-ADV-001"),
        (
            "optimizer.recommendations",
            {"status": "PENDING", "importance": "HIGH"},
            {"status": "IMPLEMENTED"},
            "ADV-RECOMMENDATION",
        ),
    ],
)
def test_positive_and_negative_governance_rules(domain, dataset, positive, negative, rule):
    scope = Scope(tenancy=domain.tenancy_ocid, dataset=dataset, region=domain.home_region)
    assert (
        governance(Batch(scope=scope, records=[Record(key="one", data=positive)]))[0].rule_id
        == rule
    )
    assert governance(Batch(scope=scope, records=[Record(key="one", data=negative)])) == []
    assert (
        governance(Batch(scope=scope, records=[Record(key="one", data=positive)], complete=False))
        == []
    )


@pytest.mark.parametrize(
    "override",
    [{"severity": "SEVERE"}, {"source": "unknown"}, {"status": "closed"}, {"extra": "field"}],
)
def test_finding_contract_rejects_values_outside_agents_section_5(override):
    valid = {
        "id": "synthetic",
        "tenancy": "ocid1.tenancy.oc1..aaaafakeparent",
        "scope": "{}",
        "source": "governance",
        "severity": "HIGH",
        "title": "Synthetic",
        "rule_id": "GOV-CG-001",
    }
    assert Finding.model_validate(valid).status == "open"
    with pytest.raises(ValidationError):
        Finding.model_validate({**valid, **override})


def test_unknown_source_severities_are_never_promoted():
    assert cloud_guard_severity("CRITICAL") == "CRITICAL"
    assert cloud_guard_severity("MINOR") == cloud_guard_severity("") == "INFO"
    assert advisor_severity("CRITICAL") == "HIGH"
    assert advisor_severity("MINOR") == advisor_severity("") == "INFO"


def test_problem_reclassification_keeps_native_identity(domain):
    scope = Scope(
        tenancy=domain.tenancy_ocid, dataset="cloud_guard.problems", region=domain.home_region
    )
    normal = governance(
        Batch(scope=scope, records=[Record(key="problem", data={"risk_level": "HIGH"})])
    )[0]
    zone = governance(
        Batch(
            scope=scope,
            records=[
                Record(
                    key="problem", data={"risk_level": "HIGH", "problem_category": "SECURITY_ZONE"}
                )
            ],
        )
    )[0]
    assert normal.id == zone.id and zone.source == "security_zone"
    assert normal.source == "cloud_guard" and normal.severity == "HIGH"
    assert governance(Batch(scope=scope)) == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"sub_type": "client"},
        {"tok_type": "IT"},
        {"client_name": "another-client"},
        {"aud": "https://unrelated-api.example"},
        {"exp": 1},
        {"iss": "https://wrong.example"},
    ],
)
def test_invalid_user_access_tokens_are_rejected(key, domain, overrides):
    from oci_governance_center.auth.tokens import verify_user_access_token

    claims = {
        "iss": domain.url,
        "aud": "https://identity.oraclecloud.com/",
        "sub_type": "user",
        "tok_type": "AT",
        "client_name": "synthetic-client",
        **overrides,
    }
    token, keys = signed(key, **claims)
    with pytest.raises((ValueError, JoseError)):
        verify_user_access_token(token, keys, domain.url, "synthetic-client", domain.url)


def test_user_access_token_is_bound_to_api_and_oauth_client(key, domain):
    from oci_governance_center.auth.tokens import verify_user_access_token

    token, keys = signed(
        key,
        iss=domain.url,
        aud="https://identity.oraclecloud.com/",
        sub_type="user",
        tok_type="AT",
        client_name="synthetic-client",
    )
    claims = verify_user_access_token(token, keys, domain.url, "synthetic-client", domain.url)
    assert claims["sub"] == "synthetic-user"
