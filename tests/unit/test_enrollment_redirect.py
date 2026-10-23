"""Enrollment CSP permits its OIDC redirect chain without broadening other pages."""

from oci_governance_center.diagnostics import PublicFailure
from tests.unit.test_enrollment_draft import fields, prepare
from tests.unit.test_web import browser


def targets(response):
    policy = response.headers["content-security-policy"]
    return next(
        part.strip() for part in policy.split(";") if part.strip().startswith("form-action")
    )


def test_enrollment_csp_allows_only_configured_identity_domain(settings, service, parent):
    client = browser(settings, service)
    assert targets(client.get("/setup")) == "form-action 'self'"
    prepared = prepare(client, settings, parent)
    expected = "form-action 'self' " + parent.domain.url
    assert targets(prepared) == expected
    assert targets(client.get("/setup")) == expected
    assert targets(client.get("/health")) == "form-action 'self'"
    assert targets(client.get("/setup?edit=true")) == "form-action 'self'"
    assert targets(client.get("/setup?domain=https://evil.test")) == expected
    assert "*" not in targets(prepared)


def test_failed_verification_keeps_correct_redirect_policy(
    settings, service, parent, key, monkeypatch
):
    client = browser(settings, service)
    prepared = prepare(client, settings, parent)

    def fail(*args):
        raise PublicFailure("Synthetic verification failure")

    monkeypatch.setattr(service, "candidate", fail)
    failed = client.post(
        "/setup/credentials",
        data={
            **fields(prepared, parent),
            "client_secret": parent.client_secret.get_secret_value(),
        },
        files={"private_key": ("scanner.key", key.encode())},
    )
    assert failed.status_code == 400
    assert targets(failed) == "form-action 'self' " + parent.domain.url
