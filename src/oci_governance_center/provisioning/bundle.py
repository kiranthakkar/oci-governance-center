"""Generate official-provider Terraform JSON, console guides and Resource Manager entry points."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any, Literal
from urllib.parse import urlencode, urlsplit

from ..models import LOGIN_SCOPES

# Resource names verified against Oracle's IAM, Cloud Guard, Audit, Optimizer and Organization
# policy references; links and live-validation gates are in docs/iam/ogc-local-read.md.
RESOURCES = (
    "tenancies",
    "compartments",
    "users",
    "groups",
    "dynamic-groups",
    "policies",
    "domains",
    "cloud-guard-family",
    "audit-events",
    "optimizer-api-family",
)


def policies(parent: bool, group: str = "'Default'/'ogc_scanner'") -> list[str]:
    """Local tenancy read grants only; never Endorse/Admit or resource writes."""
    # Organization discovery and organization-wide cost (Usage API) are read from the parent only.
    resources = RESOURCES + (("organizations-family", "usage-report") if parent else ())
    return [f"Allow group {group} to read {resource} in tenancy" for resource in resources]


def terraform(kind: Literal["parent", "child"]) -> dict[str, Any]:
    """Return provider-native Terraform JSON without any private keys or client secret inputs."""
    parent = kind == "parent"
    variables: dict[str, Any] = {
        name: {"type": "string", "description": description}
        for name, description in {
            "tenancy_ocid": "Target tenancy OCID (parent or child according to this package)",
            "region": "Target tenancy home region",
            "domain_ocid": "Selected scanner identity-domain OCID (not its GUID)",
        }.items()
    }
    resources: dict[str, Any] = {}
    scanner: dict[str, Any] = {
        "idcs_endpoint": "${data.oci_identity_domain.default.url}",
        "user_name": "ogc",
        "active": True,
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    }
    if parent:
        variables.update(
            {
                "scanner_email": {"type": "string", "description": "Parent scanner recovery email"},
                "scanner_public_key": {
                    "type": "string",
                    "description": "PUBLIC RSA key only; never supply a private key",
                },
                "initial_admin_id": {
                    "type": "string",
                    "description": "Existing selected-domain human user's SCIM ID",
                },
                "callback_url": {
                    "type": "string",
                    "description": "OGC HTTPS origin followed by /auth/callback",
                },
            }
        )
        scanner.update(
            name=[{"given_name": "OGC", "family_name": "Scanner"}],
            emails=[
                {"value": "${var.scanner_email}", "type": "work", "primary": True},
                {"value": "${var.scanner_email}", "type": "recovery"},
            ],
        )
    else:
        variables.update(
            {
                "parent_issuer": {
                    "type": "string",
                    "description": "Verified parent selected-domain JWT issuer",
                },
                "parent_jwks_url": {
                    "type": "string",
                    "description": "Parent selected-domain SigningCert/jwk URL",
                },
                "parent_subject": {
                    "type": "string",
                    "default": "ogc",
                    "description": (
                        "Parent ogc user's username (the parent JWT sub), normally ogc; "
                        "not its SCIM ID or OCID, and never a wildcard"
                    ),
                },
            }
        )
        scanner["urnietfparamsscimschemasoracleidcsextensionuser_user"] = [{"service_user": True}]
        scanner["schemas"].append("urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User")
    scanner["lifecycle"] = {
        "precondition": [
            {
                "condition": (
                    "${contains(concat([var.tenancy_ocid], "
                    "[for c in data.oci_identity_compartments.tenancy.compartments : c.id]), "
                    "data.oci_identity_domain.default.compartment_id)}"
                ),
                "error_message": "Selected domain must belong to this tenancy or its compartments.",
            }
        ]
    }
    if parent:
        variables["scanner_public_key"]["validation"] = [
            {
                "condition": (
                    '${startswith(var.scanner_public_key, "-----BEGIN PUBLIC KEY-----") && '
                    '!strcontains(var.scanner_public_key, "PRIVATE KEY")}'
                ),
                "error_message": "Supply only the PEM public key, never a private key.",
            }
        ]
    else:
        variables["parent_subject"]["validation"] = [
            {
                "condition": '${can(regex("^[A-Za-z0-9._:@/-]+$", var.parent_subject))}',
                "error_message": "Supply the parent ogc username; no wildcards or quotes.",
            }
        ]
    resources["oci_identity_domains_user"] = {"scanner": scanner}
    groups = {
        "scanner": {
            "display_name": "ogc_scanner",
            "idcs_endpoint": "${data.oci_identity_domain.default.url}",
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "members": [{"type": "User", "value": "${oci_identity_domains_user.scanner.id}"}],
        }
    }
    if parent:
        for name in ("admin", "viewer"):
            groups[name] = {
                "display_name": f"ogc_{name}",
                "idcs_endpoint": "${data.oci_identity_domain.default.url}",
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            }
        groups["admin"]["members"] = [{"type": "User", "value": "${var.initial_admin_id}"}]
        resources["oci_identity_domains_api_key"] = {
            "scanner": {
                "idcs_endpoint": "${data.oci_identity_domain.default.url}",
                "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:apikey"],
                "key": "${var.scanner_public_key}",
                "user": [{"value": "${oci_identity_domains_user.scanner.id}"}],
            }
        }
        resources["oci_identity_domains_app"] = {
            "login": {
                "idcs_endpoint": "${data.oci_identity_domain.default.url}",
                "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
                "based_on_template": [{"value": "CustomWebAppTemplateId"}],
                "display_name": "OCI Governance Center",
                "active": True,
                "is_oauth_client": True,
                "client_type": "confidential",
                "allowed_grants": ["authorization_code"],
                "redirect_uris": ["${var.callback_url}"],
                "allowed_scopes": [{"fqs": scope} for scope in LOGIN_SCOPES],
            }
        }
    else:
        resources["oci_identity_domains_app"] = {
            "exchange": {
                "idcs_endpoint": "${data.oci_identity_domain.default.url}",
                "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:App"],
                "based_on_template": [{"value": "CustomWebAppTemplateId"}],
                "display_name": "OGC Parent Token Exchange",
                "active": True,
                "is_oauth_client": True,
                "client_type": "confidential",
                "allowed_grants": ["client_credentials"],
            }
        }
        resources["oci_identity_domains_identity_propagation_trust"] = {
            "parent": {
                "idcs_endpoint": "${data.oci_identity_domain.default.url}",
                "schemas": ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"],
                "name": "ogc-parent-trust",
                "description": (
                    "Allows the OGC confidential client to exchange parent tenancy "
                    "tokens for child tenancy UPST tokens"
                ),
                "oauth_clients": ["${oci_identity_domains_app.exchange.name}"],
                "subject_mapping_attribute": "userName",
                "type": "JWT",
                "active": True,
                "issuer": "${var.parent_issuer}",
                "public_key_endpoint": "${var.parent_jwks_url}",
                "subject_type": "User",
                "subject_claim_name": "sub",
                "allow_impersonation": True,
                "impersonation_service_users": [
                    {
                        "rule": "sub eq ${var.parent_subject}",
                        "value": "${oci_identity_domains_user.scanner.id}",
                    }
                ],
                "attribute_sets": ["all"],
            }
        }
    resources["oci_identity_domains_group"] = groups
    resources["oci_identity_policy"] = {
        "scanner": {
            "compartment_id": "${var.tenancy_ocid}",
            "name": "ogc-local-read",
            "description": "Local read-only OGC inventory",
            "statements": policies(parent, "id ${oci_identity_domains_group.scanner.ocid}"),
            "depends_on": ["oci_identity_domains_group.scanner"],
        }
    }
    outputs = {
        "scanner_user_ocid": {"value": "${oci_identity_domains_user.scanner.ocid}"},
        # The username is the parent JWT subject that child trust rules match; not the SCIM ID.
        "scanner_username": {"value": "${oci_identity_domains_user.scanner.user_name}"},
        "domain_ocid": {"value": "${var.domain_ocid}"},
        "domain_url": {"value": "${data.oci_identity_domain.default.url}"},
    }
    if parent:
        outputs["login_client_id"] = {"value": "${oci_identity_domains_app.login.name}"}
        outputs["scanner_fingerprint"] = {
            "value": "${oci_identity_domains_api_key.scanner.fingerprint}"
        }
    else:
        outputs["exchange_client_id"] = {"value": "${oci_identity_domains_app.exchange.name}"}
        outputs["trust_id"] = {
            "value": "${oci_identity_domains_identity_propagation_trust.parent.id}"
        }
    return {
        "terraform": {
            "required_version": ">= 1.5.0",
            "required_providers": {"oci": {"source": "oracle/oci", "version": "= 8.10.0"}},
        },
        "provider": {"oci": {"region": "${var.region}"}},
        "variable": variables,
        "data": {
            "oci_identity_domain": {"default": {"domain_id": "${var.domain_ocid}"}},
            "oci_identity_compartments": {
                "tenancy": {
                    "compartment_id": "${var.tenancy_ocid}",
                    "compartment_id_in_subtree": True,
                    "access_level": "ACCESSIBLE",
                }
            },
        },
        "resource": resources,
        "output": outputs,
    }


def manual(kind: Literal["parent", "child"]) -> str:
    """Produce equivalent human Console instructions for the same local grants and trust."""
    common = """# OCI Governance Center setup

1. Sign in to the TARGET tenancy in OCI Console using an administrator authorized to manage
   its selected identity domain and tenancy IAM policies. Confirm the tenancy OCID and home region.
2. Open Identity & Security → Domains → your selected scanner domain.
   Record its OCID, GUID, URL and region. Default and non-default domains are supported.
   The domain region may differ from the tenancy home region.
3. Open Users and create the `ogc` user described below.
4. Open Groups, create `ogc_scanner`, and add `ogc` to that group.
5. Open Identity & Security → Policies in the tenancy root and create `ogc-local-read` with
   the exact local-read statements below. Do not create Endorse/Admit statements.

"""
    if kind == "parent":
        detail = """## Parent identity and human login

6. Create `ogc` as an API-key-capable ordinary user with a recovery email. Generate an RSA
   key pair locally (at least 2048 bits). On the user's API Keys page register ONLY its public key.
   Keep the private key local until securely uploading it to OGC. Never use a stack variable.
7. Create `ogc_admin` and `ogc_viewer` in the selected domain. Add your selected human administrator
   to `ogc_admin`. Either group permits OGC login; `ogc_viewer` has read-only application access.
   Manage memberships here in OCI; OGC does not modify memberships.
8. Open Applications → Add application → Confidential application. Name it OGC Login.
   Enable Authorization Code with PKCE S256. Set the exact OGC HTTPS /auth/callback URL.
   Permit only urn:opc:idm:__myscopes__ for human login. Do not request openid, profile,
   or groups. OGC uses the returned access token; it does not require an ID token.
   Confirm the app/user can invoke Asserter; a scope does not grant roles by itself.
   Do not assign domain administrator to this runtime app. Activate it, record its client ID,
   and retrieve its client secret securely.
   OGC verifies the access token's signature, issuer, expiry, API audience, OAuth client,
   and user subject type, then POSTs to /admin/v1/Asserter using that access token as bearer
   authorization and includeMemberships=true. OGC binds the returned user to the token identity
   and checks group IDs for ogc_admin/ogc_viewer. Missing or unavailable membership denies access.
   The scanner uses urn:opc:idm:__myscopes__ only for API-key-to-parent-JWT issuance before
   exchanging that JWT for child UPST credentials. Parent JWT issuance needs no client secret;
   the child UPST exchange authenticates using its own confidential application credentials.
9. Return to OGC. Enter the scanner user OCID, fingerprint, private key, login client ID and secret.
   Verify and sign in as the selected ogc_admin to complete enrollment. The scanner does not use
   the login application's client credentials.

Terraform administrators: `terraform init`, `terraform validate`, `terraform plan`, review, then
`terraform apply`. Resource Manager uses its own authorized provider context. OIDC secrets may be
retained in Terraform state: restrict state access. Retrieve the client secret through the domain's
application page, not an ordinary stack output. Never upload Terraform state to OGC.
"""
    else:
        detail = """## Child service user and WIF trust

6. Create `ogc` as a non-interactive service user in the selected domain.
   No password and no API key.
7. Create and activate a Confidential application named OGC Parent Token Exchange using the
   Custom Web App template, OAuth client enabled, client type Confidential and Client Credentials
   grant. Record its OAuth client ID (the app's `name`, not its SCIM resource `id`).
8. Create an active JWT Identity Propagation Trust named ogc-parent-trust. Set issuer and
   publicKeyEndpoint to the parent selected domain's issuer and signing-key/JWKS URL. Set
   subjectType=User, subjectClaimName=sub and subjectMappingAttribute=userName. Set oauthClients
   to the confidential application's OAuth client ID. Enable allowImpersonation and add the
   exact `sub eq <parent ogc username>` rule (normally `sub eq ogc`, without quotes). Use the
   parent ogc user's username from the parent setup `scanner_username` output, not its SCIM ID
   or OCID.
   Target the child ogc service user's SCIM ID.
   Terraform references the application and user directly so they exist before trust creation.
   Do not use wildcard rules, trust all parent users, or configure a child API key.
9. Return to OGC Configure and enter the child scanner-domain URL and the confidential app
   client ID/secret. Retrieve the secret securely from the application configuration.
   OGC obtains a child UPST and discovers the domain identifiers, home region, and active
   service user named ogc. No user OCID needs to be copied. Accessible datasets
   start monitoring automatically; denied reads show Partial coverage.
   All identity domains are in scope.

Terraform administrators: import existing OGC resources first if present; never replace shared
users/groups without review. Run init, validate, plan and apply, or use Resource Manager in the
CHILD tenancy. The stack creates a confidential app; its generated client secret may be present
in Terraform state, so restrict state access. No client secret is exported by the stack; OGC stores
the administrator-provided child secret encrypted and uses HTTP Basic for the child exchange.
Generation/schema validation does not prove
that the tenancy accepts the end-to-end token exchange. No child API key is created.

Reference sample:
https://github.com/balajepalli84/token-exchange-tf/tree/main/Resource_Manager
"""
    statements = "\n".join(policies(kind == "parent", "id <ogc_scanner group OCID>"))
    return (
        common + detail + "\n## Local read policy\n\n"
        "Replace the group OCID placeholder with the selected domain scanner group OCID.\n"
        "Terraform resolves that group OCID automatically, including non-default domains.\n"
        "\n```text\n" + statements + "\n```\n"
    )


def bundle(kind: Literal["parent", "child"]) -> bytes:
    """Build an in-memory ZIP with no persisted exports or credential material."""
    stream = io.BytesIO()
    config = terraform(kind)
    schema = {
        "title": f"OCI Governance Center {kind} setup",
        "schemaVersion": "1.1.0",
        "version": "20261022",
        "locale": "en",
        "variables": {
            name: {
                "type": "string",
                "title": name,
                "description": item["description"],
                "required": True,
                **({"default": item["default"]} if "default" in item else {}),
            }
            for name, item in config["variable"].items()
        },
    }
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("main.tf.json", json.dumps(config, indent=2) + "\n")
        archive.writestr("schema.yaml", json.dumps(schema, indent=2) + "\n")  # JSON is valid YAML.
        archive.writestr("README.md", manual(kind))
    return stream.getvalue()


def deploy_url(package_url: str) -> str:
    """Make a deploy button URL for an operator-published immutable package, with no secrets."""
    parsed = urlsplit(package_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.fragment:
        raise ValueError("Publish the setup ZIP at an HTTPS URL before enabling the deploy button")
    return "https://cloud.oracle.com/resourcemanager/stacks/create?" + urlencode(
        {"zipUrl": package_url}
    )
