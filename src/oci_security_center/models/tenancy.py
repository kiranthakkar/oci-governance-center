"""Tenancy, organization and connection models (docs/control-plane.md §7)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from oci_security_center.models.common import Ocid


class OrgRole(StrEnum):
    PARENT = "PARENT"
    CHILD = "CHILD"
    STANDALONE = "STANDALONE"


class OnboardingStatus(StrEnum):
    DISCOVERED = "discovered"  # seen in the Organization, not selected
    PENDING = "pending"  # selected; policies shown, not yet verified
    VERIFIED = "verified"  # smoke test passed
    ACTIVE = "active"  # included in scans
    ERROR = "error"  # verify failed


class ConnectionMethod(StrEnum):
    OIDC_TOKEN_EXCHANGE = "oidc_token_exchange"  # noqa: S105
    CLI_PROFILE = "cli_profile"
    API_KEY = "api_key"
    INSTANCE_PRINCIPAL = "instance_principal"
    RESOURCE_PRINCIPAL = "resource_principal"


class ConnectionPurpose(StrEnum):
    ADMIN = "admin"
    SCAN = "scan"


class Tenancy(BaseModel):
    model_config = ConfigDict(frozen=True)

    ocid: Ocid
    name: str
    alias: str
    org_role: OrgRole
    home_region: str | None = None
    subscribed_regions: tuple[str, ...] = ()
    organization_id: str | None = None
    parent_tenancy_ocid: str | None = None
    onboarding_status: OnboardingStatus = OnboardingStatus.DISCOVERED
    status_detail: str | None = None
    lifecycle_state: str | None = None
    governance_status: str | None = None
    last_verified_at: datetime | None = None
    last_scanned_at: datetime | None = None


class Connection(BaseModel):
    """How OSC authenticates to the parent tenancy. Never contains secret material itself."""

    model_config = ConfigDict(frozen=True)

    id: str
    tenancy_ocid: Ocid
    method: ConnectionMethod
    purpose: ConnectionPurpose
    region: str | None = None
    # OIDC (method A)
    domain_url: str | None = None
    client_id: str | None = None
    # CLI profile (method B)
    cli_config_path: str | None = None
    cli_profile: str | None = None
    # API key (method C)
    user_ocid: str | None = None
    fingerprint: str | None = None
    # Reference to a secret: "vault:<secret_ocid>" or "local:<id>" — never the secret itself.
    secret_ref: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None
    last_tested_at: datetime | None = None
    last_test_result: str | None = None


class OrganizationTenancy(BaseModel):
    """A tenancy as reported by the OCI Organizations service."""

    model_config = ConfigDict(frozen=True)

    tenancy_ocid: Ocid
    name: str
    role: str
    lifecycle_state: str | None = None
    governance_status: str | None = None
    organization_id: str


class Organization(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    display_name: str | None
    parent_tenancy_ocid: Ocid
    lifecycle_state: str | None
    tenancies: tuple[OrganizationTenancy, ...]
