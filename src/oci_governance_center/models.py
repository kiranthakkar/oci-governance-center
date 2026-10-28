"""Validated public contracts and explicit collection coverage."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints, field_validator

IDENTITY_API_SCOPE = "urn:opc:idm:__myscopes__"
LOGIN_SCOPES = (IDENTITY_API_SCOPE,)
PARENT_EXCHANGE_SCOPE = IDENTITY_API_SCOPE

Ocid = Annotated[str, StringConstraints(pattern=r"^ocid1\.[a-z_]+\.[a-z0-9-]+\..+$")]


def now() -> datetime:
    """Return aware UTC time."""
    return datetime.now(UTC)


def domain_origin(value: str) -> str:
    """Accept commercial OCI identity-domain HTTPS origins only; prevent arbitrary URL access."""
    u = urlsplit(value)
    if (
        u.scheme != "https"
        or u.port not in (None, 443)
        or u.username
        or u.password
        or u.query
        or u.fragment
        or u.path not in ("", "/")
        or not re.fullmatch(r"idcs-[a-fA-F0-9]{32}\.identity\.oraclecloud\.com", u.hostname or "")
    ):
        raise ValueError("Use the HTTPS default identity-domain URL, not an OCI Console URL")
    return f"https://{u.hostname}"


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Domain(Model):
    tenancy_ocid: Ocid
    domain_ocid: Ocid
    guid: str
    url: str
    home_region: str = Field(pattern=r"^[a-z]+-[a-z]+-\d+$")
    region: str = Field(default="", pattern=r"^(?:[a-z]+-[a-z]+-\d+)?$")

    @property
    def identity_region(self) -> str:
        """The selected domain's region, independent from the tenancy home region."""
        return self.region or self.home_region

    @field_validator("url")
    @classmethod
    def origin(cls, value: str) -> str:
        return domain_origin(value)

    @field_validator("guid")
    @classmethod
    def guid_format(cls, value: str) -> str:
        value = value.removeprefix("idcs-").replace("-", "").lower()
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ValueError("Identity-domain GUID must contain 32 hexadecimal characters")
        return value

    def check_guid(self) -> None:
        """Verify the supplied GUID matches the verified domain origin."""
        if urlsplit(self.url).hostname != f"idcs-{self.guid}.identity.oraclecloud.com":
            raise ValueError("Domain GUID and URL differ")


class Parent(Model):
    name: str = Field(min_length=1, max_length=120)
    domain: Domain
    user_ocid: Ocid
    fingerprint: str = Field(pattern=r"^(?:[0-9a-f]{2}:){15}[0-9a-f]{2}$")
    private_key: SecretStr
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: SecretStr
    # Retain the persisted field for compatibility; scanner scope is now fixed by design.
    exchange_scope: str = PARENT_EXCHANGE_SCOPE
    admin_group_id: str = ""
    viewer_group_id: str = ""

    @field_validator("exchange_scope", mode="before")
    @classmethod
    def fixed_exchange_scope(cls, value: Any) -> str:
        """Normalize legacy saved parent settings without changing their credentials."""
        return PARENT_EXCHANGE_SCOPE


class ChildCredentials(Model):
    """Child-local OAuth caller credentials; persisted only in encrypted storage."""

    client_id: str = Field(min_length=1, max_length=256)
    client_secret: SecretStr = Field(min_length=1, max_length=8192)


class Child(Model):
    ocid: Ocid
    name: str
    # Empty until Configure verifies the child's default domain; never the parent's region.
    home_region: str = ""
    domain: Domain | None = None
    user_ocid: str = ""
    status: Literal["not_configured", "active", "partial", "error", "paused", "departed"] = (
        "not_configured"
    )
    revision: int = 0
    error: str = ""


class Scope(Model):
    tenancy: str
    dataset: str
    region: str
    domain: str = ""
    compartment: str = ""

    @property
    def key(self) -> str:
        """Canonical scope identity without ambiguous concatenation."""
        return self.model_dump_json()


class Record(Model):
    key: str
    data: dict[str, Any]


class Batch(Model):
    scope: Scope
    records: list[Record] = Field(default_factory=list)
    complete: bool = True
    error: str = ""


class Identity(Model):
    subject: str
    groups: frozenset[str]

    @property
    def admin(self) -> bool:
        return "ogc_admin" in self.groups

    @property
    def allowed(self) -> bool:
        return bool(self.groups & {"ogc_admin", "ogc_viewer"})


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITIES: tuple[Severity, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
FindingSource = Literal[
    "cloud_guard",
    "security_zone",
    "advisor",
    "policy",
    "identity",
    "audit_anomaly",
    "coverage",
    "governance",
]


TriageState = Literal["ignored", "closed"]


class Triage(Model):
    """An administrator's decision on a finding, stored apart from the evaluated finding."""

    state: TriageState
    actor: str
    at: str
    reason: str = Field(default="", max_length=500)


class Finding(Model):
    """The normalized unit every pillar emits (AGENTS.md §5); timestamps are ISO-8601 UTC."""

    id: str
    tenancy: str
    scope: str
    source: FindingSource
    severity: Severity
    title: str
    rule_id: str
    description: str = ""
    resource_ocid: str = ""
    resource_type: str = ""
    compartment_ocid: str = ""
    # Pointer to the source record ("<dataset>/<record key>"), never the raw source body.
    raw_ref: str = ""
    first_seen: str = ""
    last_seen: str = ""
    resolved_at: str | None = None
    # open/resolved come from evaluation; ignored/closed are the effective status under triage.
    status: Literal["open", "resolved", "ignored", "closed"] = "open"
    triage: Triage | None = None


class ScanSettings(Model):
    """What one tenancy collects; a tenancy without saved settings uses these defaults."""

    cloud_guard: bool = True  # Cloud Guard configuration, problems and Security Zones
    cloud_advisor: bool = True
    identities: bool = True  # users, groups, dynamic groups and API keys
    policies: bool = True
    audit: bool = True
    all_domains: bool = False  # identities from every identity domain, not only the default
    cost: bool = True  # organization cost from the parent's Usage API; ignored for children
