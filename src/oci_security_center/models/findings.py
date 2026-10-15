"""Finding, scan run and record envelope models (AGENTS.md §5)."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from oci_security_center.models.common import canonical_json, content_hash, utcnow


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingSource(StrEnum):
    CLOUD_GUARD = "cloud_guard"
    SECURITY_ZONE = "security_zone"
    ADVISOR = "advisor"
    POLICY = "policy"
    AUDIT_ANOMALY = "audit_anomaly"
    COVERAGE = "coverage"  # OSC could not see something (access missing, scan incomplete)
    GOVERNANCE = "governance"  # a governance control is off or missing (e.g. Cloud Guard disabled)


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


FINDING_IDENTITY_VERSION = 1

# Identity namespace per source. Cloud Guard and Security Zone problems share one namespace so that
# re-classifying a problem updates the existing finding instead of creating a duplicate.
IDENTITY_NAMESPACE: dict[FindingSource, str] = {
    FindingSource.CLOUD_GUARD: "cloud_guard",
    FindingSource.SECURITY_ZONE: "cloud_guard",
    FindingSource.ADVISOR: "advisor",
    FindingSource.POLICY: "policy",
    FindingSource.AUDIT_ANOMALY: "audit_anomaly",
    FindingSource.COVERAGE: "coverage",
    FindingSource.GOVERNANCE: "governance",
}

# Source-specific identity components (docs/storage.md §3.4), on top of generation and tenancy.
REQUIRED_IDENTITY: dict[str, frozenset[str]] = {
    "cloud_guard": frozenset({"problem_id"}),
    "advisor": frozenset({"recommendation_id"}),
    "policy": frozenset({"rule", "policy_id", "statement_id"}),
    "coverage": frozenset({"rule", "subject", "stage"}),
    "audit_anomaly": frozenset({"rule", "subject", "occurrence"}),
    "governance": frozenset({"rule", "subject"}),
}


class Finding(BaseModel):
    """The normalized unit every pillar emits.

    ``identity`` holds the source-specific identity components; together with the organization
    generation, tenancy and source namespace they form ``finding_id``. ``scope_key`` is the
    evaluation scope: absent findings are resolved only by a complete evaluation of that scope.
    """

    model_config = ConfigDict(frozen=True)

    source: FindingSource
    tenancy_ocid: str
    rule_id: str
    severity: Severity
    title: str
    identity: dict[str, str]
    generation: int = 0
    scope_key: str = "{}"
    description: str = ""
    resource_ocid: str | None = None
    resource_type: str | None = None
    region: str | None = None
    compartment_ocid: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    resolved_at: datetime | None = None
    source_record_id: str | None = None
    occurrence_key: str | None = None
    raw_ref: str | None = None
    cis_refs: tuple[str, ...] = ()
    identity_version: int = FINDING_IDENTITY_VERSION

    @model_validator(mode="after")
    def _identity_complete(self) -> Finding:
        required = REQUIRED_IDENTITY[self.namespace]
        missing = required - {k for k, v in self.identity.items() if v}
        if missing:
            raise ValueError(f"{self.source.value} finding identity is missing {sorted(missing)}")
        return self

    @property
    def namespace(self) -> str:
        return IDENTITY_NAMESPACE[self.source]

    @property
    def finding_id(self) -> str:
        """Stable identity, hashed from structured JSON (no delimiter concatenation)."""
        doc = {
            "v": self.identity_version,
            "generation": self.generation,
            "tenancy": self.tenancy_ocid,
            "namespace": self.namespace,
            "identity": self.identity,
        }
        return "f1:" + hashlib.sha256(canonical_json(doc).encode()).hexdigest()


class Envelope(BaseModel):
    """Storage envelope: the same shape for every backend (docs/storage.md §7)."""

    model_config = ConfigDict(frozen=True)

    schema_id: str  # e.g. "identity.policies.v1"
    tenancy_ocid: str
    record_key: str  # stable id, usually the OCID
    data: dict[str, Any]
    run_id: str
    collected_at: datetime = Field(default_factory=utcnow)
    region: str | None = None
    domain: str | None = None  # identity domain OCID, for domain-scoped datasets
    compartment_ocid: str | None = None
    resource_ocid: str | None = None

    @property
    def content_hash(self) -> str:
        return content_hash(self.data)


class RunItemStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
