"""Policy requirement / check models (docs/control-plane.md §5, §7)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class PolicySide(StrEnum):
    PARENT = "parent"
    CHILD = "child"


class RequirementBlock(StrEnum):
    PARENT_ACCESS = "parent_access"  # osc-parent-access
    ENDORSE = "endorse"  # parent-side, per child
    ADMIT = "admit"  # child-side, per child
    ADMIN_BROWSE = "admin_browse"  # optional, D2


class CheckStatus(StrEnum):
    DETECTED = "detected"
    BROADER = "broader"  # satisfied by a broader grant than OSC needs (warning)
    MISSING = "missing"
    UNKNOWN = "unknown"  # cannot check (no access yet, API error)


class PolicyRequirement(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str  # stable id, e.g. "parent_access:scanner-read-all"
    side: PolicySide
    block: RequirementBlock
    tenancy_ocid: str  # where the statement must be applied
    target_tenancy_ocid: str  # which tenancy this requirement is for (child for endorse/admit)
    policy_name: str  # suggested policy name
    statement: str
    why: str
    optional: bool = False


class RequirementCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    requirement_id: str
    status: CheckStatus
    detail: str = ""
    matched_policy_ocid: str | None = None
    matched_statement: str | None = None
    checked_at: datetime | None = None
