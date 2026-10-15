"""Read-only smoke test for a child tenancy, run as the scan identity (docs/control-plane.md §5.3).

Each step maps OCI errors to a likely onboarding cause so the admin knows what to fix.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import oci

from oci_security_center.models import utcnow
from oci_security_center.oci_clients import ClientMaker
from oci_security_center.oci_clients.allowlist import ReadOnlyViolation


@dataclass(frozen=True)
class StepResult:
    name: str
    ok: bool
    detail: str
    required: bool = True


@dataclass(frozen=True)
class VerifyResult:
    tenancy_ocid: str
    steps: tuple[StepResult, ...]
    home_region: str | None = None  # the child's, from list_region_subscriptions
    subscribed_regions: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps if s.required)

    @property
    def summary(self) -> str:
        failed = [s for s in self.steps if s.required and not s.ok]
        if not failed:
            return "all required checks passed"
        return f"{failed[0].name}: {failed[0].detail}"


def explain_service_error(exc: oci.exceptions.ServiceError) -> str:
    status, code = exc.status, exc.code
    if status == 401:
        return (
            "401 NotAuthenticated — the scan identity could not authenticate "
            "(expired key/token, wrong fingerprint, or instance principal not available)"
        )
    if status == 404 and code == "NotAuthorizedOrNotFound":
        return (
            "404 NotAuthorizedOrNotFound — usually the cross-tenancy policies are missing or "
            "don't match: check the parent Endorse statement, the child Define/Admit "
            "statements, the scanner group/dynamic-group OCID, and that aliases match"
        )
    if status == 403:
        return "403 Forbidden — the call is not permitted for the scan identity"
    if status == 429:
        return "429 TooManyRequests — throttled by OCI; retry later"
    if status >= 500:
        return f"{status} {code} — OCI service error; retry later"
    return f"{status} {code}"


def _step(name: str, fn: Callable[[], str], required: bool = True) -> StepResult:
    try:
        return StepResult(name, True, fn(), required)
    except ReadOnlyViolation:
        raise  # a code defect, never a "failed probe"
    except oci.exceptions.ServiceError as exc:
        return StepResult(name, False, explain_service_error(exc), required)
    except Exception as exc:
        return StepResult(name, False, f"{type(exc).__name__}: {exc}", required)


def verify_tenancy(clients: ClientMaker, tenancy_ocid: str, region: str | None) -> VerifyResult:
    """Run the read-only smoke test. Calls:

    ``IdentityClient.get_tenancy``, ``list_region_subscriptions``, ``list_compartments``,
    ``CloudGuardClient.get_configuration``, ``AuditClient.list_events`` (last 5 minutes).

    ``region`` is used for the identity calls (pass the child's home region when known). Cloud
    Guard and Audit are regional, so they run in the child's home region as reported by
    ``list_region_subscriptions``, falling back to ``region``.
    """
    identity: Any = clients(oci.identity.IdentityClient, region)
    steps: list[StepResult] = []
    found: dict[str, Any] = {}

    def tenancy() -> str:
        return f"tenancy name '{identity.get_tenancy(tenancy_ocid).data.name}'"

    def regions() -> str:
        subs = identity.list_region_subscriptions(tenancy_ocid).data
        found["regions"] = tuple(s.region_name for s in subs if s.status == "READY")
        found["home"] = next((s.region_name for s in subs if s.is_home_region), None)
        return f"{len(subs)} subscribed region(s), home region {found['home'] or 'unknown'}"

    def compartments() -> str:
        resp = identity.list_compartments(
            tenancy_ocid, limit=1, compartment_id_in_subtree=True, access_level="ACCESSIBLE"
        )
        return f"compartments readable ({len(resp.data)} on first page)"

    def cloud_guard() -> str:
        cg: Any = clients(oci.cloud_guard.CloudGuardClient, found.get("home") or region)
        cfg = cg.get_configuration(tenancy_ocid).data
        return f"Cloud Guard status {cfg.status}, reporting region {cfg.reporting_region}"

    def audit() -> str:
        au: Any = clients(oci.audit.AuditClient, found.get("home") or region)
        end = utcnow()
        events = au.list_events(tenancy_ocid, end - timedelta(minutes=5), end).data
        return f"{len(events)} audit event(s) in the last 5 minutes (root compartment)"

    steps.append(_step("get tenancy", tenancy))
    steps.append(_step("list region subscriptions", regions))
    steps.append(_step("list compartments", compartments))
    steps.append(_step("Cloud Guard configuration", cloud_guard, required=False))
    steps.append(_step("Audit events", audit))
    return VerifyResult(tenancy_ocid, tuple(steps), found.get("home"), found.get("regions", ()))
