"""Tier-one per-scope inventory; never persist raw SDK responses."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from datetime import datetime
from functools import partial
from typing import Any

import oci

from ..diagnostics import PublicFailure, verification_step
from ..models import Batch, Child, Domain, Record, ScanSettings, Scope, domain_origin
from ..oci_clients import all_items, client

MESSAGE_LIMIT = 300


def oci_message(value: Any) -> str:
    """OCI's short error explanation, made safe for storage and display.

    Control characters are removed, whitespace collapsed, bearer tokens, JWTs and key blocks
    redacted, and the text bounded. Templates HTML-escape it on display.
    """
    if not isinstance(value, str):
        return ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    text = re.sub(
        r"-----BEGIN[^-]*-----.*?(-----END[^-]*-----|$)", "[REDACTED KEY]", text, flags=re.S
    )
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "[REDACTED TOKEN]", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+\S+", r"\1 [REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[: MESSAGE_LIMIT - 1] + "…" if len(text) > MESSAGE_LIMIT else text


def public_error(error: Exception) -> str:
    """Return a safe, specific error: status, code, operation, OCI's message and request ID."""
    if isinstance(error, PublicFailure):
        return str(error)
    if isinstance(error, oci.exceptions.ServiceError):
        # Codes, operation names and request IDs are validated tokens. OCI's message is the
        # service's short explanation (for example which parameter is invalid), sanitized above;
        # no other part of the response body is kept. Oracle support can trace the request ID.
        code = getattr(error, "code", None)
        operation = getattr(error, "operation_name", None)
        request_id = getattr(error, "request_id", None)
        detail = (
            f" {code}"
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", code)
            else ""
        )
        during = (
            f" in {operation}"
            if isinstance(operation, str) and re.fullmatch(r"[A-Za-z_]{1,64}", operation)
            else ""
        )
        message = oci_message(getattr(error, "message", None))
        explanation = f" OCI says: {message}" + ("" if message.endswith((".", "…")) else ".")
        reference = (
            f" Request ID: {request_id}."
            if isinstance(request_id, str) and re.fullmatch(r"[A-Za-z0-9/._:-]{1,200}", request_id)
            else ""
        )
        return (
            f"OCI read failed (HTTP {error.status}{detail}){during}."
            + (explanation if message else "")
            + f" Check local grants and service availability.{reference}"
        )
    return "Collection could not complete; check connectivity, domain setup and access"


def pick(obj: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    """Project reviewed scalar fields only; SDK attributes outside this list are discarded."""
    result: dict[str, Any] = {}
    for field in fields:
        value = getattr(obj, field, None)
        if isinstance(value, datetime):
            result[field] = value.isoformat()
        elif value is None or isinstance(value, (str, int, float, bool)):
            result[field] = value
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            result[field] = value
    return result


def records(values: list[Any], fields: tuple[str, ...], key: str = "id") -> list[Record]:
    """Convert SDK records to an explicit normalized projection."""
    return [Record(key=str(getattr(v, key)), data=pick(v, fields)) for v in values]


def read_records(
    method: Callable[..., Any], fields: tuple[str, ...], *args: Any, **kwargs: Any
) -> list[Record]:
    """Read and project a bound SDK operation, suitable for immediate scoped attempts."""
    return records(all_items(method, *args, **kwargs), fields)


def attempt(scope: Scope, read: Callable[[], list[Record]]) -> Batch:
    """Turn a failed source into explicit coverage without a partial snapshot commit."""
    try:
        return Batch(scope=scope, records=read())
    except Exception as error:
        return Batch(scope=scope, complete=False, error=public_error(error))


logger = logging.getLogger(__name__)

# SCIM extension attributes for MFA, federation, service-user and sign-in state (no credentials).
USER_ATTRIBUTES = ",".join(
    (
        "id",
        "ocid",
        "userName",
        "active",
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User:mfaStatus",
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User:isFederatedUser",
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User:serviceUser",
        "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User:lastSuccessfulLoginDate",
    )
)


def read_users(domains: Any) -> list[Record]:
    """List one domain's users with MFA status, federation and last sign-in; requires read users."""
    normalized: list[Record] = []
    for user in all_items(domains.list_users, attributes=USER_ATTRIBUTES):
        mfa = getattr(user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user", None)
        kind = getattr(user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user", None)
        state = getattr(
            user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user", None
        )
        normalized.append(
            Record(
                key=str(user.id),
                data={
                    **pick(user, ("id", "ocid", "user_name", "active")),
                    "mfa_status": getattr(mfa, "mfa_status", None),
                    "federated": getattr(kind, "is_federated_user", None),
                    "service_user": getattr(kind, "service_user", None),
                    "last_successful_login": getattr(state, "last_successful_login_date", None),
                },
            )
        )
    # Counts only (no identifiers) so live acceptance can confirm the attributes are returned.
    logger.info(
        "Identity-domain users read: total=%s, mfa_status_reported=%s, sign_in_reported=%s",
        len(normalized),
        sum(r.data["mfa_status"] is not None for r in normalized),
        sum(r.data["last_successful_login"] is not None for r in normalized),
    )
    return normalized


def read_api_keys(domains: Any) -> list[Record]:
    """List API-key metadata (owner, created); key material and fingerprints are never kept."""
    normalized: list[Record] = []
    # No attribute list: `meta` (creation time) and `user` are returned by default, and OCI
    # rejected the explicit `id,ocid,user,meta` list with HTTP 400 in live testing (2026-10-22).
    # The default response also carries the public key and fingerprint; they are dropped here.
    for key in all_items(domains.list_api_keys):
        owner = getattr(key, "user", None)
        meta = getattr(key, "meta", None)
        normalized.append(
            Record(
                key=str(key.id),
                data={
                    "id": key.id,
                    "ocid": getattr(key, "ocid", None),
                    "user_id": getattr(owner, "value", None),
                    "user_ocid": getattr(owner, "ocid", None),
                    "created": getattr(meta, "created", None),
                },
            )
        )
    logger.info(
        "Identity-domain API keys read: total=%s, with_owner=%s",
        len(normalized),
        sum(r.data["user_id"] is not None for r in normalized),
    )
    return normalized


def discover(signer: Any, domain: Domain) -> list[Child]:
    """List organization children in parent home region; requires read organizations-family."""
    with verification_step("organization client initialization"):
        org = client("organization", signer, domain.home_region)
    with verification_step("ListOrganizations (parent organization discovery)"):
        organizations = all_items(org.list_organizations, domain.tenancy_ocid)
    if not organizations:
        raise PublicFailure("No organization is visible; check organizations-family read access.")
    # ListOrganizations returns organizations associated with the caller. The organization
    # resource's compartment_id identifies its owning tenancy. Do not require a PARENT row
    # in ListOrganizationTenancies: parent presence there is not ownership evidence we need.
    owned = [o for o in organizations if o.compartment_id == domain.tenancy_ocid]
    if not owned:
        raise PublicFailure(
            "Organization ownership could not be verified: no returned organization has the "
            "enrolled tenancy as its owning tenancy. Check the parent OCID, home region, "
            "and organization read access."
        )
    if len(owned) != 1:
        raise PublicFailure(
            "Multiple organizations report this owning tenancy; selection is ambiguous."
        )
    organization = owned[0]
    with verification_step("ListOrganizationTenancies (organization membership discovery)"):
        members = all_items(org.list_organization_tenancies, organization.id)
    current = [m for m in members if m.lifecycle_state != "DELETED" and m.time_left is None]
    if any(
        (m.role == "PARENT" and m.tenancy_id != domain.tenancy_ocid)
        or (m.role == "CHILD" and m.tenancy_id == domain.tenancy_ocid)
        for m in current
    ):
        raise PublicFailure(
            "Organization ownership and current tenancy roles conflict; parent identity "
            "cannot be verified from this response."
        )
    # Organization listings carry no child home region, and the parent's region must never stand
    # in for it. It stays unknown until Configure verifies the child's selected domain.
    return [
        Child(ocid=m.tenancy_id, name=m.name or m.tenancy_id)
        for m in current
        if m.role == "CHILD" and m.tenancy_id != domain.tenancy_ocid
    ]


def is_selected(record: Record, domain: Domain) -> bool:
    """Whether the record is the selected scanner domain, regardless of domain type."""
    return record.key == domain.domain_ocid


class Trace:
    """Log one tenancy's collection phases: started, then completed with any coverage gaps.

    Messages name the tenancy and phase, plus each incomplete dataset with its sanitized error;
    never identifiers, records or response bodies.
    """

    def __init__(self, tenancy: str = "") -> None:
        self.tenancy = tenancy
        self.current = ""
        self.gaps = 0

    def start(self, phase: str) -> None:
        self.finish()
        self.current, self.gaps = phase, 0
        logger.info("tenancy: %s %s scan started", self.tenancy, phase)

    def seen(self, batch: Batch) -> Batch:
        if not batch.complete:
            self.gaps += 1
            # batch.error is the sanitized public_error text, safe for logs and the UI.
            logger.warning(
                "tenancy: %s %s scan: %s incomplete: %s",
                self.tenancy,
                self.current,
                batch.scope.dataset,
                batch.error,
            )
        return batch

    def finish(self) -> None:
        if self.current:
            outcome = (
                f"completed with {self.gaps} incomplete scope{'s' if self.gaps != 1 else ''}"
                " (see Coverage)"
                if self.gaps
                else "completed"
            )
            logger.info("tenancy: %s %s scan %s", self.tenancy, self.current, outcome)
        self.current = ""

    def progress(self, detail: str) -> None:
        """Report progress inside a long phase (for example hourly Audit history)."""
        logger.info("tenancy: %s %s scan: %s", self.tenancy, self.current, detail)

    def fail(self, outcome: str = "failed") -> None:
        if self.current:
            logger.warning("tenancy: %s %s scan %s", self.tenancy, self.current, outcome)
        self.current = ""


def inventory(
    signer: Any,
    domain: Domain,
    family: str = "all",
    settings: ScanSettings | None = None,
    trace: Trace | None = None,
) -> Iterator[Batch]:
    """Read IAM, governance and domain inventory using local tenancy-scoped read permissions.

    Datasets disabled in the tenancy's scan settings are not read and yield no batch.
    """
    settings = settings or ScanSettings()
    trace = trace or Trace()
    tenancy, region = domain.tenancy_ocid, domain.home_region
    identity = client("identity", signer, region)
    trace.start("Compartment")
    compartments_scope = Scope(tenancy=tenancy, dataset="identity.compartments", region=region)
    compartments = attempt(
        compartments_scope,
        lambda: records(
            all_items(
                identity.list_compartments,
                tenancy,
                compartment_id_in_subtree=True,
                access_level="ACCESSIBLE",
            ),
            ("id", "compartment_id", "name", "lifecycle_state", "time_created"),
        ),
    )
    # This prerequisite is fetched for governance and audit scoping too. Failure is visible and
    # no tenancy-wide dataset is represented as complete when compartments are unknown.
    if not compartments.complete:
        yield compartments
        return
    compartment_ids = [tenancy] + [
        r.key for r in compartments.records if r.data.get("lifecycle_state") == "ACTIVE"
    ]
    if family in {"all", "identity"}:
        yield compartments
        yield attempt(
            Scope(tenancy=tenancy, dataset="identity.regions", region=region),
            lambda: records(
                all_items(identity.list_region_subscriptions, tenancy),
                ("region_name", "region_key", "status", "is_home_region"),
                "region_name",
            ),
        )
        if settings.policies:
            trace.start("IAM policy")
            for compartment in compartment_ids:
                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity.policies",
                        region=region,
                        compartment=compartment,
                    ),
                    partial(
                        read_records,
                        identity.list_policies,
                        (
                            "id",
                            "compartment_id",
                            "name",
                            "statements",
                            "lifecycle_state",
                            "time_created",
                        ),
                        compartment,
                    ),
                )
        trace.start("Identity")
        for compartment in compartment_ids:
            domain_batch = attempt(
                Scope(
                    tenancy=tenancy,
                    dataset="identity.domains",
                    region=region,
                    compartment=compartment,
                ),
                partial(
                    read_records,
                    identity.list_domains,
                    (
                        "id",
                        "compartment_id",
                        "display_name",
                        "url",
                        "home_region",
                        "type",
                        "lifecycle_state",
                    ),
                    compartment,
                ),
            )
            yield domain_batch
            if not domain_batch.complete:
                continue
            for record in domain_batch.records:
                if record.data.get("lifecycle_state") != "ACTIVE":
                    continue
                # Only the selected scanner domain is read unless all domains are enabled; skipped
                # domains are not collected, which analysis treats as unknown, never empty.
                if not settings.identities or not (
                    settings.all_domains or is_selected(record, domain)
                ):
                    continue
                domain_region = str(record.data.get("home_region") or domain.identity_region)
                try:
                    endpoint = domain_origin(str(record.data["url"]))
                    domains = client("domains", signer, domain_region, endpoint)
                except ValueError:
                    yield Batch(
                        scope=Scope(
                            tenancy=tenancy,
                            dataset="identity_domains.users",
                            region=domain_region,
                            domain=record.key,
                        ),
                        complete=False,
                        error="Domain endpoint is unsupported",
                    )
                    continue
                users = attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity_domains.users",
                        region=domain_region,
                        domain=record.key,
                    ),
                    partial(read_users, domains),
                )
                yield users

                def read_groups(d: Any = domains) -> list[Record]:
                    groups = all_items(d.list_groups, attributes="id,ocid,displayName,members")
                    normalized: list[Record] = []
                    for group in groups:
                        members = [
                            pick(m, ("value", "ocid", "type")) for m in (group.members or [])
                        ]
                        # Group member truncation limits are a live capability gate. Never turn a
                        # suspicious boundary-sized response into proof of complete membership.
                        if len(members) >= 1000:
                            raise ValueError("Large-group membership completeness is unverified")
                        normalized.append(
                            Record(
                                key=group.id,
                                data={
                                    **pick(group, ("id", "ocid", "display_name")),
                                    "members": members,
                                },
                            )
                        )
                    return normalized

                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity_domains.groups",
                        region=domain_region,
                        domain=record.key,
                    ),
                    read_groups,
                )
                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity_domains.dynamic_groups",
                        region=domain_region,
                        domain=record.key,
                    ),
                    partial(
                        read_records,
                        domains.list_dynamic_resource_groups,
                        ("id", "ocid", "display_name", "matching_rule"),
                        attributes="id,ocid,displayName,matchingRule",
                    ),
                )
                # Whether `read users` permits listing domain API keys is a live gate; a denial
                # is a coverage gap, never proof that users have no keys.
                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity_domains.api_keys",
                        region=domain_region,
                        domain=record.key,
                    ),
                    partial(read_api_keys, domains),
                )
    if family not in {"all", "governance"}:
        return
    if settings.cloud_guard:
        trace.start("Cloud Guard")
        guard = client("guard", signer, region)
        configuration = attempt(
            Scope(tenancy=tenancy, dataset="cloud_guard.configuration", region=region),
            lambda: [
                Record(
                    key=tenancy,
                    data=pick(
                        guard.get_configuration(tenancy).data, ("status", "reporting_region")
                    ),
                )
            ],
        )
        yield configuration
        if configuration.complete:
            reporting = configuration.records[0].data.get("reporting_region") or region
            reporting_guard = client("guard", signer, reporting)

            def read_problems() -> list[Record]:
                options = {
                    "compartment_id_in_subtree": True,
                    "access_level": "ACCESSIBLE",
                    "lifecycle_detail": "OPEN",
                }
                values = all_items(reporting_guard.list_problems, tenancy, **options)
                zones = {
                    value.id
                    for value in all_items(
                        reporting_guard.list_problems,
                        tenancy,
                        problem_category="SECURITY_ZONE",
                        **options,
                    )
                }
                projected = records(
                    values,
                    (
                        "id",
                        "compartment_id",
                        "resource_id",
                        "resource_type",
                        "resource_name",
                        "region",
                        "risk_level",
                        "risk_score",
                        "target_id",
                        "detector_id",
                        "detector_rule_id",
                        "labels",
                        "lifecycle_state",
                        "lifecycle_detail",
                        "time_first_detected",
                        "time_last_detected",
                    ),
                )
                return [
                    Record(
                        key=record.key,
                        data={
                            **record.data,
                            "problem_category": "SECURITY_ZONE"
                            if record.key in zones
                            else "CLOUD_GUARD",
                        },
                    )
                    for record in projected
                ]

            yield attempt(
                Scope(tenancy=tenancy, dataset="cloud_guard.problems", region=reporting),
                read_problems,
            )
            for compartment in compartment_ids:
                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="security_zones.zones",
                        region=reporting,
                        compartment=compartment,
                    ),
                    partial(
                        read_records,
                        reporting_guard.list_security_zones,
                        (
                            "id",
                            "compartment_id",
                            "display_name",
                            "security_recipe_id",
                            "lifecycle_state",
                        ),
                        compartment,
                    ),
                )
    if settings.cloud_advisor:
        trace.start("Cloud Advisor")
        optimizer = client("optimizer", signer, region)
        yield attempt(
            Scope(tenancy=tenancy, dataset="optimizer.enrollment", region=region),
            lambda: records(
                all_items(optimizer.list_enrollment_statuses, tenancy),
                ("id", "status", "status_reason"),
            ),
        )
        yield attempt(
            Scope(tenancy=tenancy, dataset="optimizer.categories", region=region),
            partial(
                read_records,
                optimizer.list_categories,
                ("id", "name", "description", "lifecycle_state"),
                tenancy,
                True,
            ),
        )

        def read_recommendations() -> list[Record]:
            normalized: list[Record] = []
            for value in all_items(optimizer.list_recommendations, tenancy, True):
                data = pick(
                    value,
                    (
                        "id",
                        "category_id",
                        "name",
                        "description",
                        "importance",
                        "status",
                        "estimated_cost_saving",
                        "time_created",
                        "time_updated",
                    ),
                )
                # Resource counts are nested SDK objects; keep only status -> count.
                data["resource_counts"] = {
                    str(count.status): int(count.count or 0)
                    for count in (getattr(value, "resource_counts", None) or [])
                    if getattr(count, "status", None)
                }
                normalized.append(Record(key=str(value.id), data=data))
            return normalized

        yield attempt(
            Scope(tenancy=tenancy, dataset="optimizer.recommendations", region=region),
            read_recommendations,
        )
