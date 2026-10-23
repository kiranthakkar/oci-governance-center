"""Tier-one per-scope inventory; never persist raw SDK responses."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime
from functools import partial
from typing import Any

import oci

from ..diagnostics import PublicFailure, verification_step
from ..models import Batch, Child, Domain, Record, Scope, domain_origin
from ..oci_clients import all_items, client


def public_error(error: Exception) -> str:
    """Return safe error status without OCI bodies or credentials."""
    if isinstance(error, PublicFailure):
        return str(error)
    if isinstance(error, oci.exceptions.ServiceError):
        return f"OCI read failed (HTTP {error.status}); check local grants and service availability"
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
    # in for it. It stays unknown until Configure verifies the child's default domain.
    return [
        Child(ocid=m.tenancy_id, name=m.name or m.tenancy_id)
        for m in current
        if m.role == "CHILD" and m.tenancy_id != domain.tenancy_ocid
    ]


def inventory(signer: Any, domain: Domain, family: str = "all") -> Iterator[Batch]:
    """Read IAM, governance and domain inventory using local tenancy-scoped read permissions."""
    tenancy, region = domain.tenancy_ocid, domain.home_region
    identity = client("identity", signer, region)
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
                try:
                    endpoint = domain_origin(str(record.data["url"]))
                    domains = client("domains", signer, region, endpoint)
                except ValueError:
                    yield Batch(
                        scope=Scope(
                            tenancy=tenancy,
                            dataset="identity_domains.users",
                            region=region,
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
                        region=region,
                        domain=record.key,
                    ),
                    partial(
                        read_records,
                        domains.list_users,
                        ("id", "ocid", "user_name"),
                        attributes="id,ocid,userName",
                    ),
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
                        region=region,
                        domain=record.key,
                    ),
                    read_groups,
                )
                yield attempt(
                    Scope(
                        tenancy=tenancy,
                        dataset="identity_domains.dynamic_groups",
                        region=region,
                        domain=record.key,
                    ),
                    partial(
                        read_records,
                        domains.list_dynamic_resource_groups,
                        ("id", "ocid", "display_name", "matching_rule"),
                        attributes="id,ocid,displayName,matchingRule",
                    ),
                )
    if family not in {"all", "governance"}:
        return
    guard = client("guard", signer, region)
    configuration = attempt(
        Scope(tenancy=tenancy, dataset="cloud_guard.configuration", region=region),
        lambda: [
            Record(
                key=tenancy,
                data=pick(guard.get_configuration(tenancy).data, ("status", "reporting_region")),
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
            Scope(tenancy=tenancy, dataset="cloud_guard.problems", region=reporting), read_problems
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
    optimizer = client("optimizer", signer, region)
    yield attempt(
        Scope(tenancy=tenancy, dataset="optimizer.enrollment", region=region),
        lambda: records(
            all_items(optimizer.list_enrollment_statuses, tenancy),
            ("id", "status", "status_reason"),
        ),
    )
    yield attempt(
        Scope(tenancy=tenancy, dataset="optimizer.recommendations", region=region),
        lambda: records(
            all_items(optimizer.list_recommendations, tenancy, True),
            ("id", "category_id", "name", "importance", "status", "time_updated"),
        ),
    )
