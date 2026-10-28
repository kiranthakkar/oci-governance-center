"""Single reviewed SDK construction and operation boundary."""

from collections.abc import Callable
from typing import Any

import oci
from cryptography.hazmat.primitives import serialization

OPERATIONS: dict[str, frozenset[str]] = {
    "identity": frozenset(
        {
            "get_tenancy",
            "get_domain",
            "list_compartments",
            "list_region_subscriptions",
            "list_policies",
            "list_domains",
        }
    ),
    "domains": frozenset(
        {"list_users", "list_groups", "list_dynamic_resource_groups", "list_api_keys"}
    ),
    "organization": frozenset({"list_organizations", "list_organization_tenancies"}),
    "guard": frozenset({"get_configuration", "list_problems", "list_security_zones"}),
    "optimizer": frozenset({"list_categories", "list_enrollment_statuses", "list_recommendations"}),
    "audit": frozenset({"list_events"}),
    # Usage API summaries are read-only queries sent as POST; reviewed exception to the
    # get_/list_/search_/summarize_ naming rule (AGENTS.md §2.1). Requires read usage-report.
    "usage": frozenset({"request_summarized_usages"}),
}
CONSTRUCTORS: dict[str, Any] = {
    "identity": oci.identity.IdentityClient,
    "domains": oci.identity_domains.IdentityDomainsClient,
    "organization": oci.tenant_manager_control_plane.OrganizationClient,
    "guard": oci.cloud_guard.CloudGuardClient,
    "optimizer": oci.optimizer.OptimizerClient,
    "audit": oci.audit.AuditClient,
    "usage": oci.usage_api.UsageapiClient,
}


class ReadOnlyClient:
    """Expose only reviewed SDK reads; neither the wrapped client nor base_client is public."""

    __slots__ = ("_client", "_operations")

    def __init__(self, client: Any, operations: frozenset[str]) -> None:
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_operations", operations)

    def __getattribute__(self, name: str) -> Any:
        if name not in object.__getattribute__(self, "_operations"):
            raise AttributeError("OCI operation or attribute is not permitted")
        return getattr(object.__getattribute__(self, "_client"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Read-only SDK boundary")


def client(kind: str, signer: Any, region: str, endpoint: str | None = None) -> Any:
    """Construct one per-worker client with default retry; required IAM matches its allow-list."""
    if kind not in OPERATIONS:
        raise ValueError("Unreviewed SDK client")
    options: dict[str, Any] = {
        "signer": signer,
        "retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY,
        "timeout": (10, 30),
    }
    if endpoint:
        options["service_endpoint"] = endpoint
    config: dict[str, Any] = {"region": region}
    if isinstance(signer, oci.signer.Signer):
        tenancy, user, fingerprint = signer.api_key.split("/")
        config.update(
            tenancy=tenancy,
            user=user,
            fingerprint=fingerprint,
            key_content=signer.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        )
    return ReadOnlyClient(CONSTRUCTORS[kind](config, **options), OPERATIONS[kind])


def all_items(method: Callable[..., Any], *args: Any, **kwargs: Any) -> list[Any]:
    """Use SDK pagination; partial failures propagate without publishing emptiness."""

    def page_adapter(*page_args: Any, **page_kwargs: Any) -> Any:
        # The SDK generic paginator expects .items; SCIM returns .resources and
        # totalResults/startIndex instead. Adapt its responses, retaining SDK pagination/retry.
        index = page_kwargs.pop("page", None)
        if method.__name__ in {
            "list_users",
            "list_groups",
            "list_dynamic_resource_groups",
            "list_api_keys",
        }:
            page_kwargs["start_index"] = int(index or 1)
            page_kwargs["count"] = 500
        elif index:
            page_kwargs["page"] = index
        response = method(*page_args, **page_kwargs)
        if hasattr(response.data, "resources"):
            data = response.data
            resources = list(data.resources or [])
            start = data.start_index or page_kwargs.get("start_index", 1)
            if start != page_kwargs.get("start_index", 1):
                raise ValueError("SCIM pagination repeated or skipped a requested page")
            total = data.total_results
            if total is None:
                raise ValueError("SCIM response omits completeness evidence")
            next_index = start + len(resources)
            if next_index <= total:
                if not resources:
                    raise ValueError("SCIM pagination made no progress")
                response.headers["opc-next-page"] = str(next_index)
            else:
                response.headers.pop("opc-next-page", None)
            response = oci.response.Response(
                response.status, response.headers, resources, response.request
            )
        return response

    response = oci.pagination.list_call_get_all_results(page_adapter, *args, **kwargs).data
    if not isinstance(response, list):
        raise ValueError("Unsupported SDK pagination response shape")
    return response
