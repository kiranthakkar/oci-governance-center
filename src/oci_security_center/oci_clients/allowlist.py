"""Reviewed OCI SDK read operations (docs/architecture.md §3).

This is the *only* list of SDK operations OSC may invoke. Every client built by
``oci_clients.ClientFactory`` is wrapped so that anything not listed here for that exact client
class raises :class:`ReadOnlyViolation` before reaching the SDK.

Adding an operation is a review step: it must be a ``get_``/``list_``/``summarize_``/``search_``
read, exist on that SDK client, be needed by a collector or control-plane service, and be covered
by the IAM templates in ``docs/iam/``. ``tests/unit/test_sdk_boundary.py`` fails when an entry is
not used anywhere (stale) or code uses an SDK operation that isn't listed.
"""

from __future__ import annotations

from types import MappingProxyType

import oci

READ_PREFIXES = ("get_", "list_", "summarize_", "search_")


class ReadOnlyViolation(PermissionError):
    """Code tried to use an SDK operation or attribute outside the reviewed read allow-list."""


_OPERATIONS: dict[type, frozenset[str]] = {
    # control_plane/verify.py, collectors/identity.py, control_plane/service.py
    oci.identity.IdentityClient: frozenset(
        {
            "get_tenancy",
            "list_region_subscriptions",
            "list_compartments",
            "list_policies",
            "list_groups",
            "list_dynamic_groups",
            "list_domains",  # collectors/identity.py
        }
    ),
    # collectors/identity_domains.py (SCIM, minimal attributes)
    oci.identity_domains.IdentityDomainsClient: frozenset(
        {"list_users", "list_groups", "list_dynamic_resource_groups"}
    ),
    # collectors/organization.py
    oci.tenant_manager_control_plane.OrganizationClient: frozenset(
        {"list_organizations", "list_organization_tenancies"}
    ),
    # control_plane/verify.py
    oci.cloud_guard.CloudGuardClient: frozenset(
        {"get_configuration", "list_problems", "list_security_zones"}  # + collectors/cloud_guard.py
    ),
    # collectors/optimizer.py
    oci.optimizer.OptimizerClient: frozenset(
        {"list_enrollment_statuses", "list_categories", "list_recommendations"}
    ),
    oci.audit.AuditClient: frozenset({"list_events"}),  # verify + collection/audit.py fallback
    # collection/audit.py: Logging Search over the tenancy's _Audit log
    oci.loggingsearch.LogSearchClient: frozenset({"search_logs"}),
    # auth/secrets.py: Vault references (keyless scan identity only, control-plane §3.1)
    oci.secrets.SecretsClient: frozenset({"get_secret_bundle"}),
}


def _validate(ops: dict[type, frozenset[str]]) -> MappingProxyType[type, frozenset[str]]:
    for cls, names in ops.items():
        for name in names:
            if not name.startswith(READ_PREFIXES):
                raise ValueError(f"{cls.__name__}.{name} is not a read operation")
            if not callable(getattr(cls, name, None)):
                raise ValueError(f"{cls.__name__} has no operation {name}")
    return MappingProxyType(dict(ops))


READ_OPERATIONS = _validate(_OPERATIONS)


def allowed_operations(client_cls: type) -> frozenset[str]:
    try:
        return READ_OPERATIONS[client_cls]
    except KeyError:
        raise ReadOnlyViolation(
            f"{getattr(client_cls, '__name__', client_cls)} is not a reviewed OCI client"
        ) from None


class ReadOnlyClient:
    """Proxy that exposes only the allow-listed read operations of one SDK client.

    Attribute access is the check: ``client.list_policies`` returns the SDK's bound method,
    ``client.delete_policy``, ``getattr(client, "update_x")``, ``client.base_client`` and any other
    attribute raise. The wrapped client is never handed out.
    """

    __slots__ = ("__allowed", "__client", "__name")
    __allowed: frozenset[str]
    __client: object
    __name: str

    def __init__(self, client: object, client_cls: type) -> None:
        object.__setattr__(self, "_ReadOnlyClient__allowed", allowed_operations(client_cls))
        object.__setattr__(self, "_ReadOnlyClient__client", client)
        object.__setattr__(self, "_ReadOnlyClient__name", client_cls.__name__)

    def __getattr__(self, name: str) -> object:
        if name in self.__allowed:
            return getattr(self.__client, name)
        raise ReadOnlyViolation(f"{self.__name}.{name} is not an allow-listed read operation")

    def __setattr__(self, name: str, value: object) -> None:
        raise ReadOnlyViolation("read-only OCI clients can't be modified")

    def __delattr__(self, name: str) -> None:
        raise ReadOnlyViolation("read-only OCI clients can't be modified")

    def __dir__(self) -> list[str]:
        return sorted(self.__allowed)

    def __repr__(self) -> str:
        return f"<ReadOnlyClient {self.__name}>"
