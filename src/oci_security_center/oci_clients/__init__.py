"""Thin OCI client factory: region + credentials -> SDK client with retries (AGENTS.md §6).

Build every SDK client through :class:`ClientFactory`. Create clients per worker thread; do not
share one client across threads. Every client is returned wrapped in
:class:`~oci_security_center.oci_clients.allowlist.ReadOnlyClient`: only reviewed read operations
(``allowlist.py``) can be invoked (docs/architecture.md §3).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any, Protocol, TypeVar, cast

import oci

from oci_security_center.auth.signers import OciAuth
from oci_security_center.oci_clients.allowlist import (
    ReadOnlyClient,
    ReadOnlyViolation,
    allowed_operations,
)

T = TypeVar("T")


class ClientMaker(Protocol):
    def __call__(
        self,
        client_cls: Callable[..., T],
        region: str | None = None,
        service_endpoint: str | None = None,
    ) -> T: ...


class ClientFactory:
    def __init__(self, auth: OciAuth) -> None:
        self.auth = auth

    def __call__(
        self,
        client_cls: Callable[..., T],
        region: str | None = None,
        service_endpoint: str | None = None,
    ) -> T:
        """``service_endpoint``: per-instance endpoints, e.g. an identity domain's URL."""
        if not isinstance(client_cls, type):
            raise ReadOnlyViolation("client factories only build reviewed OCI client classes")
        allowed_operations(client_cls)  # refuse unreviewed clients before constructing them
        config = dict(self.auth.config)
        if region:
            config["region"] = region
        kwargs: dict[str, Any] = {"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY}
        if self.auth.signer is not None:
            kwargs["signer"] = self.auth.signer
        if service_endpoint is not None:
            if not service_endpoint.startswith("https://"):
                raise ValueError("service endpoints must be https")
            kwargs["service_endpoint"] = service_endpoint
        return cast(T, ReadOnlyClient(client_cls(config, **kwargs), client_cls))


def list_all(list_fn: Callable[..., Any], *args: Any, **kwargs: Any) -> list[Any]:
    """Fetch every page via ``oci.pagination`` (never hand-roll opc-next-page loops)."""
    data = oci.pagination.list_call_get_all_results(list_fn, *args, **kwargs).data
    return list(data)


def paged_responses(list_func: Callable[..., Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
    """Every response of a paged call (``opc-next-page``), for calls whose data isn't a list
    (e.g. ``search_logs``). Uses the SDK generator; never a hand-rolled page loop."""
    yield from oci.pagination.list_call_get_all_results_generator(
        list_func, "response", *args, **kwargs
    )


def audit_log_search(start: Any, end: Any, tenancy_ocid: str) -> Any:
    """``SearchLogsDetails`` for a tenancy's audit log, including subcompartments."""
    return oci.loggingsearch.models.SearchLogsDetails(
        time_start=start,
        time_end=end,
        search_query=f'search "{tenancy_ocid}/_Audit_Include_Subcompartment"',
        is_return_field_info=False,
    )


SCIM_PAGE_SIZE = 500  # identity domains maximum ``count`` per request (verify per Q5 gate)


def scim_list_all(
    list_func: Callable[..., Any], page_size: int = SCIM_PAGE_SIZE, **kwargs: Any
) -> tuple[list[Any], bool]:
    """Page through an identity-domains (SCIM) list call; return (resources, complete).

    SCIM pages by ``start_index``/``count`` with ``total_results`` rather than ``opc-next-page``,
    which ``oci.pagination`` doesn't handle. ``complete`` is True only when the number of
    resources received equals the reported ``total_results``.
    """
    resources: list[Any] = []
    start = 1
    total: int | None = None
    while True:
        data = list_func(start_index=start, count=page_size, **kwargs).data
        page = list(data.resources or [])
        resources.extend(page)
        total = data.total_results if data.total_results is not None else total
        if not page or total is None or len(resources) >= total:
            break
        start += len(page)
    return resources, total is not None and len(resources) == total


def to_plain(sdk_obj: Any) -> dict[str, Any]:
    """Convert an SDK model to a plain dict (datetimes become ISO strings)."""
    plain = oci.util.to_dict(sdk_obj)
    if not isinstance(plain, dict):
        raise TypeError("expected an SDK model")
    return plain


def pick(data: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Allow-list fields when normalizing (AGENTS.md §2.3: never dump whole SDK objects)."""
    return {f: data.get(f) for f in fields}
