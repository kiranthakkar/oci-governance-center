"""Organization cost from the parent tenancy's Usage API; read-only and parent-only."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import oci

from ..models import Batch, Domain, Record, Scope
from ..oci_clients import all_items, client
from .inventory import attempt

MONTHS = 12
GROUP_BY = ["tenantId", "tenantName", "service", "compartmentId", "compartmentPath"]
# OCI allows six compartment levels below the root; the path then names every level.
COMPARTMENT_DEPTH = 7


def month_start(year: int, month: int) -> datetime:
    """Midnight UTC on the first of a month, normalizing month overflow in either direction."""
    year, month = year + (month - 1) // 12, (month - 1) % 12 + 1
    return datetime(year, month, 1, tzinfo=UTC)


def window(today: datetime) -> tuple[datetime, datetime]:
    """The current month and the previous MONTHS - 1 months; the end is exclusive."""
    return (
        month_start(today.year, today.month - (MONTHS - 1)),
        month_start(today.year, today.month + 1),
    )


def read_costs(signer: Any, domain: Domain, today: datetime) -> list[Record]:
    """Monthly cost per tenancy, service and compartment for the parent's organization.

    Calls UsageapiClient.request_summarized_usages (a read-only query) in the parent's home
    region; requires `read usage-report in tenancy` for ogc_scanner in the parent.
    """
    start, end = window(today)
    usage = client("usage", signer, domain.home_region)
    details = oci.usage_api.models.RequestSummarizedUsagesDetails(
        tenant_id=domain.tenancy_ocid,
        time_usage_started=start,
        time_usage_ended=end,
        granularity="MONTHLY",
        query_type="COST",
        group_by=GROUP_BY,
        compartment_depth=COMPARTMENT_DEPTH,
    )
    rows: dict[str, dict[str, Any]] = {}
    for item in all_items(usage.request_summarized_usages, details):
        started = item.time_usage_started
        month = started.strftime("%Y-%m") if isinstance(started, datetime) else str(started)[:7]
        data = {
            "month": month,
            "tenant_id": item.tenant_id,
            "tenant_name": item.tenant_name,
            "service": item.service,
            "compartment_id": item.compartment_id,
            "compartment_path": item.compartment_path,
            "amount": float(item.computed_amount or 0),
            "currency": item.currency,
        }
        dimensions = (item.tenant_id, item.service, item.compartment_id, item.compartment_path)
        ident = json.dumps([month, *dimensions, item.currency])
        key = hashlib.sha256(ident.encode()).hexdigest()
        # Rows that share every kept dimension (for example split by an ungrouped one) merge.
        if key in rows:
            rows[key]["amount"] += data["amount"]
        else:
            rows[key] = data
    return [Record(key=key, data=data) for key, data in rows.items()]


def costs(signer: Any, domain: Domain, today: datetime) -> Batch:
    """One complete snapshot scope; a denial is a coverage gap that keeps the previous data."""
    return attempt(
        Scope(tenancy=domain.tenancy_ocid, dataset="cost.monthly", region=domain.home_region),
        lambda: read_costs(signer, domain, today),
    )
