"""All-event regional Audit collection with durable replay-safe interval progress."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ..models import Domain
from ..oci_clients import all_items, client
from .inventory import pick


def normalize(event: Any) -> dict[str, Any]:
    """Keep only reviewed AuditEvent fields; discard request/response blobs and headers."""
    data = event.data
    identity = data.identity
    request = data.request
    response = data.response
    return {
        "id": event.event_id,
        "time": event.event_time.isoformat(),
        "type": event.event_type,
        **pick(
            identity, ("principal_id", "principal_name", "auth_type", "user_agent", "ip_address")
        ),
        **pick(data, ("compartment_id", "resource_id", "resource_name")),
        **pick(request, ("action",)),
        "status": getattr(response, "status", None),
    }


def read_interval(
    signer: Any, domain: Domain, region: str, compartments: list[str], start: Any, end: Any
) -> list[dict[str, Any]]:
    """List all Audit events per compartment/region; requires read audit-events."""
    if end - start > timedelta(hours=1):
        raise ValueError("Audit API intervals must be no longer than one hour")
    audit = client("audit", signer, region)
    events: dict[str, dict[str, Any]] = {}
    for compartment in compartments:
        for event in all_items(audit.list_events, compartment, start, end):
            normalized = normalize(event)
            events[normalized["id"]] = normalized
    return list(events.values())
