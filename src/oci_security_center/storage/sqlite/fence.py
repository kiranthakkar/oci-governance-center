"""Generation and lease fencing, checked inside the committing transaction.

``osc.db`` writes run under ``BEGIN IMMEDIATE``, which serializes them against the single
``organization_state`` row. Checking the generation, maintenance state and lease in that same
transaction is the shared side of the maintenance barrier (docs/control-plane.md §6.1): a switch
that commits first is always seen, and a writer that commits first finishes before the switch.
"""

from __future__ import annotations

import sqlite3

from oci_security_center.models.common import iso, utcnow
from oci_security_center.storage.errors import LeaseError, MaintenanceError, StaleGenerationError


def check_fence(conn: sqlite3.Connection, generation: int) -> None:
    row = conn.execute("SELECT generation, state FROM organization_state WHERE id=1").fetchone()
    if row is None:
        raise StaleGenerationError("organization state is not initialized")
    if row["state"] != "active":
        raise MaintenanceError("OSC is in maintenance (organization switch or restore)")
    if int(row["generation"]) != generation:
        raise StaleGenerationError(
            f"work started under generation {generation}; current is {row['generation']}"
        )


def check_lease(conn: sqlite3.Connection, lease_key: str, token: str, generation: int) -> None:
    row = conn.execute(
        "SELECT token, generation, expires_at FROM scope_leases WHERE lease_key=?", (lease_key,)
    ).fetchone()
    if row is None or row["token"] != token or int(row["generation"]) != generation:
        raise LeaseError("scope lease is not held by this run")
    if row["expires_at"] <= iso(utcnow()):
        raise LeaseError("scope lease expired")
