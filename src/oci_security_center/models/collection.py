"""Collection scope and completeness manifest (docs/storage.md §4.1).

A ``CollectionScope`` names exactly which slice of a dataset one snapshot covers: the organization
generation, tenancy, dataset and the scope dimensions the dataset registry declares (for example a
region or an identity domain). A ``CollectionManifest`` is the collector's evidence that it fetched
that whole scope; only a complete manifest may replace current rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from oci_security_center.models.common import canonical_json, utcnow

ScopeDimension = Literal["region", "domain", "compartment"]
SCOPE_DIMENSIONS: tuple[ScopeDimension, ...] = ("region", "domain", "compartment")


class CollectionScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    generation: int
    tenancy_ocid: str
    dataset: str
    region: str | None = None
    domain: str | None = None  # identity domain OCID
    compartment: str | None = None

    def dimensions(self) -> dict[str, str]:
        return {d: v for d in SCOPE_DIMENSIONS if (v := getattr(self, d)) is not None}

    @property
    def scope_key(self) -> str:
        """Canonical key of the scope *within* a tenancy and dataset (``{}`` = whole tenancy)."""
        return canonical_json(self.dimensions())

    @property
    def lease_key(self) -> str:
        """Key that one scope lease serializes on (generation is checked separately)."""
        return canonical_json(
            {"tenancy": self.tenancy_ocid, "dataset": self.dataset, **self.dimensions()}
        )


class CollectionManifest(BaseModel):
    """What a collector fetched for one scope, and whether that is provably all of it."""

    model_config = ConfigDict(frozen=True)

    scope: CollectionScope
    run_id: str
    lease_token: str
    started_at: datetime
    finished_at: datetime = Field(default_factory=utcnow)
    query_version: str = "1"
    schema_version: int = 1
    pages_complete: bool = False
    expected_children: tuple[str, ...] = ()  # compartments/domains the collector had to visit
    visited_children: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    record_count: int = 0

    @property
    def complete(self) -> bool:
        return (
            self.pages_complete
            and not self.errors
            and set(self.expected_children) <= set(self.visited_children)
        )

    @property
    def missing_children(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.expected_children) - set(self.visited_children)))
