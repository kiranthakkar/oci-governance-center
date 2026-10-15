"""Collector contract (docs/collection.md, docs/storage.md §4.1).

A collector owns one dataset. The runner asks it for the scopes to collect in a tenancy, calls
``collect`` once per scope with read-only clients, and publishes the result only when the
collector proves completeness (all pages, all expected compartments/domains, no errors). After a
complete publication the collector may ``evaluate`` the records into findings; the runner then
resolves that scope's absent findings for each rule the collector declares.

Collectors never write to storage themselves and never call OCI outside ``collect``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from oci_security_center.config import Settings
from oci_security_center.models import (
    CollectionScope,
    Envelope,
    Finding,
    FindingSource,
    Tenancy,
    canonical_json,
)
from oci_security_center.oci_clients import ClientMaker
from oci_security_center.storage.datasets import get_dataset
from oci_security_center.storage.sqlite.data_store import SqliteDataStore


class DependencyMissing(RuntimeError):
    """A dataset this collector needs has no complete snapshot yet."""


class NotApplicable(RuntimeError):
    """The source doesn't apply to this tenancy right now (e.g. Cloud Guard disabled).

    Not a failure: current rows are kept, no coverage finding is raised, and the reason is shown.
    """


@dataclass
class Collected:
    records: list[Envelope] = field(default_factory=list)
    pages_complete: bool = True
    expected_children: tuple[str, ...] = ()
    visited_children: tuple[str, ...] = ()
    errors: list[str] = field(default_factory=list)


@dataclass
class Evaluation:
    """Findings derived from a complete snapshot, and the rules it fully evaluated."""

    findings: list[Finding] = field(default_factory=list)
    rules: list[tuple[FindingSource, str]] = field(default_factory=list)


@dataclass
class TenancyContext:
    generation: int
    tenancy: Tenancy
    parent: Tenancy
    run_id: str
    data: SqliteDataStore
    settings: Settings
    unavailable: set[str] = field(default_factory=set)

    @property
    def tenancy_ocid(self) -> str:
        return self.tenancy.ocid

    def scope(self, dataset: str, **dims: str) -> CollectionScope:
        return CollectionScope(
            generation=self.generation, tenancy_ocid=self.tenancy.ocid, dataset=dataset, **dims
        )

    def current(self, dataset: str, **dims: str) -> list[dict[str, Any]]:
        """Records of a dependency dataset; requires the latest discovery to be complete."""
        scope = self.scope(dataset, **dims)
        if dataset in self.unavailable or not self.data.dependency_ready(scope):
            raise DependencyMissing(f"{dataset} latest discovery is missing or incomplete")
        return [e.data for e in self.data.read_current(scope)]

    @property
    def home_region(self) -> str | None:
        """The tenancy's home region: known from verify, else from its region subscriptions."""
        if self.tenancy.home_region:
            return self.tenancy.home_region
        try:
            for r in self.current("identity.region_subscriptions"):
                if r.get("is_home_region"):
                    return str(r["region_name"])
        except DependencyMissing:
            pass
        return self.parent.home_region

    def envelope(
        self, dataset: str, record_key: str, data: dict[str, Any], **attrs: Any
    ) -> Envelope:
        return Envelope(
            schema_id=get_dataset(dataset).schema_id,
            tenancy_ocid=self.tenancy.ocid,
            record_key=record_key,
            data=data,
            run_id=self.run_id,
            **attrs,
        )


def evaluation_scope(scope: CollectionScope) -> str:
    """Finding evaluation scope for a collection scope (tenancy is a separate column)."""
    return canonical_json({"dataset": scope.dataset, **scope.dimensions()})


class Collector(Protocol):
    dataset: str
    tier: int
    depends_on: tuple[str, ...]

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]: ...

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected: ...

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation: ...


class TenancyScoped:
    """Mixin: one tenancy-wide scope and no findings."""

    dataset: str

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]:
        return [ctx.scope(self.dataset)]

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        return Evaluation()
