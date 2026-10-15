"""Storage interfaces. Collectors, analyzers and the control plane depend only on these.

Phase 1 implements them with SQLite. Future backends (Object Storage, ADB, MySQL, DB MCP server)
implement the same protocols (docs/storage.md §7).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from oci_security_center.models import (
    CollectionManifest,
    CollectionScope,
    Connection,
    ConnectionPurpose,
    Envelope,
    Finding,
    FindingSource,
    RequirementCheck,
    Tenancy,
)


@dataclass(frozen=True)
class Watermark:
    complete_through: str
    run_id: str | None
    updated_at: datetime


@dataclass(frozen=True)
class SnapshotResult:
    dataset: str
    tenancy_ocid: str
    total: int
    added: int
    modified: int
    removed: int
    unchanged: int


@dataclass
class PurgeResult:
    rows_deleted: dict[str, int] = field(default_factory=dict)
    files_deleted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # problems that did not stop the purge


class DataStore(Protocol):
    """Collected data. Writes are fenced by organization generation (and scope lease)."""

    def current_generation(self) -> int: ...

    def apply_snapshot(
        self, scope: CollectionScope, records: Iterable[Envelope], manifest: CollectionManifest
    ) -> SnapshotResult: ...

    def record_partial(self, manifest: CollectionManifest, status: str = "partial") -> None: ...

    def last_success(self, scope: CollectionScope) -> datetime | None: ...

    def read_current(
        self, scope: CollectionScope, include_deleted: bool = False
    ) -> Iterator[Envelope]: ...

    def append_events(
        self,
        generation: int,
        tenancy_ocid: str,
        events: Iterable[Envelope],
        run_id: str,
        *,
        scope: CollectionScope | None = None,
        lease_token: str | None = None,
    ) -> int: ...

    def get_watermark(
        self, generation: int, tenancy_ocid: str, dataset: str, region: str | None = None
    ) -> Watermark | None: ...

    def set_watermark(
        self,
        generation: int,
        tenancy_ocid: str,
        dataset: str,
        complete_through: str,
        run_id: str | None,
        region: str | None = None,
    ) -> None: ...

    def upsert_findings(self, findings: Iterable[Finding]) -> int: ...

    def resolve_absent(
        self,
        generation: int,
        source: FindingSource,
        tenancy_ocid: str,
        rule_id: str,
        scope_key: str,
        seen_ids: set[str],
    ) -> int: ...

    def list_findings(self, generation: int | None = None, **filters: Any) -> list[Finding]: ...


class AppStateStore(Protocol):
    def get_setting(self, key: str) -> str | None: ...
    def set_setting(self, key: str, value: str) -> None: ...

    def upsert_tenancy(self, tenancy: Tenancy) -> None: ...
    def get_tenancy(self, ocid: str) -> Tenancy | None: ...
    def list_tenancies(self) -> list[Tenancy]: ...

    def save_connection(self, connection: Connection) -> None: ...
    def get_connection(
        self, tenancy_ocid: str, purpose: ConnectionPurpose
    ) -> Connection | None: ...

    def save_checks(
        self, tenancy_ocid: str, target_tenancy_ocid: str, checks: Sequence[RequirementCheck]
    ) -> None: ...
    def get_checks(self, requirement_ids: Sequence[str]) -> dict[str, RequirementCheck]: ...

    def record_event(
        self,
        actor: str,
        role: str,
        action: str,
        target: str | None,
        result: str,
        detail: dict[str, Any] | None = None,
    ) -> None: ...


class Sink(Protocol):
    """Optional fan-out mirror (future: Object Storage, ADB/MySQL, DB MCP server)."""

    def publish(self, dataset: str, batch: Sequence[Envelope]) -> None: ...
