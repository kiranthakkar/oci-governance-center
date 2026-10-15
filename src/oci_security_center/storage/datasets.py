"""Dataset registry: one table per dataset, typed key columns + JSON ``data`` (docs/storage.md §3).

``columns`` maps an extra typed column to the key in the normalized record ``data`` it is copied
from. Adding a dataset = adding an entry here (and a collector). Table DDL is generated from this.
``tier`` is the collection tier that collects it (docs/collection.md §2). ``scope`` lists the
dimensions one snapshot is split by (docs/storage.md §4.1); ``()`` means one snapshot per tenancy.
Callers must supply exactly these dimensions: a snapshot can't be narrowed arbitrarily.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from oci_security_center.models.collection import CollectionScope, ScopeDimension
from oci_security_center.models.common import content_hash


@dataclass(frozen=True)
class DatasetSpec:
    id: str  # e.g. "identity.policies"
    tier: int = 1
    version: int = 1
    columns: dict[str, str] = field(default_factory=dict)  # column -> data key
    indexes: tuple[tuple[str, ...], ...] = ()
    scope: tuple[ScopeDimension, ...] = ()
    # Source fields that change without a meaningful change (e.g. "last detected" times);
    # excluded from the content hash so drift views show real changes only (delta-fetching §4).
    volatile: tuple[str, ...] = ()

    def content_hash(self, data: dict[str, object]) -> str:
        return content_hash({k: v for k, v in data.items() if k not in self.volatile})

    def check_scope(self, scope: CollectionScope) -> None:
        if scope.dataset != self.id:
            raise ValueError(f"scope is for {scope.dataset!r}, not {self.id!r}")
        given = tuple(scope.dimensions())
        if set(given) != set(self.scope):
            raise ValueError(
                f"{self.id} snapshots are scoped by {list(self.scope) or 'tenancy only'}, "
                f"got {list(given) or 'tenancy only'}"
            )

    @property
    def table(self) -> str:
        return self.id.replace(".", "_")

    @property
    def schema_id(self) -> str:
        return f"{self.id}.v{self.version}"


DATASETS: dict[str, DatasetSpec] = {
    spec.id: spec
    for spec in [
        DatasetSpec(
            "identity.compartments",
            columns={
                "name": "name",
                "lifecycle_state": "lifecycle_state",
                "parent_ocid": "compartment_id",
            },
        ),
        DatasetSpec(
            "identity.policies",
            columns={"name": "name", "lifecycle_state": "lifecycle_state"},
            indexes=(("name",),),
        ),
        DatasetSpec(
            "identity.domains",
            columns={"name": "display_name", "type": "type", "lifecycle_state": "lifecycle_state"},
        ),
        # Identity domain data: minimal fields only (docs/collection.md C4).
        DatasetSpec(
            "identity_domains.users",
            scope=("domain",),
            columns={"domain_ocid": "domain_ocid", "user_name": "user_name", "ocid": "ocid"},
            indexes=(("ocid",), ("domain_ocid", "user_name")),
        ),
        DatasetSpec(
            "identity_domains.groups",
            scope=("domain",),
            columns={"domain_ocid": "domain_ocid", "name": "display_name", "ocid": "ocid"},
            indexes=(("ocid",), ("domain_ocid", "name")),
        ),
        DatasetSpec(
            "identity_domains.dynamic_groups",
            scope=("domain",),
            columns={
                "domain_ocid": "domain_ocid",
                "name": "display_name",
                "ocid": "ocid",
                "matching_rule": "matching_rule",
            },
            indexes=(("ocid",),),
        ),
        DatasetSpec(
            "identity.region_subscriptions",
            columns={
                "region_name": "region_name",
                "status": "status",
                "is_home_region": "is_home_region",
            },
        ),
        DatasetSpec(
            "cloud_guard.configuration",
            columns={"status": "status", "reporting_region": "reporting_region"},
        ),
        DatasetSpec("cloud_guard.targets", tier=2, columns={"lifecycle_state": "lifecycle_state"}),
        DatasetSpec(
            "cloud_guard.problems",
            columns={
                "risk_level": "risk_level",
                "lifecycle_state": "lifecycle_state",
                "lifecycle_detail": "lifecycle_detail",
                "detector_id": "detector_id",
            },
            indexes=(("risk_level", "lifecycle_detail"),),
            volatile=("time_last_detected",),
        ),
        DatasetSpec("security_zones.zones", columns={"lifecycle_state": "lifecycle_state"}),
        DatasetSpec(
            "security_zones.recipes", tier=2, columns={"lifecycle_state": "lifecycle_state"}
        ),
        DatasetSpec("optimizer.enrollment", columns={"status": "status"}),
        DatasetSpec(
            "optimizer.recommendations",
            columns={"category_id": "category_id", "importance": "importance", "status": "status"},
            volatile=("time_updated",),
        ),
    ]
}

AUDIT_DATASET = "audit.events"  # Tier 1; stored in per-tenancy monthly files, not a table here


def datasets_for_tier(tier: int) -> list[DatasetSpec]:
    """Datasets collected at ``tier`` (each tier includes the lower ones)."""
    return [spec for spec in DATASETS.values() if spec.tier <= tier]


def get_dataset(dataset_id: str) -> DatasetSpec:
    try:
        return DATASETS[dataset_id]
    except KeyError as exc:
        raise KeyError(f"unknown dataset {dataset_id!r}") from exc
