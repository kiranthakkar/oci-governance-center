"""Every collector, in dependency order (docs/collection.md §3).

A collector runs only when the deployment's ``OSC_COLLECTION_TIER`` is at or above its tier.
Later tiers add their collectors here when they are built.
"""

from __future__ import annotations

from oci_security_center.collection.base import Collector
from oci_security_center.collectors.cloud_guard import (
    CloudGuardConfigurationCollector,
    CloudGuardProblemsCollector,
    SecurityZonesCollector,
)
from oci_security_center.collectors.identity import (
    CompartmentsCollector,
    DomainsCollector,
    PoliciesCollector,
    RegionSubscriptionsCollector,
)
from oci_security_center.collectors.identity_domains import (
    DynamicGroupsCollector,
    GroupsCollector,
    UsersCollector,
)
from oci_security_center.collectors.optimizer import EnrollmentCollector, RecommendationsCollector

COLLECTORS: tuple[Collector, ...] = (
    RegionSubscriptionsCollector(),
    CompartmentsCollector(),
    PoliciesCollector(),
    DomainsCollector(),
    UsersCollector(),
    GroupsCollector(),
    DynamicGroupsCollector(),
    CloudGuardConfigurationCollector(),
    CloudGuardProblemsCollector(),
    SecurityZonesCollector(),
    EnrollmentCollector(),
    RecommendationsCollector(),
)

# Scheduler groups (docs/collection.md §9).
GROUPS: dict[str, frozenset[str]] = {
    "identity": frozenset(
        {
            "identity.region_subscriptions",
            "identity.compartments",
            "identity.policies",
            "identity.domains",
            "identity_domains.users",
            "identity_domains.groups",
            "identity_domains.dynamic_groups",
        }
    ),
    "governance": frozenset(
        {
            "cloud_guard.configuration",
            "cloud_guard.problems",
            "security_zones.zones",
            "optimizer.enrollment",
            "optimizer.recommendations",
        }
    ),
}


def collectors_for_tier(tier: int) -> list[Collector]:
    return [c for c in COLLECTORS if c.tier <= tier]
