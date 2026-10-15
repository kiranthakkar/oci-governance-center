"""Identity-domain collectors (read-only, minimal fields; docs/collection.md §3, decision C4).

One snapshot per active identity domain. Calls go to the domain's own URL through
``IdentityDomainsClient(service_endpoint=<domain url>)`` with SCIM ``attributes`` projection so only
the allow-listed fields are returned:

* users — user name, domain ID, OCID;
* groups — display name, domain ID, OCID, members (value, OCID, type);
* dynamic groups — display name, domain ID, OCID, matching rule.

Group membership is cross-checked against the users' own ``groups`` attribute (fetched for the
check, never stored). A group whose membership can't be confirmed makes the snapshot incomplete,
so a truncated member list never replaces a complete one or implies absent membership (gate Q5).
IAM: ``read all-resources`` (cross-tenancy reach of domain APIs is capability gate Q1).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import oci

from oci_security_center.collection.base import (
    Collected,
    Evaluation,
    TenancyContext,
)
from oci_security_center.models import CollectionScope, Envelope
from oci_security_center.oci_clients import ClientMaker, scim_list_all


def _domains(ctx: TenancyContext) -> dict[str, dict[str, Any]]:
    return {
        str(d["id"]): d
        for d in ctx.current("identity.domains")
        if d.get("lifecycle_state") in (None, "ACTIVE") and d.get("url")
    }


class _DomainScoped:
    dataset: str
    tier = 1
    depends_on: tuple[str, ...] = ("identity.domains",)

    def scopes(self, ctx: TenancyContext) -> Sequence[CollectionScope]:
        return [ctx.scope(self.dataset, domain=d) for d in sorted(_domains(ctx))]

    def client(self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker) -> Any:
        domain = _domains(ctx)[str(scope.domain)]
        return clients(oci.identity_domains.IdentityDomainsClient, service_endpoint=domain["url"])

    def record(
        self, ctx: TenancyContext, scope: CollectionScope, sid: str, data: dict[str, Any]
    ) -> Envelope:
        return ctx.envelope(
            self.dataset,
            f"{scope.domain}/{sid}",
            {"domain_ocid": scope.domain, **data},
            domain=scope.domain,
            resource_ocid=data.get("ocid"),
        )

    def evaluate(
        self, ctx: TenancyContext, scope: CollectionScope, records: list[Envelope]
    ) -> Evaluation:
        return Evaluation()


class UsersCollector(_DomainScoped):
    """``IdentityDomainsClient.list_users`` (attributes: userName, ocid)."""

    dataset = "identity_domains.users"

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        users, complete = scim_list_all(
            self.client(ctx, scope, clients).list_users, attributes="userName,ocid"
        )
        return Collected(
            [
                self.record(
                    ctx, scope, u.id, {"id": u.id, "ocid": u.ocid, "user_name": u.user_name}
                )
                for u in users
            ],
            pages_complete=complete,
        )


class GroupsCollector(_DomainScoped):
    """``IdentityDomainsClient.list_groups`` (attributes: displayName, ocid, members), with
    membership verified against ``list_users`` (attributes: groups)."""

    dataset = "identity_domains.groups"

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        client = self.client(ctx, scope, clients)
        groups, groups_complete = scim_list_all(
            client.list_groups, attributes="displayName,ocid,members"
        )
        users, users_complete = scim_list_all(client.list_users, attributes="groups")
        by_group: dict[str, set[str]] = {}
        for u in users:
            for g in u.groups or []:
                by_group.setdefault(g.value, set()).add(u.id)
        out = Collected(pages_complete=groups_complete)
        if not users_complete:
            out.errors.append("membership cross-check incomplete (users not fully listed)")
        for g in groups:
            members = sorted(
                ({"value": m.value, "ocid": m.ocid, "type": m.type} for m in (g.members or [])),
                key=lambda m: (str(m["type"]), str(m["value"])),
            )
            listed = {m["value"] for m in members if (m["type"] or "User") == "User"}
            if listed != by_group.get(g.id, set()):
                out.errors.append(f"membership of group {g.display_name!r} could not be verified")
            out.records.append(
                self.record(
                    ctx,
                    scope,
                    g.id,
                    {
                        "id": g.id,
                        "ocid": g.ocid,
                        "display_name": g.display_name,
                        "members": members,
                    },
                )
            )
        return out


class DynamicGroupsCollector(_DomainScoped):
    """``IdentityDomainsClient.list_dynamic_resource_groups``
    (attributes: displayName, ocid, matchingRule)."""

    dataset = "identity_domains.dynamic_groups"

    def collect(
        self, ctx: TenancyContext, scope: CollectionScope, clients: ClientMaker
    ) -> Collected:
        rows, complete = scim_list_all(
            self.client(ctx, scope, clients).list_dynamic_resource_groups,
            attributes="displayName,ocid,matchingRule",
        )
        return Collected(
            [
                self.record(
                    ctx,
                    scope,
                    d.id,
                    {
                        "id": d.id,
                        "ocid": d.ocid,
                        "display_name": d.display_name,
                        "matching_rule": d.matching_rule,
                    },
                )
                for d in rows
            ],
            pages_complete=complete,
        )
