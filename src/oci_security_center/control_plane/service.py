"""Control-plane service: parent connection, Organization discovery, child onboarding, policy
screens and read-only checks (docs/control-plane.md). Strictly read-only against OCI.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import oci

from oci_security_center.collectors import identity as idc
from oci_security_center.collectors.organization import discover_organizations
from oci_security_center.config import Settings
from oci_security_center.control_plane import policy_templates as tpl
from oci_security_center.control_plane.checks import (
    PolicyRecord,
    check_requirements,
    unknown_checks,
)
from oci_security_center.control_plane.verify import (
    VerifyResult,
    explain_service_error,
    verify_tenancy,
)
from oci_security_center.logging import get_logger
from oci_security_center.models import (
    CheckStatus,
    Connection,
    ConnectionPurpose,
    Finding,
    FindingSource,
    OnboardingStatus,
    OrgRole,
    PolicyRequirement,
    RequirementCheck,
    Severity,
    Tenancy,
    utcnow,
)
from oci_security_center.oci_clients import ClientMaker
from oci_security_center.storage.errors import StorageError
from oci_security_center.storage.sqlite import SqliteStores
from oci_security_center.storage.sqlite.migrations import (
    SCOPE_CHILD_ACCESS,
    SCOPE_PARENT_POLICIES,
)
from oci_security_center.storage.sqlite.reset import SwitchIncomplete, replace_organization

log = get_logger(__name__)

SETTING_PARENT = "parent_tenancy_ocid"
SETTING_ADMIN_BROWSE = "offer_admin_browse"
SETTING_GROUP_OCIDS = "parent_group_ocids"
SETTING_TOKEN_EXCHANGE_OK = "token_exchange_last_ok"  # noqa: S105
# Settings that describe the current organization; cleared when the parent is replaced.
_ORG_SETTINGS = (SETTING_ADMIN_BROWSE, SETTING_GROUP_OCIDS, SETTING_TOKEN_EXCHANGE_OK)
ACCESS_RULE = "OSC-ACCESS-001"


class ControlPlaneError(RuntimeError):
    pass


@dataclass
class Actor:
    name: str
    role: str


@dataclass
class DiscoveryResult:
    organizations: int = 0
    children: list[Tenancy] = field(default_factory=list)
    message: str = ""


@dataclass
class PolicyView:
    """Everything a policy screen renders."""

    tenancy_ocid: str  # where these statements must be applied
    policy_name: str
    requirements: list[PolicyRequirement]
    checks: dict[str, RequirementCheck]
    cli: str

    @property
    def text(self) -> str:
        return tpl.statements_text(self.requirements)

    def status_of(self, req: PolicyRequirement) -> CheckStatus:
        check = self.checks.get(req.id)
        return check.status if check else CheckStatus.UNKNOWN


@dataclass
class PrincipalInfo:
    scanner: tpl.PrincipalRef
    admins: tpl.PrincipalRef
    names_to_ocids: dict[str, str]


class ControlPlane:
    def __init__(self, settings: Settings, stores: SqliteStores) -> None:
        self.settings = settings
        self.stores = stores
        self.state = stores.state
        # Problems the last organization replacement could not fix (e.g. undeletable files).
        self.replace_warnings: list[str] = []

    # --- parent -------------------------------------------------------------------------
    def parent(self) -> Tenancy | None:
        ocid = self.state.get_setting(SETTING_PARENT)
        return self.state.get_tenancy(ocid) if ocid else None

    def require_parent(self) -> Tenancy:
        parent = self.parent()
        if parent is None:
            raise ControlPlaneError("no parent tenancy configured (run `osc admin bootstrap`)")
        return parent

    def connect_parent(
        self,
        clients: ClientMaker,
        tenancy_ocid: str,
        display_name: str | None,
        actor: Actor,
        connections: tuple[Connection, ...] = (),
    ) -> Tenancy:
        """Connection test + register the parent. Calls ``get_tenancy``,
        ``list_region_subscriptions`` (read-only).

        OSC serves one organization per deployment. Once the connection test passes, everything
        stored for any other organization is removed locally (``replaced_tenancies`` previews it).
        Reconnecting the same parent keeps its children and onboarding state.
        """
        identity: Any = clients(oci.identity.IdentityClient)
        try:
            info = idc.get_tenancy(identity, tenancy_ocid)
            regions = idc.list_region_subscriptions(identity, tenancy_ocid)
        except oci.exceptions.ServiceError as exc:
            self.state.record_event(
                actor.name,
                actor.role,
                "parent.connect",
                tenancy_ocid,
                "error",
                {"error": explain_service_error(exc)},
            )
            raise ControlPlaneError(explain_service_error(exc)) from exc
        replacing = bool(self.replaced_tenancies(tenancy_ocid)) or self.state.get_setting(
            SETTING_PARENT
        ) not in (None, tenancy_ocid)
        if any(c.tenancy_ocid != tenancy_ocid for c in connections):
            raise ControlPlaneError("candidate connections must belong to the new parent")
        existing = self.state.get_tenancy(tenancy_ocid)
        keep_alias = existing is not None and existing.org_role is OrgRole.PARENT and not replacing
        parent = Tenancy(
            ocid=tenancy_ocid,
            name=display_name or info["name"],
            alias=(
                existing.alias
                if existing is not None and keep_alias
                else self._available_alias(
                    tpl.make_alias(self.settings.parent_alias),
                    exclude=tenancy_ocid,
                    retained_parent=tenancy_ocid if replacing else None,
                )
            ),
            org_role=OrgRole.PARENT,
            home_region=idc.home_region(regions),
            subscribed_regions=tuple(
                r["region_name"] for r in regions if r.get("status") == "READY"
            ),
            onboarding_status=OnboardingStatus.ACTIVE,
            last_verified_at=utcnow(),
        )
        connections = tuple(
            c.model_copy(
                update={
                    "id": c.id or uuid.uuid4().hex,
                    "created_by": actor.name,
                    "created_at": utcnow(),
                    "region": c.region or parent.home_region,
                }
            )
            for c in connections
        )

        def install(conn: sqlite3.Connection, generation: int) -> None:
            self.state.upsert_tenancy_in(conn, parent)
            for candidate in connections:
                self.state.save_connection_in(conn, candidate)

        replaced = self._replace_organization(tenancy_ocid, actor, install)
        generation = self.state.current_generation()  # new generation after replacement
        if not replaced:
            self.state.upsert_tenancy(parent, generation)
            self.state.set_setting(SETTING_PARENT, tenancy_ocid, generation)
            for candidate in connections:
                self.save_connection(candidate, actor)
            self.state.set_organization_parent(tenancy_ocid, generation)
        self.state.record_event(
            actor.name,
            actor.role,
            "parent.connect",
            tenancy_ocid,
            "ok",
            {"home_region": parent.home_region},
        )
        return parent

    def replaced_tenancies(self, tenancy_ocid: str) -> list[Tenancy]:
        """Tenancies whose local data ``connect_parent(tenancy_ocid)`` would remove: everything
        except that tenancy and the children already registered under it."""
        return [
            t
            for t in self.state.list_tenancies()
            if t.ocid != tenancy_ocid and t.parent_tenancy_ocid != tenancy_ocid
        ]

    def _replace_organization(
        self,
        tenancy_ocid: str,
        actor: Actor,
        install_candidate: Callable[[sqlite3.Connection, int], None],
    ) -> bool:
        """Drop every other organization's local data. Returns True if anything was removed."""
        self.replace_warnings = []
        previous = self.state.get_setting(SETTING_PARENT)
        gone = self.replaced_tenancies(tenancy_ocid)
        if not gone and previous in (None, tenancy_ocid):
            return False
        keep = {tenancy_ocid} | {
            t.ocid for t in self.state.list_tenancies() if t.parent_tenancy_ocid == tenancy_ocid
        }
        try:
            generation, result = replace_organization(
                self.stores.db,
                self.state,
                self.stores.data,
                keep,
                parent_ocid=tenancy_ocid,
                holder=f"bootstrap:{actor.name}",
                drop_settings=_ORG_SETTINGS,
                drain_timeout_s=self.settings.switch_drain_seconds,
                install_candidate=install_candidate,
            )
        except SwitchIncomplete as exc:
            self.state.record_event(
                actor.name, actor.role, "org.replace", tenancy_ocid, "error", {"error": str(exc)}
            )
            raise ControlPlaneError(str(exc)) from exc
        except StorageError as exc:
            raise ControlPlaneError(
                f"could not replace the organization; nothing was changed ({exc})"
            ) from exc
        self.state.record_event(
            actor.name,
            actor.role,
            "org.replace",
            tenancy_ocid,
            "ok",
            {
                "previous_parent": previous,
                "generation": generation,
                "removed_tenancies": len(gone),
                "rows_deleted": {k: v for k, v in result.rows_deleted.items() if v},
                "files_deleted": len(result.files_deleted),
                "errors": result.errors,
            },
        )
        self.replace_warnings = list(result.errors)
        log.info("replaced organization: removed %d tenancies", len(gone))
        return True

    def save_connection(self, conn: Connection, actor: Actor) -> Connection:
        conn = conn.model_copy(
            update={
                "id": conn.id or uuid.uuid4().hex,
                "created_by": actor.name,
                "created_at": utcnow(),
            }
        )
        generation = self.state.current_generation()
        previous = self.state.get_connection(conn.tenancy_ocid, conn.purpose)
        self.state.save_connection(conn, generation)
        if (
            conn.purpose is ConnectionPurpose.SCAN
            and previous is not None
            and _identity(previous) != _identity(conn)
        ):
            # A different scan principal: fence work started under the old one and require
            # every capability to be verified again (control-plane §6.1 step 4, §2.6).
            self.state.revoke_all_leases()
            self.state.mark_capabilities_untested(generation)
        old_ref = previous.secret_ref if previous else None
        if old_ref and old_ref.startswith("local:") and old_ref != conn.secret_ref:
            self.state.delete_secret_ciphertext(old_ref.partition(":")[2])
        self.state.record_event(
            actor.name,
            actor.role,
            "connection.save",
            conn.tenancy_ocid,
            "ok",
            {"method": conn.method.value, "purpose": conn.purpose.value},
        )
        return conn

    def connection(self, purpose: ConnectionPurpose) -> Connection | None:
        parent = self.parent()
        return self.state.get_connection(parent.ocid, purpose) if parent else None

    # --- discovery ----------------------------------------------------------------------
    def discover_children(self, clients: ClientMaker, actor: Actor) -> DiscoveryResult:
        """List the parent's Organization(s) and register children as ``discovered``.

        Calls ``OrganizationClient.list_organizations`` / ``list_organization_tenancies`` in the
        parent's home region. Existing onboarding status is preserved.
        """
        generation = self.state.current_generation()
        parent = self.require_parent()
        org_client: Any = clients(
            oci.tenant_manager_control_plane.OrganizationClient, parent.home_region
        )
        result = DiscoveryResult()
        try:
            orgs = discover_organizations(org_client, parent.ocid)
        except oci.exceptions.ServiceError as exc:
            result.message = (
                "No Organization found or not permitted: "
                + explain_discovery_error(exc)
                + ". You can still register children manually by OCID."
            )
            self.state.record_event(
                actor.name,
                actor.role,
                "org.discover",
                parent.ocid,
                "error",
                {"error": result.message},
            )
            return result
        result.organizations = len(orgs)
        for org in orgs:
            for t in org.tenancies:
                if t.tenancy_ocid == parent.ocid or t.role.upper() == "PARENT":
                    continue
                existing = self.state.get_tenancy(t.tenancy_ocid)
                org_fields: dict[str, Any] = {
                    "name": t.name,
                    "org_role": OrgRole.CHILD,
                    "organization_id": org.id,
                    "parent_tenancy_ocid": parent.ocid,
                    "lifecycle_state": t.lifecycle_state,
                    "governance_status": t.governance_status,
                }
                if existing is not None and existing.parent_tenancy_ocid == parent.ocid:
                    # Keep everything OSC knows (alias, status, regions, scan times).
                    child = existing.model_copy(update=org_fields)
                else:
                    child = Tenancy(
                        ocid=t.tenancy_ocid,
                        alias=self._unique_alias(t.name, exclude=t.tenancy_ocid),
                        onboarding_status=OnboardingStatus.DISCOVERED,
                        **org_fields,
                    )
                self.state.upsert_tenancy(child, generation)
                result.children.append(child)
        if not orgs:
            result.message = "The parent tenancy has no Organization. Register children by OCID."
        self.state.record_event(
            actor.name,
            actor.role,
            "org.discover",
            parent.ocid,
            "ok",
            {"organizations": len(orgs), "children": len(result.children)},
        )
        return result

    def _available_alias(
        self, base: str, exclude: str | None = None, retained_parent: str | None = None
    ) -> str:
        taken = {
            t.alias
            for t in self.state.list_tenancies()
            if t.ocid != exclude
            and (retained_parent is None or t.parent_tenancy_ocid == retained_parent)
        }
        alias, n = base, 2
        while alias in taken:
            alias, n = f"{base}_{n}", n + 1
        return alias

    def _unique_alias(self, name: str, exclude: str | None = None) -> str:
        return self._available_alias("osc_" + tpl.make_alias(name).lower(), exclude)

    def children(self) -> list[Tenancy]:
        """Children of the configured parent only."""
        parent_ocid = self.state.get_setting(SETTING_PARENT)
        return [
            t
            for t in self.state.list_tenancies()
            if t.org_role is OrgRole.CHILD and t.parent_tenancy_ocid == parent_ocid
        ]

    def register_child(self, ocid: str, name: str, actor: Actor) -> Tenancy:
        generation = self.state.current_generation()
        parent = self.require_parent()
        existing = self.state.get_tenancy(ocid)
        if existing is not None:
            what = "the parent tenancy" if ocid == parent.ocid else f"'{existing.name}'"
            raise ControlPlaneError(f"that OCID is already registered as {what}")
        child = Tenancy(
            ocid=ocid,
            name=name,
            alias=self._unique_alias(name),
            org_role=OrgRole.CHILD,
            parent_tenancy_ocid=parent.ocid,
            onboarding_status=OnboardingStatus.PENDING,
        )
        self.state.upsert_tenancy(child, generation)
        self.state.record_event(actor.name, actor.role, "child.register", ocid, "ok", {})
        return child

    def select_child(self, ocid: str, actor: Actor, alias: str | None = None) -> Tenancy:
        generation = self.state.current_generation()
        child = self._child(ocid)
        updates: dict[str, Any] = {}
        if child.onboarding_status is OnboardingStatus.DISCOVERED:
            updates["onboarding_status"] = OnboardingStatus.PENDING
        if alias:
            clean = tpl.make_alias(alias)
            if any(t.alias == clean and t.ocid != ocid for t in self.state.list_tenancies()):
                raise ControlPlaneError(f"alias {clean!r} is already used")
            updates["alias"] = clean
            if clean != child.alias and child.onboarding_status is not OnboardingStatus.DISCOVERED:
                # Statements already applied use the old alias; they must be redone + verified.
                updates["onboarding_status"] = OnboardingStatus.PENDING
                updates["status_detail"] = (
                    f"alias changed from {child.alias} to {clean}: apply the updated Endorse "
                    "and Admit statements, then verify again"
                )
        child = child.model_copy(update=updates)
        self.state.upsert_tenancy(child, generation)
        self.state.record_event(
            actor.name, actor.role, "child.select", ocid, "ok", {"alias": child.alias}
        )
        return child

    def _child(self, ocid: str) -> Tenancy:
        child = self.state.get_tenancy(ocid)
        if (
            child is None
            or child.org_role is not OrgRole.CHILD
            or child.parent_tenancy_ocid != self.state.get_setting(SETTING_PARENT)
        ):
            raise ControlPlaneError("unknown child tenancy")
        return child

    def selected_children(self) -> list[Tenancy]:
        return [
            c for c in self.children() if c.onboarding_status is not OnboardingStatus.DISCOVERED
        ]

    # --- principals ---------------------------------------------------------------------
    def principals(self, clients: ClientMaker | None = None) -> PrincipalInfo:
        """Resolve scanner/admin group OCIDs in the parent (read-only, best effort)."""
        generation = self.state.current_generation()
        parent = self.require_parent()
        cached = self.state.get_setting(SETTING_GROUP_OCIDS)
        names: dict[str, str] = json.loads(cached) if cached else {}
        if clients is not None:
            try:
                identity: Any = clients(oci.identity.IdentityClient, parent.home_region)
                fresh: dict[str, str] = {}
                for g in idc.list_groups(identity, parent.ocid):
                    fresh[f"default/{g['name']}".lower()] = g["id"]
                for g in idc.list_dynamic_groups(identity, parent.ocid):
                    fresh[f"default/{g['name']}".lower()] = g["id"]
                names = fresh
                self.state.set_setting(SETTING_GROUP_OCIDS, json.dumps(fresh), generation)
            except oci.exceptions.ServiceError as exc:
                log.warning("cannot resolve group OCIDs: %s", explain_service_error(exc))
        s = self.settings
        domain = (s.identity_domain_name or "default").lower()
        scanner_name = s.dynamic_group_scanner if s.scanner_is_dynamic_group else s.group_scanners
        scanner = tpl.scanner_principal(s, names.get(f"{domain}/{scanner_name}".lower()))
        admins = tpl.admins_principal(s, names.get(f"{domain}/{s.group_admins}".lower()))
        return PrincipalInfo(scanner, admins, names)

    def _admin_browse(self) -> bool:
        return self.state.get_setting(SETTING_ADMIN_BROWSE) == "true"

    # --- policy screens -----------------------------------------------------------------
    def parent_policy_views(self, principals: PrincipalInfo) -> list[PolicyView]:
        """Organization configuration screen: osc-parent-access + osc-endorse-children."""
        parent = self.require_parent()
        access = tpl.parent_requirements(
            self.settings, parent, principals.scanner, principals.admins
        )
        endorse: list[PolicyRequirement] = []
        for child in self.selected_children():
            endorse += tpl.endorse_requirements(
                self.settings,
                parent,
                child,
                principals.scanner,
                principals.admins,
                self._admin_browse(),
            )
        views = [self._view(parent.ocid, tpl.POLICY_PARENT_ACCESS, access)]
        if endorse:
            views.append(self._view(parent.ocid, tpl.POLICY_ENDORSE_CHILDREN, endorse))
        return views

    def child_policy_views(
        self, child_ocid: str, principals: PrincipalInfo
    ) -> tuple[PolicyView, PolicyView]:
        """Child configuration screen: (parent Endorse view, child Admit view)."""
        parent = self.require_parent()
        child = self._child(child_ocid)
        browse = self._admin_browse()
        endorse = tpl.endorse_requirements(
            self.settings, parent, child, principals.scanner, principals.admins, browse
        )
        admit = tpl.admit_requirements(
            self.settings, parent, child, principals.scanner, principals.admins, browse
        )
        return (
            self._view(parent.ocid, tpl.POLICY_ENDORSE_CHILDREN, endorse),
            self._view(child.ocid, tpl.POLICY_ADMIT_PARENT, admit),
        )

    def _view(self, where: str, name: str, reqs: list[PolicyRequirement]) -> PolicyView:
        checks = self.state.get_checks([r.id for r in reqs])
        return PolicyView(where, name, reqs, checks, tpl.cli_command(where, name, reqs))

    # --- checks -------------------------------------------------------------------------
    def _root_policies(
        self, clients: ClientMaker, tenancy_ocid: str, region: str | None
    ) -> list[PolicyRecord]:
        identity: Any = clients(oci.identity.IdentityClient, region)
        return [
            PolicyRecord(p["id"], p["name"], tuple(p.get("statements") or ()))
            for p in idc.list_policies(identity, tenancy_ocid)
        ]

    def refresh_parent_checks(self, clients: ClientMaker, actor: Actor) -> list[RequirementCheck]:
        """Read the parent's root policies and check every parent-side requirement."""
        generation = self.state.current_generation()  # fences the writes below
        parent = self.require_parent()
        principals = self.principals(clients)
        reqs = [r for v in self.parent_policy_views(principals) for r in v.requirements]
        check_error: str | None = None
        try:
            policies = self._root_policies(clients, parent.ocid, parent.home_region)
            checks = check_requirements(reqs, policies, principals.names_to_ocids)
        except oci.exceptions.ServiceError as exc:
            check_error = explain_service_error(exc)
            checks = unknown_checks(reqs, check_error)
        self.state.save_checks(parent.ocid, parent.ocid, checks, generation)
        self._coverage_findings(
            generation, parent.ocid, SCOPE_PARENT_POLICIES, reqs, checks, check_error=check_error
        )
        self.state.record_event(
            actor.name, actor.role, "policies.check", parent.ocid, "ok", {"checked": len(checks)}
        )
        return checks

    def verify_child(
        self, scan_clients: ClientMaker, child_ocid: str, actor: Actor
    ) -> VerifyResult:
        """Smoke test as the scan identity; on success, confirm the child's Admit statements."""
        generation = self.state.current_generation()  # fences the writes below
        parent = self.require_parent()
        child = self._child(child_ocid)
        result = verify_tenancy(scan_clients, child.ocid, child.home_region or parent.home_region)
        home = result.home_region or child.home_region or parent.home_region
        principals = self.principals(scan_clients)
        _, admit_view = self.child_policy_views(child.ocid, principals)
        admit_reqs = admit_view.requirements
        check_error: str | None = None
        if result.ok:
            try:
                policies = self._root_policies(scan_clients, child.ocid, home)
                checks = check_requirements(admit_reqs, policies, principals.names_to_ocids)
            except oci.exceptions.ServiceError as exc:
                check_error = explain_service_error(exc)
                checks = unknown_checks(admit_reqs, check_error)
            status, detail = OnboardingStatus.VERIFIED, result.summary
        else:
            checks = unknown_checks(admit_reqs, "will be confirmed by Verify once access works")
            status, detail = OnboardingStatus.ERROR, result.summary
        self.state.save_checks(child.ocid, child.ocid, checks, generation)
        updates: dict[str, Any] = {
            "onboarding_status": status,
            "status_detail": detail,
            "last_verified_at": utcnow() if result.ok else child.last_verified_at,
        }
        if result.home_region:
            updates["home_region"] = result.home_region
            updates["subscribed_regions"] = result.subscribed_regions
        self.state.upsert_tenancy(child.model_copy(update=updates), generation)
        self._coverage_findings(
            generation,
            child.ocid,
            SCOPE_CHILD_ACCESS,
            admit_reqs,
            checks,
            access_ok=result.ok,
            check_error=check_error,
        )
        self.state.record_event(
            actor.name,
            actor.role,
            "child.verify",
            child.ocid,
            "ok" if result.ok else "error",
            {"summary": detail},
        )
        return result

    def activate_child(self, child_ocid: str, actor: Actor) -> Tenancy:
        generation = self.state.current_generation()
        child = self._child(child_ocid)
        if child.onboarding_status not in (OnboardingStatus.VERIFIED, OnboardingStatus.ACTIVE):
            raise ControlPlaneError("verify the child before activating it")
        child = child.model_copy(update={"onboarding_status": OnboardingStatus.ACTIVE})
        self.state.upsert_tenancy(child, generation)
        self.state.record_event(actor.name, actor.role, "child.activate", child_ocid, "ok", {})
        return child

    def _coverage_findings(
        self,
        generation: int,
        tenancy_ocid: str,
        scope_key: str,
        reqs: list[PolicyRequirement],
        checks: list[RequirementCheck],
        access_ok: bool = True,
        check_error: str | None = None,
    ) -> None:
        """Raise OSC-ACCESS-001 findings for one evaluation scope (parent policies or one child's
        access). Fails closed: absent findings are resolved only after a complete check of that
        scope; when access or the policy read fails, open findings stay open."""
        by_id = {r.id: r for r in reqs}

        def finding(subject: str, stage: str, title: str, description: str) -> Finding:
            return Finding(
                source=FindingSource.COVERAGE,
                tenancy_ocid=tenancy_ocid,
                rule_id=ACCESS_RULE,
                identity={"rule": ACCESS_RULE, "subject": subject, "stage": stage},
                generation=generation,
                scope_key=scope_key,
                severity=Severity.HIGH,
                title=title,
                description=description,
            )

        findings: list[Finding] = []
        if check_error is not None:
            findings.append(
                finding(
                    "policy_read",
                    "policy_read",
                    "OSC cannot check its access policies — coverage unknown",
                    f"Reading the root policies failed: {check_error}",
                )
            )
        if not access_ok:
            findings.append(
                finding(
                    "smoke_test",
                    "verify",
                    "OSC cannot access this tenancy — not scanned",
                    "The read-only smoke test failed. See the child configuration screen for "
                    "the failing call and the required policies.",
                )
            )
        for c in checks:
            req = by_id.get(c.requirement_id)
            if req is None or req.optional or c.status is not CheckStatus.MISSING:
                continue
            findings.append(
                finding(
                    req.id,
                    "missing_grant",
                    "OSC access policy missing — tenancy partially or not scanned",
                    f"Missing in policy '{req.policy_name}': {req.statement}",
                )
            )
        if findings:
            self.stores.data.upsert_findings(findings)
        if not access_ok or check_error is not None:
            return
        self.stores.data.resolve_absent(
            generation,
            FindingSource.COVERAGE,
            tenancy_ocid,
            ACCESS_RULE,
            scope_key,
            {f.finding_id for f in findings},
        )

    def set_admin_browse(self, enabled: bool, actor: Actor) -> None:
        self.state.set_setting(
            SETTING_ADMIN_BROWSE,
            "true" if enabled else "false",
            self.state.current_generation(),
        )
        self.state.record_event(
            actor.name, actor.role, "settings.admin_browse", None, "ok", {"enabled": enabled}
        )


def _identity(conn: Connection) -> tuple[object, ...]:
    """What makes two connections the same OCI principal."""
    return (
        conn.method,
        conn.region,
        conn.cli_config_path,
        conn.cli_profile,
        conn.user_ocid,
        conn.fingerprint,
        conn.secret_ref,
    )


def explain_discovery_error(exc: oci.exceptions.ServiceError) -> str:
    """Discovery runs in the parent, so cross-tenancy causes don't apply to a 404 here."""
    if exc.status == 404:
        return (
            "404 NotAuthorizedOrNotFound — the identity used for discovery can't list the "
            "parent's Organization. Check that it has 'read organizations-family' in the parent "
            "(policy osc-parent-access), and that this tenancy is the parent of an OCI "
            "Organization (Governance & Administration → Organization Management)"
        )
    return explain_service_error(exc)


ClientsProvider = Callable[[ConnectionPurpose], ClientMaker]
