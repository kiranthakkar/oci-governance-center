"""``osc`` command line. Read-only against OCI.

osc admin bootstrap ...      setup on the host (parent + connections); a new parent replaces
                             the previous organization and removes its local data
osc admin recover            finish/roll back an interrupted organization switch
osc org discover             list the Organization's child tenancies
osc org show                 tenancies and onboarding status
osc policies parent [--check]
osc policies child <ocid>
osc child select|verify|activate <ocid>
osc findings list
osc db purge | backup <path>
osc scan [--tier N] [--only datasets] [--tenancy ocid]
osc audit ingest | reconcile
osc scheduler [--once]
osc web
"""

from __future__ import annotations

import getpass
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import typer

from oci_security_center.auth.policy import validate_connections
from oci_security_center.auth.secrets import PENDING_LOCAL_REF, SecretError
from oci_security_center.auth.signers import AuthError
from oci_security_center.config import get_settings
from oci_security_center.control_plane.service import Actor, ControlPlaneError, PolicyView
from oci_security_center.logging import configure_logging
from oci_security_center.models import (
    CheckStatus,
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    FindingStatus,
    is_ocid,
)
from oci_security_center.oci_clients import ClientFactory
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.storage.errors import StorageError

app = typer.Typer(help="OCI Security Center (read-only).", no_args_is_help=True)
admin_app = typer.Typer(help="Setup and administration.", no_args_is_help=True)
org_app = typer.Typer(help="Organization and tenancies.", no_args_is_help=True)
pol_app = typer.Typer(help="Policies OSC needs (displayed, never applied).", no_args_is_help=True)
child_app = typer.Typer(help="Child onboarding.", no_args_is_help=True)
findings_app = typer.Typer(help="Findings.", no_args_is_help=True)
db_app = typer.Typer(help="Local SQLite storage.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit event ingestion.", no_args_is_help=True)
for sub, name in [
    (audit_app, "audit"),
    (admin_app, "admin"),
    (org_app, "org"),
    (pol_app, "policies"),
    (child_app, "child"),
    (findings_app, "findings"),
    (db_app, "db"),
]:
    app.add_typer(sub, name=name)

_ICON = {
    CheckStatus.DETECTED: "[ok]     ",
    CheckStatus.BROADER: "[broad]  ",
    CheckStatus.MISSING: "[MISSING]",
    CheckStatus.UNKNOWN: "[?]      ",
}


class AdminMethod(StrEnum):
    oidc = "oidc"
    cli_profile = "cli_profile"
    api_key = "api_key"
    none = "none"


class ScanMethod(StrEnum):
    instance_principal = "instance_principal"
    resource_principal = "resource_principal"
    cli_profile = "cli_profile"
    api_key = "api_key"


def _rt() -> Runtime:
    configure_logging("WARNING")
    return build_runtime(get_settings())


def _actor() -> Actor:
    return Actor(f"cli:{getpass.getuser()}", "admin")


def _fail(msg: str) -> None:
    typer.secho(msg, fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


def _print_view(view: PolicyView, heading: str) -> None:
    typer.secho(f"\n== {heading}", bold=True)
    typer.echo(f"   policy '{view.policy_name}' in root compartment of {view.tenancy_ocid}")
    for req in view.requirements:
        check = view.checks.get(req.id)
        status = check.status if check else CheckStatus.UNKNOWN
        opt = " (optional)" if req.optional else ""
        typer.echo(f"   {_ICON[status]} {req.statement}{opt}")
    typer.echo("\n   OCI CLI command for the IAM admin:\n")
    typer.echo("\n".join("   " + line for line in view.cli.splitlines()))


@admin_app.command("bootstrap")
def bootstrap(
    tenancy_ocid: str = typer.Option(..., help="Parent tenancy OCID"),
    name: str = typer.Option("", help="Display name (defaults to the tenancy name)"),
    scan_method: ScanMethod = typer.Option(ScanMethod.cli_profile, help="Scan identity"),
    admin_method: AdminMethod = typer.Option(
        AdminMethod.none, help="Admin sign-in connection for the web UI"
    ),
    region: str = typer.Option("", help="Region for API calls (default: profile/home region)"),
    profile: str = typer.Option("DEFAULT", help="OCI CLI profile (cli_profile)"),
    config_file: str = typer.Option("~/.oci/config", help="OCI CLI config file (cli_profile)"),
    user_ocid: str = typer.Option("", help="API key user OCID (api_key)"),
    fingerprint: str = typer.Option("", help="API key fingerprint (api_key)"),
    key_file: Path | None = typer.Option(None, help="PEM private key to store encrypted (api_key)"),
    key_secret_ocid: str = typer.Option("", help="Vault secret OCID holding the PEM (api_key)"),
    domain_url: str = typer.Option("", help="Identity domain URL (oidc)"),
    client_id: str = typer.Option("", help="Integrated app client ID (oidc)"),
    client_secret_ocid: str = typer.Option(
        "", help="Vault secret OCID with the client secret (oidc); otherwise you are prompted"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Don't ask before replacing the current organization"
    ),
) -> None:
    """Register the parent tenancy and its connections, then discover children.

    OSC serves one organization per deployment. Bootstrapping a different parent replaces the
    current organization: once the new connection test passes, all local data for the previous
    parent and its children is deleted (the control-plane activity log is kept).
    """
    if not is_ocid(tenancy_ocid):
        _fail("--tenancy-ocid is not an OCID")
    rt = _rt()
    actor = _actor()
    cp = rt.control_plane
    stored: list[str] = []  # local secrets created by this run; removed again if it fails

    def store(pending: _Pending) -> Connection:
        if pending.secret is None:
            return pending.conn
        ref = rt.secrets.store_local(pending.secret)
        stored.append(ref)
        return pending.conn.model_copy(update={"secret_ref": ref})

    try:
        # 1. Preflight the whole candidate configuration before anything changes (§6.1 step 1).
        scan_p = _make_connection(
            tenancy_ocid,
            ConnectionPurpose.SCAN,
            scan_method.value,
            region,
            profile,
            config_file,
            user_ocid,
            fingerprint,
            key_file,
            key_secret_ocid,
            "",
            "",
            "",
        )
        admin_p: _Pending | None = None
        if admin_method is not AdminMethod.none:
            method = (
                "oidc_token_exchange" if admin_method is AdminMethod.oidc else admin_method.value
            )
            admin_p = _make_connection(
                tenancy_ocid,
                ConnectionPurpose.ADMIN,
                method,
                region,
                profile,
                config_file,
                user_ocid,
                fingerprint,
                key_file,
                key_secret_ocid,
                domain_url,
                client_id,
                client_secret_ocid,
            )
        current = cp.parent()
        kept_admin = (
            cp.connection(ConnectionPurpose.ADMIN)
            if admin_p is None and current is not None and current.ocid == tenancy_ocid
            else None
        )
        validate_connections(rt.settings, scan_p.conn, admin_p.conn if admin_p else kept_admin)

        # 2. Show what a replacement deletes and ask.
        replaced = cp.replaced_tenancies(tenancy_ocid)
        if replaced:
            typer.secho(
                "This replaces the current organization. After the connection test passes, OSC "
                "deletes its local data (connections, children, policy checks, findings, "
                "collected data, audit files) and signs everyone out of the web UI. Existing "
                "backups are kept under their own retention:",
                fg=typer.colors.YELLOW,
            )
            for t in replaced:
                typer.echo(f"   {t.org_role.value:<7} {t.name}  {t.ocid}")
            if not yes and not typer.confirm("Continue?", default=False):
                raise typer.Exit(1)

        # 3. Connection test, then (only if it passes) the fenced replacement.
        from oci_security_center.auth.signers import build_auth

        scan = store(scan_p)
        clients = ClientFactory(build_auth(scan, rt.settings, rt.secrets))
        candidates = (scan,) + ((store(admin_p),) if admin_p is not None else ())
        parent = cp.connect_parent(clients, tenancy_ocid, name or None, actor, candidates)
        for warning in cp.replace_warnings:
            typer.secho(f"Warning: {warning} — remove it by hand.", fg=typer.colors.YELLOW)
        stored.clear()  # now owned by saved connections
        typer.secho(
            f"Parent '{parent.name}' connected (home region {parent.home_region}).",
            fg=typer.colors.GREEN,
        )
        result = cp.discover_children(clients, actor)
        typer.echo(result.message or f"Discovered {len(result.children)} child tenancies.")
        typer.echo("Next: `osc policies parent`, then `osc web` to continue in the browser.")
    except (AuthError, ControlPlaneError, SecretError, ValueError) as exc:
        _fail(str(exc))
    finally:
        for ref in stored:
            # A committed switch may fail during quarantine. Its candidate secrets are owned
            # by durable connections and must survive recovery.
            with rt.stores.db.read() as conn:
                owned = conn.execute(
                    "SELECT 1 FROM connections WHERE secret_ref=?", (ref,)
                ).fetchone()
            if not owned:
                rt.stores.state.delete_secret_ciphertext(ref.partition(":")[2])


@admin_app.command("recover")
def admin_recover() -> None:
    """Finish or roll back an interrupted organization switch (control-plane §6.1).

    Runs automatically at startup too; only acts once the interrupted holder's maintenance lease
    has expired.
    """
    from oci_security_center.storage.sqlite.reset import recover_interrupted_switch

    rt = _rt()
    done = recover_interrupted_switch(rt.stores.db, rt.stores.state, rt.stores.data)
    org = rt.stores.state.organization()
    typer.echo(done or "nothing to recover")
    typer.echo(f"organization state: {org.state}, generation {org.generation}")
    if org.state != "active":
        holder = org.maintenance_holder or "?"
        until = org.maintenance_expires_at.isoformat() if org.maintenance_expires_at else "?"
        typer.echo(f"maintenance held by {holder} until {until}")
        raise typer.Exit(2)


@dataclass(frozen=True)
class _Pending:
    """A connection whose local secret (if any) is stored only after preflight passes."""

    conn: Connection
    secret: str | None = None


def _make_connection(
    tenancy_ocid: str,
    purpose: ConnectionPurpose,
    method: str,
    region: str,
    profile: str,
    config_file: str,
    user_ocid: str,
    fingerprint: str,
    key_file: Path | None,
    key_secret_ocid: str,
    domain_url: str,
    client_id: str,
    client_secret_ocid: str,
) -> _Pending:
    m = ConnectionMethod(method)
    secret_ref: str | None = None
    secret: str | None = None
    if m is ConnectionMethod.API_KEY:
        if key_secret_ocid:
            secret_ref = f"vault:{key_secret_ocid}"
        elif key_file:
            secret_ref, secret = PENDING_LOCAL_REF, key_file.expanduser().read_text()
        else:
            raise ValueError("api_key needs --key-file or --key-secret-ocid")
    if m is ConnectionMethod.OIDC_TOKEN_EXCHANGE:
        if not (domain_url.startswith("https://") and client_id):
            raise ValueError("oidc needs --domain-url (https) and --client-id")
        if client_secret_ocid:
            secret_ref = f"vault:{client_secret_ocid}"
        else:
            secret_ref = PENDING_LOCAL_REF
            secret = typer.prompt("Client secret", hide_input=True)
    conn = Connection(
        id="",
        tenancy_ocid=tenancy_ocid,
        method=m,
        purpose=purpose,
        region=region or None,
        cli_config_path=config_file if m is ConnectionMethod.CLI_PROFILE else None,
        cli_profile=profile if m is ConnectionMethod.CLI_PROFILE else None,
        user_ocid=user_ocid or None,
        fingerprint=fingerprint or None,
        secret_ref=secret_ref,
        domain_url=domain_url.rstrip("/") or None,
        client_id=client_id or None,
    )
    return _Pending(conn, secret)


@org_app.command("discover")
def org_discover() -> None:
    """Discover child tenancies from the parent's OCI Organization (read-only)."""
    rt = _rt()
    try:
        result = rt.control_plane.discover_children(rt.admin_clients(), _actor())
    except (AuthError, ControlPlaneError, SecretError) as exc:
        _fail(str(exc))
        return
    typer.echo(result.message or f"{len(result.children)} child tenancies")
    org_show()


@org_app.command("show")
def org_show() -> None:
    """Show the parent and children with onboarding status."""
    rt = _rt()
    for t in rt.stores.state.list_tenancies():
        typer.echo(
            f"{t.org_role.value:<7} {t.onboarding_status.value:<10} {t.alias:<24} "
            f"{t.name}  {t.ocid}"
        )


@pol_app.command("parent")
def policies_parent(check: bool = typer.Option(False, help="Re-check against OCI first")) -> None:
    """Everything OSC needs in the parent tenancy (Organization configuration screen)."""
    rt = _rt()
    cp = rt.control_plane
    try:
        if check:
            clients = rt.admin_clients()
            cp.principals(clients)
            cp.refresh_parent_checks(clients, _actor())
        for view in cp.parent_policy_views(cp.principals(None)):
            _print_view(view, "Parent tenancy")
    except (AuthError, ControlPlaneError, SecretError) as exc:
        _fail(str(exc))


@pol_app.command("child")
def policies_child(ocid: str) -> None:
    """Endorse (parent) and Define/Admit (child) statements for one child."""
    rt = _rt()
    try:
        endorse, admit = rt.control_plane.child_policy_views(
            ocid, rt.control_plane.principals(None)
        )
    except ControlPlaneError as exc:
        _fail(str(exc))
        return
    _print_view(endorse, "Parent tenancy — Endorse")
    _print_view(admit, "Child tenancy — Define and Admit (for the child's IAM admin)")


@child_app.command("select")
def child_select(ocid: str, alias: str = typer.Option("", help="Alias for policies")) -> None:
    rt = _rt()
    try:
        child = rt.control_plane.select_child(ocid, _actor(), alias or None)
    except ControlPlaneError as exc:
        _fail(str(exc))
        return
    typer.echo(f"{child.name}: {child.onboarding_status.value} (alias {child.alias})")
    typer.echo(f"Next: `osc policies child {ocid}`")


@child_app.command("verify")
def child_verify(ocid: str) -> None:
    """Read-only smoke test in the child as the scan identity."""
    rt = _rt()
    try:
        result = rt.control_plane.verify_child(rt.scan_clients(), ocid, _actor())
    except (AuthError, ControlPlaneError, SecretError) as exc:
        _fail(str(exc))
        return
    for s in result.steps:
        mark = "ok  " if s.ok else ("warn" if not s.required else "FAIL")
        typer.echo(f"[{mark}] {s.name}: {s.detail}")
    if not result.ok:
        raise typer.Exit(2)


@child_app.command("activate")
def child_activate(ocid: str) -> None:
    rt = _rt()
    try:
        rt.control_plane.activate_child(ocid, _actor())
    except ControlPlaneError as exc:
        _fail(str(exc))
    typer.echo("Active.")


@findings_app.command("list")
def findings_list(status: str = typer.Option("open")) -> None:
    rt = _rt()
    st = FindingStatus(status) if status in {s.value for s in FindingStatus} else None
    for f in rt.stores.data.list_findings(status=st):
        typer.echo(f"{f.severity.value:<8} {f.tenancy_ocid}  {f.title}\n         {f.description}")


@db_app.command("purge")
def db_purge() -> None:
    """Apply retention (default 90 days)."""
    from oci_security_center.storage.sqlite.retention import purge

    rt = _rt()
    result = purge(rt.settings, rt.stores.db, rt.stores.data)
    typer.echo(f"rows: {sum(result.rows_deleted.values())}, files: {len(result.files_deleted)}")


@db_app.command("backup")
def db_backup(dest: Path) -> None:
    """Full backup (osc.db + audit files + manifest) into DEST/osc-backup-<time>/ (storage §6.1).

    Takes the maintenance barrier briefly; read-only pages keep working. Protect DEST like the live
    data and keep the encryption key separately — it is not in the backup.
    """
    from oci_security_center.auth.secrets import load_fernet_key
    from oci_security_center.storage.sqlite.backup import create_backup

    rt = _rt()
    try:
        path = create_backup(
            rt.settings,
            rt.stores.db,
            rt.stores.state,
            load_fernet_key(rt.settings),
            dest.expanduser(),
        )
    except (StorageError, OSError) as exc:
        _fail(f"backup failed: {exc}")
        return
    typer.echo(f"backup written to {path}")


@db_app.command("restore")
def db_restore(
    backup_dir: Path,
    expect_parent: str = typer.Option("", help="Refuse unless the backup is of this parent OCID"),
    main_db_only: bool = typer.Option(
        False, help="Partial restore without audit files (audit is fetched again)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation"),
) -> None:
    """Restore a backup OFFLINE: stop `osc web` and `osc scheduler` first.

    Everything is validated before anything changes; the current data is kept aside as
    <data root>.pre-restore-<time>.
    """
    from oci_security_center.auth.secrets import load_fernet_key
    from oci_security_center.storage.sqlite.backup import restore_backup, validate_backup

    settings = get_settings()
    configure_logging("WARNING")
    key = load_fernet_key(settings)
    try:
        manifest = validate_backup(backup_dir.expanduser(), key, main_db_only)
    except (StorageError, OSError, ValueError) as exc:
        _fail(f"backup can't be restored: {exc}")
        return
    typer.echo(
        f"Backup {manifest['backup_id']} of parent {manifest['parent_tenancy_ocid']}, "
        f"created {manifest['created_at']}, {len(manifest['files'])} files."
    )
    if not yes and not typer.confirm(
        f"Replace the data in {settings.data_root}? OSC must be stopped.", default=False
    ):
        raise typer.Exit(1)
    try:
        result = restore_backup(
            settings, backup_dir.expanduser(), key, expect_parent or None, main_db_only
        )
    except (StorageError, OSError, ValueError) as exc:
        _fail(f"restore failed, nothing changed: {exc}")
        return
    typer.secho(
        f"Restored into {result.data_root} (generation {result.generation}).", fg=typer.colors.GREEN
    )
    if result.previous:
        typer.echo(f"Previous data kept at {result.previous}")
    for note in result.notes:
        typer.echo(f"Note: {note}")


@app.command("scan")
def scan(
    tier: int = typer.Option(0, help="Collection tier (default: OSC_COLLECTION_TIER)"),
    only: str = typer.Option("", help="Comma-separated datasets, e.g. identity.policies"),
    tenancy: str = typer.Option("", help="Only this tenancy OCID"),
    audit: bool = typer.Option(True, help="Also ingest audit events"),
) -> None:
    """Collect now (read-only), as the scan identity. Exit code 2 if anything was incomplete."""
    from oci_security_center.collection.audit import AuditIngestor
    from oci_security_center.collection.registry import collectors_for_tier
    from oci_security_center.collection.runner import ScanRunner

    rt = _rt()
    selected = {d.strip() for d in only.split(",") if d.strip()} or None
    tenancies = {tenancy} if tenancy else None
    try:
        clients = rt.scan_clients()
        collectors = collectors_for_tier(tier or rt.settings.collection_tier)
        summary = ScanRunner(rt.settings, rt.stores, clients, collectors).scan(
            only=selected, tenancy_ocids=tenancies, trigger="cli"
        )
        outcomes = list(summary.outcomes)
        if audit and (selected is None or "audit.events" in selected):
            outcomes += (
                AuditIngestor(rt.settings, rt.stores, clients)
                .ingest(tenancy_ocids=tenancies)
                .outcomes
            )
    except (AuthError, ControlPlaneError, SecretError, StorageError) as exc:
        _fail(str(exc))
        return
    names = {t.ocid: t.name for t in rt.stores.state.list_tenancies()}
    for o in outcomes:
        scope = "" if o.scope_key == "{}" else f" {o.scope_key}"
        colour = typer.colors.GREEN if o.status in ("ok", "not_applicable") else typer.colors.YELLOW
        typer.secho(
            f"{o.status:<18} {names.get(o.tenancy_ocid, o.tenancy_ocid):<20} {o.dataset}{scope}"
            + (f"  — {o.detail}" if o.detail else ""),
            fg=colour,
        )
    if any(o.status not in ("ok", "not_applicable", "skipped") for o in outcomes):
        raise typer.Exit(2)


@audit_app.command("ingest")
def audit_ingest(tenancy: str = typer.Option("", help="Only this tenancy OCID")) -> None:
    """Fetch new audit events (forward, then backfill)."""
    _audit_run(tenancy, reconcile=False)


@audit_app.command("reconcile")
def audit_reconcile(tenancy: str = typer.Option("", help="Only this tenancy OCID")) -> None:
    """Re-read retained audit intervals to pick up late events (never moves checkpoints)."""
    _audit_run(tenancy, reconcile=True)


def _audit_run(tenancy: str, reconcile: bool) -> None:
    from oci_security_center.collection.audit import AuditIngestor

    rt = _rt()
    try:
        summary = AuditIngestor(rt.settings, rt.stores, rt.scan_clients()).ingest(
            tenancy_ocids={tenancy} if tenancy else None, reconcile=reconcile
        )
    except (AuthError, SecretError, StorageError) as exc:
        _fail(str(exc))
        return
    for o in summary.outcomes:
        typer.echo(f"{o.status:<18} {o.tenancy_ocid}  {o.scope_key}  {o.detail}")
    if not summary.ok:
        raise typer.Exit(2)


@app.command("scheduler")
def scheduler(once: bool = typer.Option(False, help="Run every job once and exit")) -> None:
    """Run collection on its schedule (separate process from `osc web`)."""
    import signal

    from oci_security_center.collection.scheduler import Scheduler

    configure_logging("INFO")
    rt = build_runtime(get_settings())
    sched = Scheduler(rt)
    if once:
        typer.echo("ran: " + ", ".join(sched.tick()))
        return
    signal.signal(signal.SIGTERM, lambda *_: sched.stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: sched.stop_event.set())
    sched.serve_forever()


@app.command("web")
def web(host: str = typer.Option(None), port: int = typer.Option(None)) -> None:
    """Run the web UI."""
    import uvicorn

    from oci_security_center.web.app import create_app

    settings = get_settings()
    configure_logging("INFO")
    uvicorn.run(
        create_app(settings),
        host=host or settings.web_host,
        port=port or settings.web_port,
        proxy_headers=False,
        # Use OSC's JSON logging (with redaction) for uvicorn's access and error logs too;
        # uvicorn's default handlers would log the OIDC callback's ?code= unredacted.
        log_config=None,
    )


@app.command("version")
def version() -> None:
    from oci_security_center import __version__

    typer.echo(__version__)
