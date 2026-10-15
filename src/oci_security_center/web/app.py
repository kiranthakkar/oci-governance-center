"""FastAPI web app: sign-in, Organization configuration and Child configuration screens.

Every route is authorized server-side. State-changing routes are POST + CSRF. OSC never writes to
OCI; the "apply" step for policies is always a human with copy / download / CLI command.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from oci_security_center.auth.policy import allowed_methods, validate_connections
from oci_security_center.auth.secrets import PENDING_LOCAL_REF, SecretError
from oci_security_center.auth.signers import AuthError
from oci_security_center.config import DeploymentMode, Settings, get_settings
from oci_security_center.control_plane import policy_templates as tpl
from oci_security_center.control_plane.service import (
    SETTING_TOKEN_EXCHANGE_OK,
    Actor,
    ControlPlaneError,
    PolicyView,
    PrincipalInfo,
)
from oci_security_center.logging import get_logger
from oci_security_center.models import (
    CheckStatus,
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    FindingStatus,
    OnboardingStatus,
    is_ocid,
)
from oci_security_center.oci_clients import ClientMaker
from oci_security_center.runtime import Runtime, build_runtime
from oci_security_center.web import dashboards
from oci_security_center.web.security import (
    ROLE_ADMIN,
    LoginRateLimiter,
    LoginRequired,
    MaintenanceMiddleware,
    SecurityHeadersMiddleware,
    TrustedHostMiddleware,
    User,
    csrf_token,
    current_user,
    establish_session,
    jwt_provider_for,
    local_login_allowed,
    require_admin,
    require_user,
    role_from_groups,
    verify_csrf,
)
from oci_security_center.web.sessions import ServerSideSessionMiddleware

log = get_logger(__name__)
HERE = Path(__file__).parent

_FRIENDLY_ERRORS = (ControlPlaneError, AuthError, SecretError)


def create_app(settings: Settings | None = None, runtime: Runtime | None = None) -> FastAPI:
    settings = settings or get_settings()
    secure = settings.public_base_url.startswith("https://")
    if settings.deployment is DeploymentMode.OCI and not secure:
        raise RuntimeError("OSC_PUBLIC_BASE_URL must be https:// in oci deployment mode")
    rt = runtime or build_runtime(settings)
    cp = rt.control_plane
    app = FastAPI(title="OCI Security Center", docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals["CheckStatus"] = CheckStatus
    templates.env.globals["OnboardingStatus"] = OnboardingStatus
    templates.env.filters["placeholder"] = tpl.has_placeholder
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.add_middleware(
        ServerSideSessionMiddleware,
        store=rt.stores.state,
        crypto=rt.secrets,
        idle_minutes=settings.session_idle_minutes,
        secure=secure,
        max_hours=settings.session_max_hours,
        generation=rt.stores.state.current_generation,
    )
    app.add_middleware(
        MaintenanceMiddleware,
        in_maintenance=lambda: rt.stores.state.organization().state != "active",
    )
    # Middleware added later runs earlier: foreign Host/Origin is refused before any session
    # work, and security headers wrap every response, refusals included.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(SecurityHeadersMiddleware, hsts=secure)
    limiter = LoginRateLimiter()
    oauth_cache: dict[tuple[str, str], Any] = {}

    # --- helpers --------------------------------------------------------------------------
    def flash(request: Request, message: str, level: str = "info") -> None:
        request.session.setdefault("flash", []).append({"level": level, "message": message})

    def render(request: Request, name: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
        user = current_user(request)
        # Only signed-in pages and the sign-in form need a CSRF token; not creating one for
        # anonymous error pages keeps anonymous traffic from writing session rows.
        ctx.update(
            request=request,
            user=user,
            csrf=csrf_token(request) if user or name == "login.html" else "",
            settings=settings,
            parent=cp.parent(),
            flashes=request.session.pop("flash", []),
            is_admin=bool(user and user.role == ROLE_ADMIN),
        )
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def actor(user: User) -> Actor:
        return Actor(user.name, user.role)

    def oidc_connection() -> Connection | None:
        conn = cp.connection(ConnectionPurpose.ADMIN)
        if conn and conn.method is ConnectionMethod.OIDC_TOKEN_EXCHANGE:
            return conn
        return None

    def oidc_client() -> Any:
        conn = oidc_connection()
        if conn is None or not (conn.domain_url and conn.client_id and conn.secret_ref):
            return None
        key = (conn.domain_url, conn.client_id)
        if key not in oauth_cache:
            oauth = OAuth()
            oauth.register(
                name="oci",
                client_id=conn.client_id,
                client_secret=rt.secrets.resolve(conn.secret_ref),
                server_metadata_url=conn.domain_url.rstrip("/")
                + "/.well-known/openid-configuration",
                client_kwargs={"scope": settings.oidc_scopes, "code_challenge_method": "S256"},
            )
            oauth_cache[key] = oauth.create_client("oci")
        return oauth_cache[key]

    def admin_clients(request: Request, user: User) -> ClientMaker:
        conn = oidc_connection()
        if conn and user.via == "oidc" and conn.client_id and conn.secret_ref:
            provider = jwt_provider_for(
                request, conn.client_id, rt.secrets.resolve(conn.secret_ref), settings
            )
            gen = session_generation(request)
            try:
                clients = rt.admin_clients(provider)  # the signer exchanges the token here
            except AuthError:
                cp.state.set_setting(SETTING_TOKEN_EXCHANGE_OK, "false", gen)
                raise
            cp.state.set_setting(SETTING_TOKEN_EXCHANGE_OK, "true", gen)
            return clients
        return rt.admin_clients(None)

    def session_generation(request: Request) -> int:
        """The organization generation this signed-in session belongs to (write fence)."""
        gen = request.session.get("generation")
        return int(gen) if isinstance(gen, int) else -1

    def principals_cached() -> PrincipalInfo:
        return cp.principals(None)

    def back(path: str) -> RedirectResponse:
        return RedirectResponse(path, status_code=303)

    def child_ocid_or_404(ocid: str) -> str:
        if not is_ocid(ocid):
            raise HTTPException(status_code=404)
        return ocid

    # --- error handling -------------------------------------------------------------------
    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> Response:
        return back("/login")

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> Response:
        # The JSON formatter redacts the traceback; the browser only gets a generic message.
        log.error("unhandled error on %s", request.url.path, exc_info=exc)
        try:
            return render(
                request,
                "error.html",
                status_code=500,
                code=500,
                detail="Something went wrong. The details are in the OSC server log.",
            )
        except Exception:
            return PlainTextResponse("Internal Server Error", status_code=500)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> Response:
        return render(
            request,
            "error.html",
            status_code=exc.status_code,
            code=exc.status_code,
            detail=str(exc.detail),
        )

    # --- public ---------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        if cp.parent() is None:
            return render(request, "setup_required.html")
        user = require_user(request)
        children = cp.children()
        counts: dict[str, int] = {}
        for c in children:
            counts[c.onboarding_status.value] = counts.get(c.onboarding_status.value, 0) + 1
        open_findings = rt.stores.data.list_findings(status=FindingStatus.OPEN)
        return render(
            request,
            "dashboard.html",
            user_obj=user,
            children=children,
            counts=counts,
            open_findings=open_findings[:10],
            severity=rt.stores.data.count_findings_by_severity(),
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login(request: Request) -> Response:
        limiter.check(request)
        if cp.parent() is None:
            return render(request, "setup_required.html")
        return render(
            request,
            "login.html",
            oidc=oidc_connection() is not None,
            local=local_login_allowed(request, settings),
        )

    @app.get("/login/oidc")
    async def login_oidc(request: Request) -> Response:
        limiter.check(request)
        client = oidc_client()
        if client is None:
            raise HTTPException(status_code=404, detail="OIDC sign-in is not configured")
        redirect_uri = settings.public_base_url.rstrip("/") + "/auth/callback"
        return await client.authorize_redirect(request, redirect_uri)  # type: ignore[no-any-return]

    @app.get("/auth/callback")
    async def auth_callback(request: Request) -> Response:
        limiter.check(request)
        client = oidc_client()
        if client is None:
            raise HTTPException(status_code=404)
        try:
            token = await client.authorize_access_token(request)
        except OAuthError as exc:
            log.warning("OIDC callback failed: %s", exc.error)
            raise HTTPException(status_code=401, detail="Sign-in failed") from exc
        claims: dict[str, Any] = dict(token.get("userinfo") or {})
        groups = claims.get(settings.groups_claim)
        if groups is None:
            try:
                groups = dict(await client.userinfo(token=token)).get(settings.groups_claim)
            except Exception:
                groups = None
        name = str(
            claims.get("user_displayname")
            or claims.get("preferred_username")
            or claims.get("email")
            or claims.get("sub")
            or "unknown"
        )
        role = role_from_groups(groups, settings)
        if role is None:
            cp.state.record_event(
                name, "-", "login", None, "denied", {"reason": "not in OSC-Admins/OSC-Viewers"}
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Your account is not in {settings.group_admins} or {settings.group_viewers}. "
                    "If you are, make sure the integrated app includes group claims."
                ),
            )
        if "access_token" not in token:
            raise HTTPException(status_code=401, detail="Sign-in failed")
        tokens = {
            "access_token": token["access_token"],
            "refresh_token": token.get("refresh_token"),
            "expires_at": int(token.get("expires_at", 0)),
            "token_endpoint": client.server_metadata.get("token_endpoint"),
            "userinfo_endpoint": client.server_metadata.get("userinfo_endpoint"),
        }
        establish_session(request, User(name, role, "oidc"), tokens, cp.state.current_generation())
        cp.state.record_event(name, role, "login", None, "ok", {"via": "oidc"})
        return back("/")

    @app.post("/login/local")
    async def login_local(request: Request, _: None = Depends(verify_csrf)) -> Response:
        limiter.check(request)
        if not local_login_allowed(request, settings):
            raise HTTPException(
                status_code=403,
                detail="Local sign-in is only available in workstation mode from this machine",
            )
        establish_session(
            request, User("local-admin", ROLE_ADMIN, "local"), None, cp.state.current_generation()
        )
        cp.state.record_event("local-admin", ROLE_ADMIN, "login", None, "ok", {"via": "local"})
        return back("/")

    @app.post("/logout")
    async def logout(request: Request, _: None = Depends(verify_csrf)) -> Response:
        user = current_user(request)
        if user:
            cp.state.record_event(user.name, user.role, "logout", None, "ok", {})
        request.session.clear()
        request.session["__clear__"] = True
        return back("/login")

    # --- viewer ---------------------------------------------------------------------------
    @app.get("/findings", response_class=HTMLResponse)
    async def findings(
        request: Request, status: str = "open", user: User = Depends(require_user)
    ) -> Response:
        st = FindingStatus(status) if status in {s.value for s in FindingStatus} else None
        items = rt.stores.data.list_findings(status=st)
        names = {t.ocid: t.name for t in cp.state.list_tenancies()}
        return render(request, "findings.html", findings=items, names=names, status=status)

    # --- Tier 1 dashboards (viewers and admins) --------------------------------------------
    def pick_tenancy(tenancy: str) -> Any:
        options = dashboards.tenancies(rt)
        if not options:
            raise HTTPException(status_code=404, detail="No active tenancies yet")
        if not tenancy:
            return options[0], options
        for t in options:
            if t.ocid == tenancy:
                return t, options
        raise HTTPException(status_code=404)

    @app.get("/coverage", response_class=HTMLResponse)
    async def coverage_page(request: Request, user: User = Depends(require_user)) -> Response:
        rows = dashboards.coverage(rt)
        totals: dict[str, int] = {}
        for r in rows:
            totals[r.state] = totals.get(r.state, 0) + 1
        return render(
            request,
            "coverage.html",
            rows=rows,
            totals=sorted(totals.items()),
            runs=rt.stores.data.scan_runs(),
            tier=settings.collection_tier,
        )

    @app.get("/compartments", response_class=HTMLResponse)
    async def compartments_page(
        request: Request, tenancy: str = "", user: User = Depends(require_user)
    ) -> Response:
        t, options = pick_tenancy(tenancy)
        nodes, known = dashboards.compartments(rt, t)
        return render(
            request, "compartments.html", tenancy=t, tenancies=options, nodes=nodes, known=known
        )

    @app.get("/access", response_class=HTMLResponse)
    async def access_page(
        request: Request, tenancy: str = "", user: User = Depends(require_user)
    ) -> Response:
        t, options = pick_tenancy(tenancy)
        return render(
            request, "access.html", tenancy=t, tenancies=options, view=dashboards.access(rt, t)
        )

    @app.get("/governance", response_class=HTMLResponse)
    async def governance_page(request: Request, user: User = Depends(require_user)) -> Response:
        rows, findings_ = dashboards.governance(rt)
        names = {t.ocid: t.name for t in cp.state.list_tenancies()}
        return render(request, "governance.html", rows=rows, findings=findings_, names=names)

    @app.get("/activity", response_class=HTMLResponse)
    async def activity_page(request: Request, user: User = Depends(require_user)) -> Response:
        return render(request, "activity.html", rows=dashboards.activity(rt), days=14)

    # --- admin: organization --------------------------------------------------------------
    @app.get("/admin/organization", response_class=HTMLResponse)
    async def organization(request: Request, user: User = Depends(require_admin)) -> Response:
        parent = cp.require_parent()
        principals = principals_cached()
        views = cp.parent_policy_views(principals)
        names = principals.names_to_ocids
        domain = (settings.identity_domain_name or "default").lower()

        def exists(name: str) -> CheckStatus:
            if not names:
                return CheckStatus.UNKNOWN
            key = f"{domain}/{name}".lower()
            return CheckStatus.DETECTED if key in names else CheckStatus.MISSING

        scanner_name = (
            settings.dynamic_group_scanner
            if settings.scanner_is_dynamic_group
            else settings.group_scanners
        )
        signed_in_oidc = user.via == "oidc"
        prereqs = [
            (
                "Group " + settings.group_admins,
                exists(settings.group_admins),
                "Members can use the admin screens",
            ),
            (
                "Group " + settings.group_viewers,
                exists(settings.group_viewers),
                "Members can view findings",
            ),
            (
                ("Dynamic group " if settings.scanner_is_dynamic_group else "Group ")
                + scanner_name,
                exists(scanner_name),
                "Scan identity. Matching rule: ALL {instance.id = '<OSC instance OCID>'}"
                if settings.scanner_is_dynamic_group
                else "Holds the OSC service user",
            ),
            (
                "Confidential integrated app (Auth Code + Client Credentials, group claims)",
                CheckStatus.DETECTED if signed_in_oidc else CheckStatus.UNKNOWN,
                "Confirmed when someone signs in with OCI IAM",
            ),
            (
                "Identity Propagation Trust for the app's client ID",
                CheckStatus.DETECTED
                if cp.state.get_setting(SETTING_TOKEN_EXCHANGE_OK) == "true" and signed_in_oidc
                else CheckStatus.UNKNOWN,
                "Confirmed after a successful token exchange",
            ),
        ]
        return render(
            request,
            "organization.html",
            views=views,
            prereqs=prereqs,
            children=cp.children(),
            admin_conn=cp.connection(ConnectionPurpose.ADMIN),
            scan_conn=cp.connection(ConnectionPurpose.SCAN),
            parent_obj=parent,
            admin_browse=cp.state.get_setting("offer_admin_browse") == "true",
            methods=_allowed_methods(settings),
        )

    @app.post("/admin/organization/discover")
    async def discover(
        request: Request, user: User = Depends(require_admin), _: None = Depends(verify_csrf)
    ) -> Response:
        try:
            result = cp.discover_children(admin_clients(request, user), actor(user))
            flash(
                request,
                result.message
                or f"Found {len(result.children)} child tenancies in "
                f"{result.organizations} Organization(s).",
                "warn" if result.message else "ok",
            )
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
        return back("/admin/organization")

    @app.post("/admin/organization/check")
    async def check_parent(
        request: Request, user: User = Depends(require_admin), _: None = Depends(verify_csrf)
    ) -> Response:
        try:
            clients = admin_clients(request, user)
            cp.principals(clients)  # refresh group OCID cache
            checks = cp.refresh_parent_checks(clients, actor(user))
            missing = sum(c.status is CheckStatus.MISSING for c in checks)
            flash(
                request,
                f"Checked {len(checks)} statements; {missing} missing.",
                "warn" if missing else "ok",
            )
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
        return back("/admin/organization")

    @app.post("/admin/settings/admin-browse")
    async def admin_browse(
        request: Request,
        enabled: str = Form("false"),
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        cp.set_admin_browse(enabled == "true", actor(user))
        return back("/admin/organization")

    @app.post("/admin/connections/{purpose}")
    async def save_connection(
        request: Request,
        purpose: str,
        method: str = Form(...),
        region: str = Form(""),
        domain_url: str = Form(""),
        client_id: str = Form(""),
        client_secret: str = Form(""),
        cli_config_path: str = Form(""),
        cli_profile: str = Form(""),
        user_ocid: str = Form(""),
        fingerprint: str = Form(""),
        private_key: str = Form(""),
        secret_ocid: str = Form(""),
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        try:
            conn = _connection_from_form(
                rt,
                settings,
                cp.require_parent().ocid,
                purpose,
                method,
                region,
                domain_url,
                client_id,
                client_secret,
                cli_config_path,
                cli_profile,
                user_ocid,
                fingerprint,
                private_key,
                secret_ocid,
            )
            cp.save_connection(conn, actor(user))
            oauth_cache.clear()
            flash(request, f"Saved {purpose} connection ({conn.method.value}).", "ok")
        except (ValueError, *_FRIENDLY_ERRORS) as exc:
            flash(request, str(exc), "error")
        return back("/admin/organization")

    @app.post("/admin/children/register")
    async def register_child(
        request: Request,
        ocid: str = Form(...),
        name: str = Form(...),
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        if not is_ocid(ocid.strip()) or ".tenancy." not in ocid:
            flash(request, "That is not a tenancy OCID.", "error")
            return back("/admin/organization")
        try:
            child = cp.register_child(ocid.strip(), name.strip() or ocid.strip(), actor(user))
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
            return back("/admin/organization")
        return back(f"/admin/children/{child.ocid}")

    # --- admin: child ---------------------------------------------------------------------
    @app.get("/admin/children/{ocid}", response_class=HTMLResponse)
    async def child_page(
        request: Request, ocid: str, user: User = Depends(require_admin)
    ) -> Response:
        child = cp.state.get_tenancy(child_ocid_or_404(ocid))
        if child is None:
            raise HTTPException(status_code=404)
        try:
            endorse, admit = cp.child_policy_views(child.ocid, principals_cached())
        except ControlPlaneError as exc:
            raise HTTPException(status_code=404) from exc
        raw = cp.state.get_setting(f"verify:{child.ocid}")
        return render(
            request,
            "child.html",
            child=child,
            endorse=endorse,
            admit=admit,
            verify=json.loads(raw) if raw else None,
        )

    @app.post("/admin/children/{ocid}/select")
    async def select_child(
        request: Request,
        ocid: str,
        alias: str = Form(""),
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        try:
            cp.select_child(child_ocid_or_404(ocid), actor(user), alias or None)
            flash(request, "Child selected. Apply the policies below, then click Verify.", "ok")
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
        return back(f"/admin/children/{ocid}")

    @app.post("/admin/children/{ocid}/verify")
    async def verify_child(
        request: Request,
        ocid: str,
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        try:
            result = cp.verify_child(rt.scan_clients(), child_ocid_or_404(ocid), actor(user))
            cp.state.set_setting(
                f"verify:{ocid}",
                json.dumps(
                    {
                        "ok": result.ok,
                        "summary": result.summary,
                        "steps": [asdict(s) for s in result.steps],
                    }
                ),
                session_generation(request),
            )
            flash(
                request,
                "Verified." if result.ok else f"Verify failed — {result.summary}",
                "ok" if result.ok else "error",
            )
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
        return back(f"/admin/children/{ocid}")

    @app.post("/admin/children/{ocid}/activate")
    async def activate_child(
        request: Request,
        ocid: str,
        user: User = Depends(require_admin),
        _: None = Depends(verify_csrf),
    ) -> Response:
        try:
            cp.activate_child(child_ocid_or_404(ocid), actor(user))
            flash(request, "Child is active and will be included in scans.", "ok")
        except _FRIENDLY_ERRORS as exc:
            flash(request, str(exc), "error")
        return back(f"/admin/children/{ocid}")

    @app.get("/admin/download")
    async def download(
        request: Request, view: str, ocid: str = "", user: User = Depends(require_admin)
    ) -> Response:
        selected: PolicyView | None = None
        principals = principals_cached()
        if view in (tpl.POLICY_PARENT_ACCESS, tpl.POLICY_ENDORSE_CHILDREN) and not ocid:
            selected = next(
                (v for v in cp.parent_policy_views(principals) if v.policy_name == view), None
            )
        elif view in ("child-endorse", "child-admit") and is_ocid(ocid):
            try:
                endorse, admit = cp.child_policy_views(ocid, principals)
            except ControlPlaneError as exc:
                raise HTTPException(status_code=404) from exc
            selected = endorse if view == "child-endorse" else admit
        if selected is None:
            raise HTTPException(status_code=404)
        fname = f"{selected.policy_name}{'-' + ocid[-8:] if ocid else ''}.txt"
        return PlainTextResponse(
            selected.text + "\n", headers={"Content-Disposition": f'attachment; filename="{fname}"'}
        )

    @app.get("/admin/events", response_class=HTMLResponse)
    async def events(request: Request, user: User = Depends(require_admin)) -> Response:
        return render(request, "events.html", events=cp.state.list_events(200))

    return app


def _allowed_methods(settings: Settings) -> dict[str, list[ConnectionMethod]]:
    return {p.value: methods for p, methods in allowed_methods(settings).items()}


def _connection_from_form(
    rt: Runtime,
    settings: Settings,
    tenancy_ocid: str,
    purpose: str,
    method: str,
    region: str,
    domain_url: str,
    client_id: str,
    client_secret: str,
    cli_config_path: str,
    cli_profile: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    secret_ocid: str,
) -> Connection:
    try:
        purpose_e = ConnectionPurpose(purpose)
        method_e = ConnectionMethod(method)
    except ValueError as exc:
        raise ValueError("unknown connection purpose or method") from exc
    if method_e not in allowed_methods(settings)[purpose_e]:
        raise ValueError(
            f"{method_e.value} is not supported for the {purpose_e.value} connection "
            f"in {settings.deployment.value} mode"
        )
    existing = rt.control_plane.connection(purpose_e)
    secret_ref = existing.secret_ref if existing and existing.method is method_e else None
    pending_local: str | None = None  # stored only after the configuration validates
    if secret_ocid.strip():
        if not is_ocid(secret_ocid.strip()):
            raise ValueError("Vault secret must be an OCID")
        secret_ref = f"vault:{secret_ocid.strip()}"
    elif method_e is ConnectionMethod.OIDC_TOKEN_EXCHANGE and client_secret:
        pending_local, secret_ref = client_secret, PENDING_LOCAL_REF
    elif method_e is ConnectionMethod.API_KEY and private_key.strip():
        if "PRIVATE KEY" not in private_key:
            raise ValueError("private key must be PEM")
        pending_local, secret_ref = private_key.strip() + "\n", PENDING_LOCAL_REF
    if method_e is ConnectionMethod.OIDC_TOKEN_EXCHANGE:
        if not domain_url.startswith("https://") or not client_id or not region:
            raise ValueError("OIDC needs an https identity domain URL, client ID and region")
        if not secret_ref:
            raise ValueError("OIDC needs a client secret (or a Vault secret OCID)")
    if method_e is ConnectionMethod.API_KEY and not (
        user_ocid and fingerprint and region and secret_ref
    ):
        raise ValueError("API key needs user OCID, fingerprint, region and a private key")
    conn = Connection(
        id="",
        tenancy_ocid=tenancy_ocid,
        method=method_e,
        purpose=purpose_e,
        region=region or None,
        domain_url=domain_url.rstrip("/") or None,
        client_id=client_id or None,
        cli_config_path=cli_config_path or None,
        cli_profile=cli_profile or None,
        user_ocid=user_ocid or None,
        fingerprint=fingerprint or None,
        secret_ref=secret_ref,
    )
    other = rt.control_plane.connection(
        ConnectionPurpose.ADMIN if purpose_e is ConnectionPurpose.SCAN else ConnectionPurpose.SCAN
    )
    scan, admin = (conn, other) if purpose_e is ConnectionPurpose.SCAN else (other, conn)
    validate_connections(settings, scan, admin)  # before anything is stored
    if pending_local is not None:
        conn = conn.model_copy(update={"secret_ref": rt.secrets.store_local(pending_local)})
    return conn
