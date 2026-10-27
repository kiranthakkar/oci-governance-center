"""OGC web enrollment, OIDC authorization, configuration and read-only dashboards."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any, Literal, get_args
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Send
from starlette.types import Scope as ASGIScope

from ..auth import oidc
from ..collectors.inventory import public_error
from ..config import Settings
from ..diagnostics import PublicFailure
from ..models import (
    PARENT_EXCHANGE_SCOPE,
    SEVERITIES,
    Domain,
    FindingSource,
    Parent,
    ScanSettings,
    TriageState,
)
from ..provisioning.bundle import bundle, deploy_url, manual
from ..scans import ScanControl, ScanSchedule
from ..service import Service
from ..storage import StaleWork, Store
from . import views

FINDING_STATUSES = {"open", "resolved", "ignored", "closed"}
# Cost rows are large and only the Cost tab reads them.
COST = ("cost.",)

COOKIE = "__Host-ogc"


def _origin(value: str) -> tuple[str, str, int] | None:
    """Compare origin components, including implicit HTTP/HTTPS ports, without trusting paths."""
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return None
        port = parsed.port
        return (
            parsed.scheme,
            parsed.hostname,
            port if port is not None else (443 if parsed.scheme == "https" else 80),
        )
    except ValueError:
        return None


class CsrfToken:
    """Render the session CSRF token, marking a new session as worth persisting only then."""

    def __init__(self, request: Request) -> None:
        self.request = request

    def __str__(self) -> str:
        self.request.state.persist_session = True
        return str(self.request.state.session["csrf"])

    # Jinja autoescaping calls __html__; the token is URL-safe base64 and needs no escaping.
    __html__ = __str__


class BodyLimit:
    """Bound all request bodies, including chunked multipart uploads, before form parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: ASGIScope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        total = 0

        async def limited() -> Message:
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > 131072:
                raise HTTPException(413, "Request is too large")
            return message

        await self.app(scope, limited, send)


def create_app(settings: Settings, service: Service | None = None) -> FastAPI:
    """Build the application. OCI clients are injectable through the service for mocked tests."""
    store = (
        service.store
        if service
        else Store(settings.data_root, settings.encryption_key.get_secret_value())
    )
    service = service or Service(settings, store)
    app = FastAPI(title="OCI Governance Center", docs_url=None, redoc_url=None, openapi_url=None)
    secure_cookies = urlsplit(settings.public_base_url).scheme == "https"
    cookie_name = COOKIE if secure_cookies else "ogc-dev"
    app.state.service = service
    app.state.store = store
    scans = ScanControl(store)
    app.add_middleware(BodyLimit)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=[str(urlsplit(settings.public_base_url).hostname)]
    )
    directory = Path(__file__).parent
    templates = Jinja2Templates(directory=directory / "templates")
    templates.env.filters["when"] = views.when
    templates.env.filters["money"] = views.money
    app.mount("/static", StaticFiles(directory=directory / "static"), name="static")

    def render(request: Request, template: str, **context: Any) -> Response:
        generation, parent, blocked = store.state()
        authorized = getattr(request.state, "authorized_generation", generation)
        if authorized != generation:
            if template != "error.html":
                raise HTTPException(409, "Organization changed; sign in again")
            parent = None
        return templates.TemplateResponse(
            request=request,
            name=template,
            status_code=context.pop("status_code", 200),
            context={
                "parent": parent,
                "blocked": blocked,
                "generation": generation,
                "csrf": CsrfToken(request),
                "callback_url": settings.public_base_url + "/auth/callback",
                "admin": "ogc_admin" in request.state.session.get("groups", []),
                **context,
            },
        )

    @app.middleware("http")
    async def sessions(request: Request, call_next: Any) -> Response:
        incoming = request.cookies.get(cookie_name, "")
        session = store.session(incoming) if incoming else None
        sid = incoming if session else secrets.token_urlsafe(32)
        request.state.sid = sid
        request.state.persist_session = False
        request.state.session = session or {
            "csrf": secrets.token_urlsafe(32),
            "created": time.time(),
        }
        response: Response = await call_next(request)
        data = request.state.session
        # Cookieless probes (health checks, static files, redirects) must not each write a row.
        unused = (
            session is None
            and request.state.sid == sid
            and set(data) <= {"csrf", "created"}
            and not request.state.persist_session
        )
        current_generation, _, _ = store.state()
        if unused:
            pass
        elif data.get("generation", current_generation) == current_generation and not data.get(
            "deleted"
        ):
            # Enforce absolute session lifetime; regular requests never extend it.
            remaining = max(0, int(settings.session_seconds - (time.time() - data["created"])))
            if remaining:
                store.save_session(request.state.sid, data, remaining)
                response.set_cookie(
                    cookie_name,
                    request.state.sid,
                    max_age=remaining,
                    httponly=True,
                    secure=secure_cookies,
                    samesite="lax",
                    path="/",
                )
        else:
            store.drop_session(request.state.sid)
            response.delete_cookie(cookie_name, path="/", secure=secure_cookies, httponly=True)
        if (
            request.method == "POST"
            and response.status_code < 400
            and data.get("grant")
            and data.get("generation") == current_generation
            and not data.get("deleted")
        ):
            try:
                store.event(current_generation, request.url.path, data["grant"]["subject"])
            except StaleWork:
                pass
        # Chrome applies the initiating document's form-action policy to every redirect
        # after POST. Enrollment must permit its exact configured OIDC origin as well.
        form_action = "'self'"
        if oidc_origin := getattr(request.state, "oidc_form_origin", None):
            form_action += " " + oidc_origin
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'none'; style-src 'self'; "
                f"img-src 'self'; form-action {form_action}; "
                "frame-ancestors 'none'; base-uri 'none'",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                # no-referrer makes browser form POSTs send Origin: null.
                # Preserve same-origin forms while withholding referrers from other origins.
                "Referrer-Policy": "same-origin",
            }
        )
        if secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    async def form(request: Request) -> dict[str, Any]:
        values = dict(await request.form(max_files=1, max_fields=30, max_part_size=65536))
        supplied = str(values.pop("csrf", ""))
        if not secrets.compare_digest(supplied, request.state.session["csrf"]):
            raise HTTPException(403, "Form expired; reload and try again")
        origin = request.headers.get("origin")
        if origin and _origin(origin) != _origin(settings.public_base_url):
            raise HTTPException(
                403,
                "Cross-origin form rejected. Open " + settings.public_base_url + "/setup, "
                "or set OGC_PUBLIC_BASE_URL to the browser's origin (scheme, hostname, and port "
                "only, without /setup) and restart OGC.",
            )
        return values

    async def access(request: Request, admin: bool = False) -> Parent:
        generation, parent, _ = store.state()
        session = request.state.session
        if parent is None or session.get("generation") != generation or "grant" not in session:
            raise HTTPException(401, "Sign in to OCI Governance Center")
        if admin or time.time() - session.get("checked", 0) >= 300:
            try:
                identity = await oidc.membership(parent, session["grant"])
            except ValueError:
                session["deleted"] = True
                raise HTTPException(
                    403, "Your OGC group membership no longer permits access"
                ) from None
            except Exception:
                raise HTTPException(
                    503, "Group membership cannot be verified; try again later"
                ) from None
            session.update(groups=sorted(identity.groups), checked=time.time())
        if not set(session.get("groups", [])) & {"ogc_admin", "ogc_viewer"}:
            raise HTTPException(403, "OGC group membership required")
        if admin and "ogc_admin" not in session["groups"]:
            raise HTTPException(403, "ogc_admin membership required")
        if store.state()[0] != generation:
            raise HTTPException(409, "Organization changed during authorization")
        request.state.authorized_generation = generation
        return parent

    async def setup_access(request: Request) -> None:
        generation, parent, _ = store.state()
        if parent:
            await access(request, admin=True)
            if not request.state.session.get("replacement"):
                raise HTTPException(403, "Begin parent replacement from Configuration")
        elif (
            not request.state.session.get("setup")
            or request.state.session.get("generation") != generation
        ):
            raise HTTPException(401, "Enter the operator setup password")
        request.state.authorized_generation = generation

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> Response:
        return render(
            request, "error.html", message=str(error.detail), status_code=error.status_code
        )

    @app.exception_handler(ValueError)
    async def validation_error(request: Request, error: ValueError) -> Response:
        # Pydantic/SDK errors can contain raw form values. Do not reflect their repr/message.
        return render(
            request,
            "error.html",
            message="Configuration could not be validated. Check identifiers and prerequisites.",
            status_code=400,
        )

    @app.exception_handler(StaleWork)
    async def stale_error(request: Request, error: StaleWork) -> Response:
        return render(
            request,
            "error.html",
            message="Configuration changed. Reload before continuing.",
            status_code=409,
        )

    @app.exception_handler(PublicFailure)
    async def public_failure(request: Request, error: PublicFailure) -> Response:
        # PublicFailure messages are authored, credential-free diagnostics (diagnostics.py).
        return render(request, "error.html", message=str(error), status_code=400)

    @app.get("/healthcheck", response_class=PlainTextResponse)
    async def healthcheck() -> str:
        return "OK"

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        _, parent, _ = store.state()
        if parent is None:
            return RedirectResponse("/setup", status_code=303)
        if "grant" not in request.state.session:
            return render(request, "login.html")
        await access(request)
        coverage = [
            {**row, "scope": json.loads(row["scope"])}
            for row in store.rows("coverage", request.state.authorized_generation)
        ]
        findings = [
            json.loads(row["data"])
            for row in store.rows("findings", request.state.authorized_generation)
        ]
        return render(
            request,
            "dashboard.html",
            children=store.children(request.state.authorized_generation),
            coverage=coverage,
            findings=[f for f in findings if f["status"] == "open"],
        )

    def provision_page(request: Request, *, message: str = "", failed: bool = False) -> Response:
        draft = request.state.session.get("setup_credentials", {})
        # Revalidate the saved domain; never derive CSP sources from query parameters or headers.
        request.state.oidc_form_origin = Domain.model_validate(
            request.state.session["setup_metadata"]["domain"]
        ).url
        return render(
            request,
            "provision.html",
            instructions=manual("parent"),
            deploy=deploy_url(settings.parent_package_url) if settings.parent_package_url else "",
            metadata=request.state.session["setup_metadata"],
            draft={key: draft.get(key, "") for key in ("user_ocid", "fingerprint", "client_id")},
            has_private_key=bool(draft.get("private_key")),
            has_client_secret=bool(draft.get("client_secret")),
            message=message,
            failed=failed,
            status_code=400 if failed else 200,
        )

    def scan_page(
        request: Request,
        message: str = "",
        failed: bool = False,
        draft: dict[str, Any] | None = None,
    ) -> Response:
        generation = request.state.authorized_generation
        parent = store.state()[1]
        saved = scans.schedule(generation)
        schedule = ScanSchedule.model_validate_json(saved["data"]) if saved else None
        jobs = scans.jobs(generation)
        values = draft or (
            schedule.model_dump()
            if schedule
            else {
                "frequency": "daily",
                "time_of_day": "09:00",
                "weekday": 0,
                "timezone": "UTC",
            }
        )
        next_run = ""
        if saved and schedule:
            from datetime import datetime
            from zoneinfo import ZoneInfo

            next_run = (
                datetime.fromisoformat(saved["next_run"])
                .astimezone(ZoneInfo(schedule.timezone))
                .strftime("%a %d %b %Y, %H:%M %Z")
            )
        return render(
            request,
            "scans.html",
            schedule=schedule,
            next_run=next_run,
            jobs=jobs,
            active_job=next((job for job in jobs if job["status"] in {"queued", "running"}), None),
            worker_online=scans.online(),
            locked_until=scans.locked_until(),
            collection=[
                (ocid, label, store.scan_settings(ocid))
                for ocid, label in (tenancy_options(generation, parent) if parent else [])
            ],
            draft=values,
            message=message,
            failed=failed,
            weekdays=("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"),
            status_code=400 if failed else 200,
        )

    @app.get("/scans")
    async def scan_tab(request: Request, requested: bool = False, saved: bool = False) -> Response:
        await access(request)
        message = "Scan requested. Refresh this page to see progress." if requested else ""
        if saved:
            message = "Scan settings updated. Changes apply from the next scan."
        return scan_page(request, message)

    @app.get("/scans/{ident}")
    async def scan_details(request: Request, ident: str) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        saved = scans.details(generation, ident)
        if saved is None:
            raise HTTPException(404, "Scan not found")
        job, rows = saved
        live = job["status"] in {"queued", "running"}
        if live:
            rows = store.rows("coverage", generation)
        names = {parent.domain.tenancy_ocid: parent.name}
        names.update({c.ocid: c.name for c in store.children(generation)})
        for row in rows:
            row["scope"] = json.loads(row["scope"])
            row["attempted_in_run"] = bool(
                job["started_at"] and row["attempted"] >= job["started_at"]
            )
        rows.sort(key=lambda row: (row["status"] == "complete", row["scope"]["tenancy"]))
        return render(
            request,
            "scan_details.html",
            job=job,
            rows=rows,
            names=names,
            live=live,
            incomplete=sum(row["status"] != "complete" for row in rows),
        )

    @app.post("/scans/start")
    async def scan_start(request: Request) -> Response:
        await access(request, admin=True)
        await form(request)
        try:
            scans.enqueue(
                request.state.authorized_generation, request.state.session["grant"]["subject"]
            )
        except Exception as error:
            if isinstance(error, StaleWork):
                raise
            return scan_page(request, public_error(error), failed=True)
        return RedirectResponse("/scans?requested=true", status_code=303)

    @app.post("/scans/schedule")
    async def scan_schedule(request: Request) -> Response:
        await access(request, admin=True)
        values = await form(request)
        try:
            schedule = ScanSchedule.model_validate(
                {
                    "frequency": values.get("frequency"),
                    "time_of_day": values.get("time_of_day"),
                    "timezone": values.get("timezone"),
                    "weekday": values.get("weekday")
                    if values.get("frequency") == "weekly"
                    else None,
                }
            )
        except ValidationError:
            return scan_page(
                request,
                "Choose daily or weekly, a valid time, weekday, and IANA timezone.",
                failed=True,
                draft=values,
            )
        scans.save(request.state.authorized_generation, schedule)
        return RedirectResponse("/scans?saved=true", status_code=303)

    @app.post("/scans/schedule/disable")
    async def scan_schedule_disable(request: Request) -> Response:
        await access(request, admin=True)
        await form(request)
        scans.disable(request.state.authorized_generation)
        return RedirectResponse("/scans?saved=true", status_code=303)

    @app.post("/scans/settings/{tenancy}")
    async def scan_settings_save(request: Request, tenancy: str) -> Response:
        parent = await access(request, admin=True)
        values = await form(request)
        generation = request.state.authorized_generation
        if tenancy not in dict(tenancy_options(generation, parent)):
            raise HTTPException(404, "Tenancy not found")
        chosen = ScanSettings(
            **{
                name: values.get(name) == "on"
                for name in ("cloud_guard", "cloud_advisor", "identities", "policies", "audit")
            },
            # Cost is read from the parent only; a child's setting keeps the default.
            cost=values.get("cost") == "on" if tenancy == parent.domain.tenancy_ocid else True,
            all_domains=values.get("domains") == "all",
        )
        store.save_scan_settings(
            generation, tenancy, chosen, request.state.session["grant"]["subject"]
        )
        return RedirectResponse("/scans?saved=true", status_code=303)

    @app.post("/findings/{ident}/triage")
    async def finding_triage(request: Request, ident: str) -> Response:
        await access(request, admin=True)
        values = await form(request)
        action = str(values.get("action", ""))
        states: dict[str, TriageState | None] = {
            "ignore": "ignored",
            "close": "closed",
            "reopen": None,
        }
        if action not in states:
            raise HTTPException(400, "Unsupported action")
        reason = str(values.get("reason", "")).strip()
        if len(reason) > 500:
            raise HTTPException(400, "Reason is too long")
        if not store.triage(
            request.state.authorized_generation,
            ident,
            states[action],
            request.state.session["grant"]["subject"],
            reason,
        ):
            raise HTTPException(404, "Finding not found")
        target = str(values.get("next", ""))
        # Only same-site relative paths; anything else (//host, scheme, backslash) is ignored.
        parts = urlsplit(target)
        if (
            not target.startswith("/")
            or target.startswith("//")
            or "\\" in target
            or parts.scheme
            or parts.netloc
        ):
            target = "/data/findings"
        return RedirectResponse(target, status_code=303)

    @app.get("/setup")
    async def setup(request: Request, edit: bool = False) -> Response:
        _, parent, _ = store.state()
        if parent:
            await setup_access(request)
        if request.state.session.get("setup_metadata") and not edit:
            await setup_access(request)
            return provision_page(request)
        return render(
            request,
            "setup.html",
            unlocked=bool(request.state.session.get("setup") or parent),
            metadata=request.state.session.get("setup_metadata", {}),
        )

    @app.post("/setup/unlock")
    async def unlock(request: Request) -> Response:
        values = await form(request)
        generation, parent, _ = store.state()
        if parent:
            raise HTTPException(403, "First-run setup is disabled")
        # Persistent, global throttle on failed attempts, with no dependency on attacker-controlled
        # proxy headers. Guessing resistance comes from the required long password (config.py);
        # this bounds online guessing, and a lockout only delays first-run setup by 15 minutes.
        stamp = int(time.time() // 900)
        with store.db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS setup_attempts("
                "window INTEGER PRIMARY KEY,count INTEGER)"
            )
            db.execute("DELETE FROM setup_attempts WHERE window<?", (stamp,))
            row = db.execute("SELECT count FROM setup_attempts WHERE window=?", (stamp,)).fetchone()
        if row and row[0] >= 10:
            raise HTTPException(429, "Too many failed setup attempts; retry in fifteen minutes")
        supplied = hashlib.sha256(str(values.get("password", "")).encode()).digest()
        expected = hashlib.sha256(settings.setup_password.get_secret_value().encode()).digest()
        if not secrets.compare_digest(supplied, expected):
            with store.db() as db:
                db.execute(
                    "INSERT INTO setup_attempts VALUES(?,1) ON CONFLICT(window) "
                    "DO UPDATE SET count=count+1",
                    (stamp,),
                )
            raise HTTPException(403, "Setup password is invalid")
        store.drop_session(request.state.sid)
        request.state.sid = secrets.token_urlsafe(32)
        request.state.session = {
            "setup": True,
            "generation": generation,
            "csrf": secrets.token_urlsafe(32),
            "created": time.time(),
        }
        return RedirectResponse("/setup", status_code=303)

    @app.post("/setup/metadata")
    async def setup_metadata(request: Request) -> Response:
        await setup_access(request)
        values = await form(request)
        domain = Domain.model_validate({key: values[key] for key in Domain.model_fields})
        domain.check_guid()
        name = str(values.get("name", ""))
        if not name or len(name) > 120:
            raise ValueError("Invalid display name")
        metadata = {"name": name, "domain": domain.model_dump()}
        old = request.state.session.get("setup_metadata")
        if old and old.get("domain") != metadata["domain"]:
            request.state.session.pop("setup_credentials", None)
            request.state.session.pop("candidate", None)
        request.state.session["setup_metadata"] = metadata
        return provision_page(request)

    @app.post("/setup/discard")
    async def discard_setup(request: Request) -> Response:
        await setup_access(request)
        await form(request)
        for key in ("setup_metadata", "setup_credentials", "candidate", "oidc"):
            request.state.session.pop(key, None)
        with store.db() as db:
            db.execute("DELETE FROM candidates WHERE owner=?", (request.state.sid,))
        return RedirectResponse("/setup", status_code=303)

    @app.get("/setup/package/{kind}")
    async def package(request: Request, kind: Literal["parent", "child"]) -> Response:
        if kind == "parent":
            await setup_access(request)
        else:
            await access(request, admin=True)
        return Response(
            bundle(kind),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="ogc-{kind}-setup.zip"'},
        )

    @app.post("/setup/credentials")
    async def credentials(request: Request) -> Response:
        await setup_access(request)
        values = await form(request)
        saved = request.state.session.get("setup_metadata")
        if not saved:
            raise HTTPException(400, "Enter the parent metadata first")
        draft = dict(request.state.session.get("setup_credentials", {}))
        for field in ("user_ocid", "fingerprint", "client_id"):
            draft[field] = str(values.get(field, ""))
        draft["exchange_scope"] = PARENT_EXCHANGE_SCOPE
        if values.get("client_secret"):
            draft["client_secret"] = str(values["client_secret"])
        request.state.session["setup_credentials"] = draft
        upload = values.get("private_key")
        if isinstance(upload, UploadFile) and upload.filename:
            contents = await upload.read(16385)
            if len(contents) > 16384:
                return provision_page(
                    request, message="Private-key file is too large.", failed=True
                )
            try:
                draft["private_key"] = contents.decode("utf-8")
            except UnicodeDecodeError:
                return provision_page(
                    request, message="Upload a PEM text private-key file.", failed=True
                )
        if values.get("action") == "save":
            return provision_page(request, message="Enrollment draft saved for this setup session.")
        try:
            parent = Parent.model_validate({**saved, **draft})
        except ValidationError:
            return provision_page(
                request,
                message="Check required credentials, user OCID, and API-key fingerprint format.",
                failed=True,
            )
        try:
            ident = await run_in_threadpool(
                service.candidate, request.state.sid, parent, request.state.authorized_generation
            )
        except Exception as error:
            return provision_page(request, message=public_error(error), failed=True)
        request.state.session["candidate"] = ident
        return RedirectResponse("/auth/login?enrollment=true", status_code=303)

    @app.get("/auth/login")
    async def login(request: Request, enrollment: bool = False) -> Response:
        generation, parent, _ = store.state()
        if enrollment:
            await setup_access(request)
            generation, parent = store.get_candidate(
                request.state.session.get("candidate", ""), request.state.sid
            )
        if parent is None:
            raise HTTPException(400, "Complete setup first")
        url, pending = await oidc.begin(parent, settings.public_base_url + "/auth/callback")
        request.state.session["oidc"] = {
            **pending,
            "generation": generation,
            "enrollment": enrollment,
            "began": time.time(),
        }
        return RedirectResponse(url, status_code=303)

    @app.get("/auth/callback")
    async def callback(request: Request, state: str = "", code: str = "") -> Response:
        session = request.state.session
        pending = session.pop("oidc", None)  # one-use even if provider rejects the code.
        if (
            not pending
            or time.time() - pending["began"] > 600
            or not secrets.compare_digest(state, pending["state"])
        ):
            raise HTTPException(403, "OIDC state expired or invalid")
        generation, parent, _ = store.state()
        if pending["generation"] != generation:
            raise HTTPException(409, "Organization changed during sign-in")
        if pending["enrollment"]:
            if parent is not None:
                await access(request, admin=True)
            _, parent = store.get_candidate(session["candidate"], request.state.sid)
        if parent is None:
            raise HTTPException(400, "No login configuration")
        try:
            identity, grant = await oidc.finish(
                parent, settings.public_base_url + "/auth/callback", code, pending
            )
        except Exception:
            raise HTTPException(403, "Sign-in or group verification failed") from None
        if pending["enrollment"]:
            if not identity.admin:
                raise HTTPException(403, "New-parent ogc_admin sign-in is required")
            generation = await run_in_threadpool(
                store.install, session["candidate"], request.state.sid, identity.subject
            )
        else:
            store.drop_session(request.state.sid)
        request.state.sid = secrets.token_urlsafe(32)
        request.state.session = {
            "generation": generation,
            "grant": grant,
            "groups": sorted(identity.groups),
            "checked": time.time(),
            "created": time.time(),
            "csrf": secrets.token_urlsafe(32),
        }
        return RedirectResponse("/", status_code=303)

    @app.post("/auth/logout")
    async def logout(request: Request) -> Response:
        await form(request)
        store.drop_session(request.state.sid)
        request.state.session["deleted"] = True
        return RedirectResponse("/", status_code=303)

    @app.get("/configuration")
    async def configuration(request: Request) -> Response:
        await access(request, admin=True)
        return render(
            request,
            "configuration.html",
            children=store.children(request.state.authorized_generation),
        )

    @app.post("/configuration/replace")
    async def replace(request: Request) -> Response:
        await access(request, admin=True)
        await form(request)
        request.state.session.pop("setup_metadata", None)
        request.state.session.pop("setup_credentials", None)
        request.state.session.pop("candidate", None)
        request.state.session["replacement"] = True
        return RedirectResponse("/setup", status_code=303)

    @app.post("/configuration/cancel")
    async def cancel(request: Request) -> Response:
        await access(request, admin=True)
        await form(request)
        for key in ("replacement", "candidate", "setup_metadata", "setup_credentials", "oidc"):
            request.state.session.pop(key, None)
        with store.db() as db:
            db.execute("DELETE FROM candidates WHERE owner=?", (request.state.sid,))
        return RedirectResponse("/configuration", status_code=303)

    @app.post("/configuration/key")
    async def repair(request: Request) -> Response:
        await access(request, admin=True)
        values = await form(request)
        upload = values.get("private_key")
        if not isinstance(upload, UploadFile) or not upload.filename:
            raise HTTPException(400, "Upload the replacement API private-key file")
        try:
            key = (await upload.read(16385)).decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "Upload a PEM text private-key file") from None
        if len(key) > 16384:
            raise HTTPException(400, "Private-key file is too large")
        await run_in_threadpool(
            service.repair,
            key,
            str(values.get("fingerprint", "")),
            str(values.get("user_ocid", "")),
            request.state.authorized_generation,
        )
        request.state.session["deleted"] = True
        return RedirectResponse("/auth/login", status_code=303)

    @app.get("/children/{child_id}")
    async def child_setup(request: Request, child_id: str) -> Response:
        parent = await access(request, admin=True)
        child = next(
            (c for c in store.children(request.state.authorized_generation) if c.ocid == child_id),
            None,
        )
        if child is None or child.status == "departed":
            raise HTTPException(404, "Discovered child not found")
        return render(
            request,
            "child.html",
            child=child,
            exchange_credentials=store.child_credentials(
                request.state.authorized_generation, child_id
            ),
            instructions=manual("child"),
            parent_jwks=parent.domain.url + "/admin/v1/SigningCert/jwk",
            deploy=deploy_url(settings.child_package_url) if settings.child_package_url else "",
        )

    @app.post("/children/{child_id}/configure")
    async def child_configure(request: Request, child_id: str) -> Response:
        await access(request, admin=True)
        values = await form(request)
        try:
            await run_in_threadpool(
                service.configure_child,
                child_id,
                values.get("url", ""),
                request.state.authorized_generation,
                values.get("client_id", ""),
                values.get("client_secret", ""),
            )
        except Exception as error:
            return render(request, "error.html", message=public_error(error), status_code=400)
        return RedirectResponse("/configuration", status_code=303)

    @app.post("/children/{child_id}/pause")
    async def pause(request: Request, child_id: str) -> Response:
        await access(request, admin=True)
        await form(request)
        service.pause(child_id, request.state.authorized_generation)
        return RedirectResponse("/configuration", status_code=303)

    @app.post("/children/{child_id}/resume")
    async def resume(request: Request, child_id: str) -> Response:
        await access(request, admin=True)
        await form(request)
        child = next(
            (c for c in store.children(request.state.authorized_generation) if c.ocid == child_id),
            None,
        )
        if child is None or child.domain is None:
            raise HTTPException(400, "Configure child first")
        await run_in_threadpool(
            service.configure_child,
            child_id,
            child.domain.url,
            request.state.authorized_generation,
        )
        return RedirectResponse("/configuration", status_code=303)

    def tenancy_options(generation: int, parent: Parent) -> list[tuple[str, str]]:
        """Label the parent and discovered children for filter menus; OCIDs stay the values."""
        return [(parent.domain.tenancy_ocid, parent.name + " (parent)")] + [
            (child.ocid, child.name) for child in store.children(generation)
        ]

    def text_filter(value: str) -> str:
        """Bound free-text filter input; matching is a case-insensitive substring."""
        value = value.strip()
        if len(value) > 200:
            raise HTTPException(400, "Filter text is too long")
        return value

    def choice(value: str, allowed: set[str]) -> str:
        """Accept only a known menu value (or none)."""
        if value and value not in allowed:
            raise HTTPException(400, "Unsupported filter value")
        return value

    def finding_status(value: str | None) -> str:
        """Finding lists show open findings unless a status (or "" for all) is chosen."""
        return "open" if value is None else choice(value, FINDING_STATUSES)

    def narrowed(filters: dict[str, str]) -> bool:
        """Whether filters differ from the defaults (all values, open findings)."""
        return any(v for k, v in filters.items() if not (k == "status" and v == "open"))

    def disabled_for(generation: int, parent: Parent, *flags: str) -> list[tuple[str, list[str]]]:
        """Tenancies whose scan settings disable collection shown on a tab, per setting."""
        labels = dict(tenancy_options(generation, parent))
        names = {
            "cloud_guard": "Cloud Guard",
            "cloud_advisor": "Cloud Advisor",
            "identities": "identities",
            "policies": "policies",
        }
        result = []
        for flag in flags:
            off = [
                label
                for ocid, label in labels.items()
                if not getattr(store.scan_settings(ocid), flag)
            ]
            if off:
                result.append((names[flag], off))
        return result

    @app.get("/cloud-guard")
    async def cloud_guard_tab(
        request: Request,
        tenancy: str = "",
        severity: str = "",
        source: str = "",
        region: str = "",
        resource_type: str = "",
        status: str | None = None,
        q: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        filters = {
            "tenancy": text_filter(tenancy),
            "severity": choice(severity, set(SEVERITIES)),
            "source": choice(source, {"cloud_guard", "security_zone"}),
            "region": text_filter(region),
            "resource_type": text_filter(resource_type),
            "status": finding_status(status),
            "q": text_filter(q),
        }
        tenancies = tenancy_options(generation, parent)
        view = views.cloud_guard(
            views.records_by_dataset(store.records(generation, exclude=COST)),
            views.parse_findings(store.rows("findings", generation)),
            store.rows("coverage", generation),
            tenancies,
            filters,
        )
        return render(
            request,
            "cloud_guard.html",
            **view,
            filters=filters,
            filtered=narrowed(filters),
            tenancies=tenancies,
            severities=SEVERITIES,
            disabled=disabled_for(generation, parent, "cloud_guard"),
            here=str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
        )

    @app.get("/cloud-advisor")
    async def cloud_advisor_tab(
        request: Request,
        tenancy: str = "",
        importance: str = "",
        status: str = "",
        category: str = "",
        q: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        filters = {
            "tenancy": text_filter(tenancy),
            "importance": text_filter(importance),
            "status": text_filter(status),
            "category": text_filter(category),
            "q": text_filter(q),
        }
        tenancies = tenancy_options(generation, parent)
        view = views.cloud_advisor(
            views.records_by_dataset(store.records(generation, exclude=COST)),
            store.rows("coverage", generation),
            tenancies,
            filters,
        )
        return render(
            request,
            "cloud_advisor.html",
            **view,
            filters=filters,
            filtered=any(filters.values()),
            tenancies=tenancies,
            disabled=disabled_for(generation, parent, "cloud_advisor"),
        )

    @app.get("/cost")
    async def cost_tab(
        request: Request,
        view: str = "tenancy",
        tenancy: str = "",
        service: str = "",
        month_from: str = "",
        month_to: str = "",
        q: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        tenancies = tenancy_options(generation, parent)
        for month in (month_from, month_to):
            if month and not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
                raise HTTPException(400, "Unsupported filter value")
        filters = {
            "tenancy": choice(tenancy, set(dict(tenancies))),
            "service": text_filter(service),
            "month_from": month_from,
            "month_to": month_to,
            "q": text_filter(q),
        }
        selected = choice(view, set(views.COST_VIEWS)) or "tenancy"
        ocid = parent.domain.tenancy_ocid
        data = views.cost(
            views.records_by_dataset(store.records(generation, include=COST)),
            store.rows("coverage", generation),
            tenancies,
            filters,
            selected,
            ocid,
            store.scan_settings(ocid).cost,
        )
        shared = {k: v for k, v in filters.items() if v}
        return render(
            request,
            "cost.html",
            **data,
            view=selected,
            filters=filters,
            filtered=any(v for k, v in filters.items() if not k.startswith("month_")),
            tenancies=tenancies,
            shared_query=urlencode(shared),
        )

    @app.get("/resources")
    async def resources_tab(request: Request, tenancy: str = "", deleted: bool = False) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        tenancies = tenancy_options(generation, parent)
        labels = dict(tenancies)
        selected = tenancy or parent.domain.tenancy_ocid
        if selected not in labels:
            raise HTTPException(400, "Unsupported filter value")
        view = views.compartment_tree(
            views.records_by_dataset(store.records(generation, exclude=COST)),
            store.rows("coverage", generation),
            selected,
            labels[selected],
            deleted,
            store.scan_settings(selected).policies,
        )
        return render(
            request,
            "resources.html",
            **view,
            tenancies=tenancies,
            selected=selected,
            include_deleted=deleted,
        )

    @app.get("/identity")
    async def identity_tab(
        request: Request,
        view: str = "users",
        tenancy: str = "",
        domain: str = "",
        q: str = "",
        mfa: str = "",
        rule: str = "",
        severity: str = "",
        status: str | None = None,
        compartment: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        filters = {
            "tenancy": text_filter(tenancy),
            "domain": text_filter(domain),
            "compartment": text_filter(compartment),
            "q": text_filter(q),
            "mfa": choice(mfa, {"ENROLLED", "not_enrolled", "unknown"}),
            "rule": text_filter(rule),
            "severity": choice(severity, set(SEVERITIES)),
            "status": finding_status(status),
        }
        selected = choice(view, set(views.IDENTITY_VIEWS)) or "users"
        if selected != "analysis":
            filters["status"] = ""
        tenancies = tenancy_options(generation, parent)
        data = views.identity(
            views.records_by_dataset(store.records(generation, exclude=COST)),
            views.parse_findings(store.rows("findings", generation)),
            tenancies,
            filters,
            selected,
            settings.api_key_max_age_days,
            store.rows("coverage", generation),
        )
        shared = {k: v for k, v in filters.items() if k in {"tenancy", "domain"} and v}
        return render(
            request,
            "identity.html",
            **data,
            view=selected,
            filters=filters,
            filtered=narrowed(filters),
            tenancies=tenancies,
            severities=SEVERITIES,
            shared_query=urlencode(shared),
            disabled=disabled_for(generation, parent, "identities", "policies"),
            here=str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
        )

    @app.get("/activity")
    async def activity(
        request: Request,
        tenancy: str = "",
        region: str = "",
        principal: str = "",
        event: str = "",
        result: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        if result not in {"", "success", "failure"}:
            raise HTTPException(400, "Unsupported filter value")
        filters = {
            "tenancy": text_filter(tenancy),
            "region": text_filter(region),
            "principal": text_filter(principal),
            "event": text_filter(event),
            "result": result,
        }
        regions = sorted(
            {
                scope["region"]
                for scope in (
                    json.loads(row["scope"]) for row in store.rows("coverage", generation)
                )
                if scope["dataset"] == "audit.events"
            }
        )
        return render(
            request,
            "activity.html",
            events=store.audit_events(
                generation,
                tenancy=filters["tenancy"],
                region=filters["region"],
                principal=filters["principal"],
                event=filters["event"],
                result=filters["result"],
            ),
            filters=filters,
            filtered=any(filters.values()),
            tenancies=tenancy_options(generation, parent),
            regions=regions,
        )

    @app.get("/data/{table}")
    async def data_page(
        request: Request,
        table: Literal["records", "coverage", "findings", "control_events", "changes"],
        status: str | None = None,
        source: str = "",
        severity: str = "",
        rule: str = "",
        tenancy: str = "",
        dataset: str = "",
        region: str = "",
        q: str = "",
    ) -> Response:
        parent = await access(request)
        generation = request.state.authorized_generation
        if status is None:
            status = "open" if table == "findings" else ""
        allowed = {
            "status": {"complete", "failed"} | FINDING_STATUSES,
            "source": set(get_args(FindingSource)),
            "severity": set(SEVERITIES),
        }
        for name, value in (("status", status), ("source", source), ("severity", severity)):
            if value and value not in allowed[name]:
                raise HTTPException(400, "Unsupported filter value")
        filters = {
            "status": status,
            "source": source,
            "severity": severity,
            "rule": text_filter(rule),
            "tenancy": text_filter(tenancy),
            "dataset": text_filter(dataset),
            "region": text_filter(region),
            "q": text_filter(q),
        }
        rows = (
            # Cost rows have their own tab; exports still include them.
            store.records(generation, exclude=COST)
            if table == "records"
            else store.rows(table, generation)
        )
        for row in rows:
            if "data" in row:
                row["data"] = json.loads(row["data"])
            if "scope" in row:
                row["scope"] = json.loads(row["scope"])
        # Menu options come from everything stored, so narrowing one filter keeps the others.
        options = {
            "dataset": sorted({str(r["scope"]["dataset"]) for r in rows if "scope" in r}),
            "region": sorted({str(r["scope"]["region"]) for r in rows if "scope" in r}),
            "rule": sorted(
                {str(r["data"]["rule_id"]) for r in rows if "rule_id" in r.get("data", {})}
            ),
        }

        def keep(row: dict[str, Any]) -> bool:
            data, scope = row.get("data", {}), row.get("scope", {})
            row_status = data.get("status") if table == "findings" else row.get("status")
            searchable = (
                data.get("title", "")
                if table == "findings"
                else " ".join(
                    str(data.get(field) or "")
                    for field in ("name", "display_name", "user_name", "id")
                )
                + " "
                + str(row.get("key", ""))
            )
            return all(
                (
                    not filters["status"] or row_status == filters["status"],
                    not filters["source"] or data.get("source") == filters["source"],
                    not filters["severity"] or data.get("severity") == filters["severity"],
                    not filters["rule"] or data.get("rule_id") == filters["rule"],
                    not filters["tenancy"] or scope.get("tenancy") == filters["tenancy"],
                    not filters["dataset"] or scope.get("dataset") == filters["dataset"],
                    not filters["region"] or scope.get("region") == filters["region"],
                    not filters["q"] or filters["q"].casefold() in searchable.casefold(),
                )
            )

        rows = [row for row in rows if keep(row)]
        if table == "findings":
            rank = {severity: index for index, severity in enumerate(SEVERITIES)}
            rows.sort(key=lambda row: str(row["data"].get("last_seen", "")), reverse=True)
            rows.sort(
                key=lambda row: (row["data"]["status"] != "open", rank[row["data"]["severity"]])
            )
        else:
            rows.sort(key=lambda row: row.get("status") == "complete")
        return render(
            request,
            "data.html",
            table=table,
            rows=rows,
            filters=filters,
            filtered=narrowed(filters) if table == "findings" else any(filters.values()),
            options=options,
            here=str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
            tenancies=tenancy_options(generation, parent),
            severities=SEVERITIES,
            sources=[
                (source, source.replace("_", " ").title()) for source in get_args(FindingSource)
            ],
        )

    @app.get("/exports/{table}.json")
    async def export(
        request: Request, table: Literal["records", "coverage", "findings"]
    ) -> Response:
        await access(request)
        return JSONResponse(
            store.rows(table, request.state.authorized_generation),
            headers={"Content-Disposition": f'attachment; filename="ogc-{table}.json"'},
        )

    return app
