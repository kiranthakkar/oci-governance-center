"""Web authentication, roles, CSRF and security headers (docs/control-plane.md §6).

* OIDC Authorization Code + PKCE (S256) via Authlib; state and nonce are generated and verified by
  Authlib, and the ID token is validated against the domain's JWKS (iss, aud, exp, nonce).
* Roles come from identity-domain groups: ``OSC-Admins`` → admin, ``OSC-Viewers`` → viewer,
  anything else → 403.
* Workstation mode only: a localhost-only "local sign-in" for single-user use with a CLI profile.
* Host / Origin allow-list on every request (defends the localhost UI against DNS rebinding).
* Group membership is re-checked whenever the OIDC access token is refreshed.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from oci_security_center.auth.signers import AuthError
from oci_security_center.config import DeploymentMode, Settings

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"


@dataclass(frozen=True)
class User:
    name: str
    role: str
    via: str  # "oidc" | "local"


class LoginRequired(Exception):
    pass


def current_user(request: Request) -> User | None:
    data = request.session.get("user")
    if not isinstance(data, dict):
        return None
    return User(data["name"], data["role"], data["via"])


def require_user(request: Request) -> User:
    user = current_user(request)
    if user is None:
        raise LoginRequired()
    return user


def require_admin(request: Request) -> User:
    user = require_user(request)
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="OSC-Admins only")
    return user


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def verify_csrf(request: Request) -> None:
    form = await request.form()
    sent = form.get("csrf_token")
    expected = request.session.get("csrf")
    if (
        not isinstance(sent, str)
        or not isinstance(expected, str)
        or not hmac.compare_digest(sent, expected)
    ):
        raise HTTPException(status_code=403, detail="invalid CSRF token")


def role_from_groups(groups: Any, settings: Settings) -> str | None:
    names: set[str] = set()
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str):
                names.add(g.lower())
            elif isinstance(g, dict):
                for key in ("name", "display", "value"):
                    if isinstance(g.get(key), str):
                        names.add(str(g[key]).lower())
    if settings.group_admins.lower() in names:
        return ROLE_ADMIN
    if settings.group_viewers.lower() in names:
        return ROLE_VIEWER
    return None


def is_local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "testclient")


def local_login_allowed(request: Request, settings: Settings) -> bool:
    return settings.deployment is DeploymentMode.WORKSTATION and is_local_request(request)


def establish_session(
    request: Request, user: User, tokens: dict[str, Any] | None, generation: int
) -> None:
    request.session.clear()
    request.session["user"] = {"name": user.name, "role": user.role, "via": user.via}
    request.session["generation"] = generation
    if tokens:
        request.session["tokens"] = tokens
    request.session["csrf"] = secrets.token_urlsafe(32)
    request.session["__rotate__"] = True  # new session id after login (fixation defence)


def jwt_provider_for(
    request: Request, client_id: str, client_secret: str, settings: Settings
) -> Callable[[], str]:
    """Return the signed-in admin's access token for ``TokenExchangeSigner``; refresh if needed.

    On refresh, group membership is re-read from the userinfo endpoint. If the user is no longer
    in an OSC group (or membership can't be confirmed) the session ends; if their role changed,
    the session is updated and the current action is refused.
    """

    def end_session(message: str) -> AuthError:
        request.session.clear()
        request.session["__clear__"] = True
        return AuthError(message)

    def provider() -> str:
        tokens = request.session.get("tokens")
        if not isinstance(tokens, dict):
            raise AuthError("no OIDC session; sign in again")
        if tokens.get("expires_at", 0) - 60 > time.time():
            return str(tokens["access_token"])
        refresh, endpoint = tokens.get("refresh_token"), tokens.get("token_endpoint")
        if not refresh or not endpoint:
            raise end_session("OIDC session expired; sign in again")
        resp = httpx.post(
            endpoint,
            data={"grant_type": "refresh_token", "refresh_token": refresh},
            auth=(client_id, client_secret),
            timeout=15,
        )
        if resp.status_code != 200:
            raise end_session("could not refresh OIDC session; sign in again")
        body = resp.json()
        access = str(body["access_token"])
        role = _current_role(tokens.get("userinfo_endpoint"), access, settings)
        user = request.session.get("user")
        if role is None or not isinstance(user, dict):
            raise end_session(
                "could not confirm your OSC group membership; sign in again "
                f"(you must be in {settings.group_admins} or {settings.group_viewers})"
            )
        tokens.update(
            {
                "access_token": access,
                "refresh_token": body.get("refresh_token", refresh),
                "expires_at": int(time.time()) + int(body.get("expires_in", 3600)),
            }
        )
        request.session["tokens"] = tokens
        if role != user.get("role"):
            request.session["user"] = {**user, "role": role}
            raise AuthError(f"your OSC role changed to {role}; reload the page")
        return access

    return provider


def _current_role(userinfo_endpoint: Any, access_token: str, settings: Settings) -> str | None:
    """Read the groups claim from the domain's userinfo endpoint (read-only GET)."""
    if not isinstance(userinfo_endpoint, str) or not userinfo_endpoint.startswith("https://"):
        return None
    try:
        resp = httpx.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    return role_from_groups(resp.json().get(settings.groups_claim), settings)


def _hostname(value: str) -> str:
    try:
        return (urlsplit("//" + value).hostname or "").lower()
    except ValueError:
        return ""


class TrustedHostMiddleware:
    """Reject requests whose Host (or, for unsafe methods, Origin) isn't one of ours.

    Without this, a web page can rebind its own domain to 127.0.0.1 and talk to the
    workstation UI as a same-origin client.
    """

    _SAFE = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        self.app, self.allowed = app, frozenset(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        problem = None
        if _hostname(headers.get("host", "")) not in self.allowed:
            problem = (400, b"Invalid host header")
        elif scope["method"] not in self._SAFE and "origin" in headers:
            origin = headers["origin"]
            if origin == "null" or _hostname(urlsplit(origin).netloc) not in self.allowed:
                problem = (403, b"Cross-origin request refused")
        if problem is None:
            await self.app(scope, receive, send)
            return
        status, body = problem
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain"), (b"cache-control", b"no-store")],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool) -> None:
        self.app, self.hsts = app, hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self'; "
                        b"img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
                    ),
                    (b"x-frame-options", b"DENY"),
                    (b"x-content-type-options", b"nosniff"),
                    # same-origin, not no-referrer: under no-referrer browsers send
                    # "Origin: null" even on same-site form posts, which the Origin check refuses.
                    # Other sites still get no referrer (URLs here contain OCIDs).
                    (b"referrer-policy", b"same-origin"),
                    (b"cache-control", b"no-store"),
                ]
                if self.hsts:
                    headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped)


class MaintenanceMiddleware:
    """Refuse state-changing requests while an organization switch/restore holds the barrier.

    Read-only pages keep working; storage fencing still rejects any write that slips through.
    """

    _SAFE = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, app: ASGIApp, in_maintenance: Callable[[], bool]) -> None:
        self.app, self.in_maintenance = app, in_maintenance

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in self._SAFE or not self.in_maintenance():
            await self.app(scope, receive, send)
            return
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"retry-after", b"60"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": b"OSC is in maintenance; try again shortly."}
        )


class LoginRateLimiter:
    """Small in-memory limiter for login/callback endpoints (per client IP)."""

    def __init__(self, max_hits: int = 20, window_s: int = 60, max_ips: int = 10_000) -> None:
        self.max_hits, self.window, self.max_ips = max_hits, window_s, max_ips
        self.hits: dict[str, list[float]] = {}

    def check(self, request: Request) -> None:
        ip = request.client.host if request.client else "?"
        now = time.time()
        if len(self.hits) >= self.max_ips:  # forget IPs with nothing in the window
            self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < self.window}
        recent = [t for t in self.hits.get(ip, []) if now - t < self.window]
        if len(recent) >= self.max_hits:
            raise HTTPException(status_code=429, detail="too many sign-in attempts")
        recent.append(now)
        self.hits[ip] = recent
