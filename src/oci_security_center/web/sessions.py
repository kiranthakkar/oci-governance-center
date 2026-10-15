"""Server-side sessions (docs/control-plane.md §6).

The browser only holds an opaque random ID in an ``HttpOnly`` cookie. Session contents (user,
role, OIDC tokens, CSRF token, PKCE/nonce state) are Fernet-encrypted in ``osc.db``, keyed by the
SHA-256 of the cookie value, with an idle timeout and an absolute lifetime. Sessions without a
signed-in user (sign-in page, OIDC round trip) get a short idle timeout, and expired rows are
pruned whenever a new session is created.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from datetime import timedelta
from http.cookies import SimpleCookie
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from oci_security_center.auth.secrets import SecretResolver
from oci_security_center.models import utcnow
from oci_security_center.storage.sqlite.app_state import SqliteAppStateStore

COOKIE = "osc_session"
ANONYMOUS_IDLE = timedelta(minutes=10)
_CREATED = "__created__"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ServerSideSessionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        store: SqliteAppStateStore,
        crypto: SecretResolver,
        idle_minutes: int,
        secure: bool,
        max_hours: int = 12,
        generation: Callable[[], int] | None = None,
    ) -> None:
        self.app, self.store, self.crypto = app, store, crypto
        self.generation = generation
        self.idle = timedelta(minutes=idle_minutes)
        self.max_age_s = max_hours * 3600
        self.secure = secure

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        token = self._cookie(scope)
        data: dict[str, Any] = {}
        if token:
            blob = self.store.get_session(_hash(token))
            if blob is not None:
                try:
                    data = json.loads(self.crypto.decrypt(blob))
                except Exception:
                    data = {}
                expired = time.time() - float(data.get(_CREATED, 0)) > self.max_age_s
                # A signed-in session belongs to one organization generation (control-plane §6.1).
                stale = (
                    "user" in data
                    and self.generation is not None
                    and data.get("generation") != self.generation()
                )
                if expired or stale:
                    self.store.delete_session(_hash(token))
                    data, token = {}, None
            else:
                token = None
        scope["session"] = data

        async def send_wrapper(message: Message) -> None:
            nonlocal token
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                session: dict[str, Any] = scope["session"]
                if session.get("__clear__"):
                    if token:
                        self.store.delete_session(_hash(token))
                    headers.append("Set-Cookie", self._cookie_header("", max_age=0))
                elif session:
                    if token is None:
                        token = secrets.token_urlsafe(32)
                        self.store.prune_expired_sessions()
                        session[_CREATED] = time.time()
                    # Always persist to slide the idle timeout; rotate on privilege change.
                    if session.pop("__rotate__", False) and token:
                        self.store.delete_session(_hash(token))
                        token = secrets.token_urlsafe(32)
                        session[_CREATED] = time.time()  # lifetime starts at sign-in
                    idle = self.idle if "user" in session else min(self.idle, ANONYMOUS_IDLE)
                    blob = self.crypto.encrypt(json.dumps(session).encode())
                    self.store.put_session(_hash(token), blob, utcnow() + idle)
                    if token != self._cookie(scope):
                        headers.append("Set-Cookie", self._cookie_header(token))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    @staticmethod
    def _cookie(scope: Scope) -> str | None:
        for name, value in scope.get("headers", []):
            if name == b"cookie":
                jar: SimpleCookie = SimpleCookie()
                jar.load(value.decode("latin-1"))
                if COOKIE in jar:
                    return jar[COOKIE].value
        return None

    def _cookie_header(self, value: str, max_age: int | None = None) -> str:
        parts = [f"{COOKIE}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if self.secure:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)
