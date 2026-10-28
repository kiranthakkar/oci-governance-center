"""Credential-safe request summaries and pre-ASGI HTTP parser diagnostics."""

from __future__ import annotations

import logging
import secrets
import time
import traceback
from pathlib import Path
from typing import Any

import h11
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol

from ..logging import request_id_context

logger = logging.getLogger(__name__)


class DiagnosticConnection(h11.Connection):
    """Categorize parser failures without retaining or logging their raw error messages."""

    safe_error = "Malformed HTTP/1.1 request; check request-line and header syntax."

    def next_event(self) -> Any:
        try:
            return super().next_event()
        except h11.RemoteProtocolError as error:
            reason = str(error).casefold()
            for marker, explanation in (
                ("multiple host", "Multiple Host headers received; send exactly one Host header."),
                ("missing mandatory host", "HTTP/1.1 request is missing its required Host header."),
                ("receive buffer too long", "HTTP request headers exceed the parser size limit."),
                ("illegal header", "Malformed HTTP header syntax."),
                ("illegal request line", "Malformed HTTP request line or a non-HTTP protocol."),
            ):
                if marker in reason:
                    self.safe_error = explanation
                    break
            raise


class DiagnosticHTTPProtocol(H11Protocol):
    """Pinned Uvicorn h11 protocol with safe connection-level rejection explanations."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        options = {}
        if self.config.h11_max_incomplete_event_size is not None:
            options["max_incomplete_event_size"] = self.config.h11_max_incomplete_event_size
        self.diagnostic_connection = DiagnosticConnection(h11.SERVER, **options)
        self.conn = self.diagnostic_connection
        self._diagnostic_prefix = b""

    def data_received(self, data: bytes) -> None:
        self._diagnostic_prefix = (self._diagnostic_prefix + data[:32])[:32]
        super().data_received(data)

    def send_400_response(self, msg: str) -> None:
        prefix = self._diagnostic_prefix
        reason = self.diagnostic_connection.safe_error
        if prefix.startswith(b"\x16\x03"):
            reason = (
                "TLS handshake received on a plain HTTP listener. Configure the load balancer "
                "backend protocol as HTTP; terminate HTTPS at the load balancer."
            )
        elif prefix.startswith(b"PRI * HTTP/2"):
            reason = "HTTP/2 preface received; configure the load balancer backend for HTTP/1.1."
        elif prefix.startswith((b"PROXY ", b"\r\n\r\n\x00\r\nQUIT\n")):
            reason = "PROXY protocol received; disable PROXY protocol on this HTTP backend."
        logger.warning("HTTP connection rejected: peer=%s, reason=%s", self.client, reason)
        super().send_400_response(msg)


class RequestDiagnostics:
    """Log route patterns, status and duration; never headers, query strings or raw bodies."""

    def __init__(self, app: ASGIApp, expected_host: str) -> None:
        self.app, self.expected_host = app, expected_host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ident = secrets.token_hex(12)
        context = request_id_context.set(ident)
        started = time.perf_counter()
        status = 500
        response_started = False
        failure = ""
        method = scope.get("method", "")
        if method not in {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "TRACE",
            "CONNECT",
        }:
            method = "OTHER"

        async def observed(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status = message["status"]
                message = {
                    **message,
                    "headers": [*message.get("headers", []), (b"x-ogc-request-id", ident.encode())],
                }
            await send(message)

        try:
            await self.app(scope, receive, observed)
        except Exception as error:
            failure = type(error).__name__
            frames = traceback.extract_tb(error.__traceback__)[-12:]
            locations = " -> ".join(f"{Path(f.filename).name}:{f.lineno}:{f.name}" for f in frames)
            logger.error(
                "Web exception: request_id=%s, type=%s, locations=%s", ident, failure, locations
            )
            if response_started:
                raise
            await PlainTextResponse(f"Request failed. Reference: {ident}", status_code=500)(
                scope, receive, observed
            )
        finally:
            route = getattr(scope.get("route"), "path", "<unmatched>")
            hint = ""
            if status == 400 and route == "<unmatched>":
                hint = f"Check Host header; expected application host is {self.expected_host}."
            elif status == 403:
                hint = "Check application role, CSRF token and form origin."
            elif status >= 500:
                hint = "Check the matching request_id exception event."
            level = (
                logging.ERROR
                if status >= 500
                else logging.WARNING
                if status >= 400
                else logging.INFO
            )
            logger.log(
                level,
                "Web request: request_id=%s, peer=%s, method=%s, route=%s, status=%s, "
                "duration_ms=%.1f, error_type=%s, hint=%s",
                ident,
                scope.get("client"),
                method,
                route,
                status,
                (time.perf_counter() - started) * 1000,
                failure or "none",
                hint or "none",
            )
            request_id_context.reset(context)
