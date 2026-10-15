"""Structured JSON logging with a redaction filter (AGENTS.md §2.4).

Never log full OCI request/response bodies. The filter below is a last line of defence that
scrubs anything resembling a credential before it reaches a handler.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

_REDACTED = "[REDACTED]"

_PATTERNS: list[re.Pattern[str]] = [
    # PEM private keys
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    # Bearer / ST$ (OCI security token) headers
    re.compile(r"(?i)\b(bearer|ST\$)\s*[A-Za-z0-9\-_\.=]+"),
    # OAuth values in URLs, e.g. uvicorn access log lines for /auth/callback?code=...&state=...
    re.compile(r"(?i)(?<=[?&])(code|state|session_state|id_token_hint)(=)([^&\s\"]+)"),
    # JWTs
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    # key=value style secrets
    re.compile(
        r"(?i)(client_secret|secret|password|passphrase|access_token|refresh_token|id_token"
        r"|api_key|private_key)(\"?\s*[:=]\s*\"?)([^\s\",}]+)"
    ),
]

_SENSITIVE_KEYS = {
    "client_secret",
    "secret",
    "password",
    "pass_phrase",
    "passphrase",
    "access_token",
    "refresh_token",
    "id_token",
    "private_key",
    "key_content",
    "token",
    "authorization",
}


def redact(text: str) -> str:
    """Return ``text`` with credential-like substrings replaced."""
    for pattern in _PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
        else:
            text = pattern.sub(_REDACTED, text)
    return text


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact values whose key looks sensitive."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in _SENSITIVE_KEYS:
            out[key] = _REDACTED
        elif isinstance(value, dict):
            out[key] = redact_mapping(value)
        elif isinstance(value, str):
            out[key] = redact(value)
        else:
            out[key] = value
    return out


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        extra = getattr(record, "osc", None)
        if isinstance(extra, dict):
            record.osc = redact_mapping(extra)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "osc", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # The OCI SDK can log request details at DEBUG; keep it quiet.
    logging.getLogger("oci").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
