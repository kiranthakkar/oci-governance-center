"""Structured, minimal logging; SDK and HTTP request logging stays disabled."""

import json
import logging
import re
from datetime import UTC, datetime


class Redaction(logging.Filter):
    """Remove credentials and private-key blocks before any handler formats a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        message = re.sub(
            r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----",
            "[REDACTED KEY]",
            message,
            flags=re.DOTALL,
        )
        message = re.sub(
            r"(?i)(authorization|client_secret|access_token|id_token|private_key)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            message,
        )
        message = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED TOKEN]", message
        )
        record.msg, record.args = message, ()
        record.exc_info, record.exc_text = None, None
        return True


class Structured(logging.Formatter):
    """Format already-redacted application events without exception response bodies."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


def configure_logging() -> None:
    """Install structured redaction and disable SDK/transport request diagnostics."""
    handler = logging.StreamHandler()
    handler.addFilter(Redaction())
    handler.setFormatter(Structured())
    logging.getLogger().handlers = [handler]
    logging.getLogger().setLevel(logging.INFO)
    for name in ("oci", "httpx", "httpcore", "requests", "urllib3"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
