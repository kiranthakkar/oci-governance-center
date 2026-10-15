"""Shared types and helpers for models."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AfterValidator

_OCID_RE = re.compile(r"^ocid1\.[a-z0-9_\-]+\.[a-z0-9_\-]*\.[a-z0-9_\-]*\.[A-Za-z0-9_\-\.]+$")


def _validate_ocid(value: str) -> str:
    if not _OCID_RE.match(value):
        raise ValueError(f"not a valid OCID: {value!r}")
    return value


Ocid = Annotated[str, AfterValidator(_validate_ocid)]


def is_ocid(value: str) -> bool:
    return bool(_OCID_RE.match(value))


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("naive datetimes are not allowed; use UTC")
    return dt.astimezone(UTC).isoformat()


def canonical_json(data: Any) -> str:
    """Deterministic JSON used for hashing and storage."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def content_hash(data: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()
