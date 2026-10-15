"""Severity mapping from each source to OSC's scale (AGENTS.md §5). The only place it is defined."""

from __future__ import annotations

from oci_security_center.models.findings import Severity

# Cloud Guard problem risk levels.
_CLOUD_GUARD = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "MINOR": Severity.INFO,
}
# Cloud Advisor recommendation importance. Advisor recommendations are advisory (cost,
# performance, availability), so they map one step below the source's own wording.
_ADVISOR = {
    "CRITICAL": Severity.HIGH,
    "HIGH": Severity.MEDIUM,
    "MODERATE": Severity.LOW,
    "LOW": Severity.INFO,
    "MINOR": Severity.INFO,
}


def from_cloud_guard(risk_level: str | None) -> Severity:
    return _CLOUD_GUARD.get((risk_level or "").upper(), Severity.MEDIUM)


def from_advisor(importance: str | None) -> Severity:
    return _ADVISOR.get((importance or "").upper(), Severity.INFO)
