"""Source-specific severities; an unknown value is never promoted to a severe finding."""

from .models import SEVERITIES, Severity


def cloud_guard_severity(value: str) -> Severity:
    """Preserve known native Cloud Guard risk levels."""
    return next((severity for severity in SEVERITIES if severity == value), "INFO")


def advisor_severity(value: str) -> Severity:
    """Map Advisor importance one level lower than its source risk equivalent."""
    mapping: dict[str, Severity] = {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MODERATE": "LOW",
        "MEDIUM": "LOW",
        "LOW": "INFO",
    }
    return mapping.get(value, "INFO")
