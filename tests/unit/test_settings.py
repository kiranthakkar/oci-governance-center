"""Validate operator encryption settings before storage initialization."""

import pytest
from pydantic import ValidationError

from oci_governance_center.config import Settings


@pytest.mark.parametrize("key", ["", "synthetic-invalid-key", "a" * 32, "a" * 44, "🔑"])
def test_invalid_encryption_key_has_actionable_redacted_error(settings, key):
    with pytest.raises(ValidationError) as error:
        Settings(**{**settings.model_dump(), "encryption_key": key})
    message = str(error.value)
    assert "ogc encryption-key" in message
    assert "OGC_ENCRYPTION_KEY" in message
    assert "input_value" not in message


def test_valid_encryption_key_is_preserved(settings):
    configured = Settings(**settings.model_dump())
    assert configured.encryption_key == settings.encryption_key


def test_short_setup_password_is_rejected_without_echoing_it(settings):
    with pytest.raises(ValidationError) as error:
        Settings(**{**settings.model_dump(), "setup_password": "too-short"})
    assert "at least 16 characters" in str(error.value)
    assert "too-short" not in str(error.value)
