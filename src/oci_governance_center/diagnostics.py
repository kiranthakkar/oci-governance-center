"""Actionable verification errors without SDK response bodies or credential material."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import oci
import requests

logger = logging.getLogger(__name__)


class PublicFailure(RuntimeError):
    """A deliberately authored, credential-free explanation suitable for application display."""


def safe_reason(error: Exception) -> str:
    """Describe a failure by category; never interpolate arbitrary exception messages."""
    if isinstance(error, PublicFailure):
        return str(error)
    oauth_error = getattr(error, "error", None)
    if isinstance(oauth_error, str) and oauth_error in {
        "invalid_client",
        "invalid_grant",
        "invalid_request",
        "invalid_scope",
        "unauthorized_client",
        "unsupported_grant_type",
        "access_denied",
    }:
        return f"The identity domain rejected the OAuth request ({oauth_error})."
    if isinstance(error, httpx.HTTPStatusError):
        return f"The identity domain returned HTTP {error.response.status_code}."
    if isinstance(error, httpx.TimeoutException):
        return "The identity-domain request timed out."
    if isinstance(error, httpx.RequestError):
        return "Connection to the identity domain failed; check DNS, TLS, and network access."
    if isinstance(error, oci.exceptions.ServiceError):
        reasons = {
            400: "Check the identifiers, region, and query parameters.",
            401: "Check the uploaded API key, user OCID, fingerprint, and server clock.",
            403: "Check the scanner group's local IAM policies and identity-domain read access.",
            404: "Check OCIDs, home region, and IAM access; OCI may hide denied resources.",
            429: "OCI rate limiting persisted after retries; try again later.",
        }
        return f"OCI returned HTTP {error.status}. " + reasons.get(
            error.status, "Check OCI service availability and try again."
        )
    if isinstance(error, requests.exceptions.SSLError):
        return "TLS verification failed; check server certificates and proxy configuration."
    if isinstance(error, requests.exceptions.Timeout):
        return "The request timed out; check connectivity to OCI and the identity-domain endpoint."
    if isinstance(error, requests.exceptions.ConnectionError):
        return "Connection failed; check DNS, network access, and the identity-domain endpoint."
    known_validation = {
        "The token endpoint did not return a usable access token": (
            "The token endpoint did not return a usable access token."
        ),
        "OIDC endpoint is outside the configured identity domain": (
            "The discovered endpoint is outside the configured identity domain."
        ),
        "Login requires a user access token, not a client or identity token": (
            "Login requires a user access token, not a client or identity token."
        ),
        "Access token does not belong to the configured login client": (
            "Access token does not belong to the configured login client."
        ),
        "Access-token audience does not include the identity-domain API": (
            "Access-token audience does not include the identity-domain API."
        ),
        "Access token has no usable user identity": "Access token has no usable user identity.",
        "Human access-token authorization expired or unavailable; sign in again": (
            "Human access-token authorization expired or unavailable; sign in again."
        ),
        "Access-token subject mapping is unsupported": "Unsupported access-token subject mapping.",
        "Membership of ogc_admin or ogc_viewer is required": (
            "Membership of ogc_admin or ogc_viewer is required."
        ),
        "Asserter identity does not match the verified access token": (
            "Asserter identity does not match the verified access token."
        ),
        "Asserter group membership is malformed": "Asserter group membership is malformed.",
        "Human authorization expired; sign in again": "Human authorization expired; sign in again.",
        "ID-token authorized party does not match the login client": (
            "ID-token authorized party does not match the login client."
        ),
        "API public-key fingerprint does not match private key": (
            "The uploaded private key does not match the supplied API-key fingerprint."
        ),
        "Use an unencrypted RSA API private key of at least 2048 bits": (
            "Upload an unencrypted RSA API private key of at least 2048 bits."
        ),
    }
    if isinstance(error, ValueError) and str(error) in known_validation:
        return known_validation[str(error)]
    if isinstance(error, (ValueError, TypeError)):
        return (
            f"Configuration or OCI response validation failed. Error type: {type(error).__name__}."
        )
    return f"The operation failed unexpectedly. Error type: {type(error).__name__}."


@contextmanager
def verification_step(step: str) -> Iterator[None]:
    """Label one enrollment operation and log only the safe diagnostic, never its raw cause."""
    try:
        yield
    except Exception as error:
        message = f"Verification failed at {step}: {safe_reason(error)}"
        logger.warning("%s", message)
        raise PublicFailure(message) from None
