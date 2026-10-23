"""JWT verification with a pinned algorithm and trusted, externally supplied key set."""

from typing import Any

from joserfc import jwk, jwt


def verify_jwt(
    token: str,
    keys: jwk.KeySetSerialization,
    issuer: str,
    audience: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Verify JWT identity and time using trusted keys, never token-controlled key URLs."""
    decoded = jwt.decode(token, jwk.KeySet.import_key_set(keys), algorithms=["RS256"])
    options: dict[str, Any] = {
        "iss": {"essential": True, "value": issuer},
        "exp": {"essential": True},
        "sub": {"essential": True},
    }
    if audience is not None:
        options["aud"] = {"essential": True, "value": audience}
    if nonce is not None:
        options["nonce"] = {"essential": True, "value": nonce}
    jwt.JWTClaimsRegistry(leeway=30, **options).validate(decoded.claims)
    claims = decoded.claims
    if audience is not None:
        audiences = claims["aud"]
        if (isinstance(audiences, list) and len(audiences) > 1 or "azp" in claims) and claims.get(
            "azp"
        ) != audience:
            raise ValueError("ID-token authorized party does not match the login client")
    return claims


def verify_user_access_token(
    token: str,
    keys: jwk.KeySetSerialization,
    issuer: str,
    client_id: str,
    domain_url: str,
) -> dict[str, Any]:
    """Validate a signed IAM API access token bound to this OAuth client and a human user."""
    claims = verify_jwt(token, keys, issuer)
    if claims.get("tok_type") != "AT" or claims.get("sub_type") != "user":
        raise ValueError("Login requires a user access token, not a client or identity token")
    if claims.get("client_id") != client_id and claims.get("client_name") != client_id:
        raise ValueError("Access token does not belong to the configured login client")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    accepted = {
        domain_url,
        domain_url + "/",
        "https://identity.oraclecloud.com/",
        "https://identity.oraclecloud.com",
    }
    if (
        not isinstance(audiences, list)
        or not all(isinstance(value, str) for value in audiences)
        or not any(value in accepted for value in audiences)
    ):
        raise ValueError("Access-token audience does not include the identity-domain API")
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise ValueError("Access token has no usable user identity")
    return claims
