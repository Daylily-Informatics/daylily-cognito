"""JWT verification helpers for Cognito machine-to-machine access tokens."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from .jwks import JWKSCache


def _normalize_scopes(scopes: str | Iterable[str] | None) -> set[str]:
    """Normalize a Cognito scope value into a set of scope strings."""
    if scopes is None:
        return set()
    if isinstance(scopes, str):
        return {scope for scope in scopes.split() if scope}
    return {scope for scope in scopes if scope}


def _required_scopes_present(
    token_scopes: str | Iterable[str] | None,
    required_scopes: str | Iterable[str] | None,
) -> bool:
    """Return True when the token contains every required scope."""
    return _normalize_scopes(required_scopes).issubset(_normalize_scopes(token_scopes))


def verify_m2m_token_with_jwks(
    token: str,
    *,
    expected_client_id: str,
    region: str,
    user_pool_id: str,
    required_scopes: str | Iterable[str] | None = None,
    cache: "JWKSCache | None" = None,
) -> dict[str, Any]:
    """Verify a Cognito client_credentials access token with JWKS.

    This helper verifies the JWT signature and issuer via the shared JWKS
    path, then enforces Cognito access-token semantics:

    - ``token_use`` must be ``"access"``
    - ``client_id`` must match the expected Cognito app client
    - all ``required_scopes`` must be present in the token's ``scope`` claim

    Args:
        token: JWT access token string.
        expected_client_id: Cognito app client ID that issued the token.
        region: AWS region for the Cognito user pool.
        user_pool_id: Cognito user pool ID.
        required_scopes: One or more scopes that must be present.
        cache: Optional JWKS cache to reuse key fetches.

    Returns:
        Verified token claims.

    Raises:
        ImportError: If python-jose is not installed.
        HTTPException(401): If the token is invalid, expired, or wrong client/type.
        HTTPException(403): If the token is missing required scopes.
    """
    try:
        from jose import ExpiredSignatureError, JWTError
    except ImportError as e:
        raise ImportError(
            "python-jose is required for JWT verification. Install with: pip install 'python-jose[cryptography]'"
        ) from e

    from .jwks import verify_token_with_jwks

    try:
        claims = verify_token_with_jwks(token, region, user_pool_id, cache=cache)

        if claims.get("token_use") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        if claims.get("client_id") != expected_client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
            )

        if not _required_scopes_present(claims.get("scope"), required_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient token scopes",
            )

        return claims

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except (KeyError, RuntimeError, JWTError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
