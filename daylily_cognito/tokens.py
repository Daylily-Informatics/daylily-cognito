"""JWT token decoding and verification helpers.

Provides functions for decoding and validating Cognito JWT tokens
without signature verification (matching existing Ursa behavior).
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import HTTPException, status


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT token without signature verification.

    This function does NOT validate expiration or any claims.
    Use verify_jwt_claims_unverified_signature() for claim validation.

    Args:
        token: JWT token string

    Returns:
        Decoded token claims as dict

    Raises:
        ImportError: If python-jose is not installed
        jose.JWTError: If token is malformed
    """
    try:
        from jose import jwt
    except ImportError as e:
        raise ImportError(
            "python-jose is required for JWT decoding. Install with: pip install 'python-jose[cryptography]'"
        ) from e

    # Key is required by the API but not used when verify_signature=False
    # Disable all claim verification - this is just for decoding
    return jwt.decode(
        token,
        key="",
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_aud": False,
            "verify_iat": False,
            "verify_nbf": False,
        },
    )


def verify_jwt_claims_unverified_signature(
    token: str,
    *,
    expected_client_id: str,
) -> dict[str, Any]:
    """Verify JWT claims without signature verification.

    Matches CognitoAuth.verify_token semantics exactly:
    - Decodes with verify_signature=False
    - Requires 'exp' claim to be present
    - Enforces expiration
    - Enforces client_id match

    Args:
        token: JWT token string
        expected_client_id: Expected app client ID

    Returns:
        Decoded token claims as dict

    Raises:
        HTTPException(401): If token is invalid, expired, or has wrong audience
        ImportError: If python-jose is not installed
    """
    try:
        from jose import ExpiredSignatureError, JWTError, jwt
    except ImportError as e:
        raise ImportError(
            "python-jose is required for JWT verification. Install with: pip install 'python-jose[cryptography]'"
        ) from e

    try:
        # Decode without verification first to get header
        jwt.get_unverified_header(token)

        # Decode with basic validation (no signature verification)
        # Key is required by the API but not used when verify_signature=False
        # Disable exp verification here so we can provide our own error message
        claims: dict[str, Any] = jwt.decode(
            token,
            key="",
            options={
                "verify_signature": False,
                "verify_exp": False,
            },
        )

        # Verify token hasn't expired (manual check for consistent error message)
        if "exp" in claims:
            if claims["exp"] < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                )

        # Verify audience (app client ID)
        if claims.get("client_id") != expected_client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
            )

        return claims

    except ExpiredSignatureError:
        # This shouldn't happen with verify_exp=False, but handle it anyway
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )



def verify_jwt_claims(
    token: str,
    *,
    expected_client_id: str,
    region: str,
    user_pool_id: str,
    cache: "JWKSCache | None" = None,
) -> dict[str, Any]:
    """Verify JWT claims with full signature verification via JWKS.

    Verifies the token signature against Cognito JWKS keys, then
    checks expiration and client_id claims.

    Args:
        token: JWT token string
        expected_client_id: Expected app client ID (checked against 'client_id' claim)
        region: AWS region
        user_pool_id: Cognito User Pool ID
        cache: Optional JWKSCache instance for key caching

    Returns:
        Decoded and verified token claims

    Raises:
        HTTPException(401): If token is invalid, expired, signature fails,
            or has wrong audience
        ImportError: If python-jose is not installed
    """
    try:
        from jose import JWTError
    except ImportError as e:
        raise ImportError(
            "python-jose is required for JWT verification. "
            "Install with: pip install 'python-jose[cryptography]'"
        ) from e

    from .jwks import JWKSCache, verify_token_with_jwks

    try:
        claims = verify_token_with_jwks(
            token, region, user_pool_id, cache=cache
        )

        # Verify token hasn't expired (manual check for consistent error message)
        if "exp" in claims:
            if claims["exp"] < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                )

        # Verify audience (app client ID)
        if claims.get("client_id") != expected_client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
            )

        return claims

    except (KeyError, RuntimeError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )