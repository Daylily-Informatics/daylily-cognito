"""JWKS (JSON Web Key Set) handling for Cognito.

NOTE: JWKS signature verification is not currently implemented.
The existing Ursa codebase constructs the JWKS URL but does not use it
for signature verification. This module is a placeholder for future
implementation.
"""

from __future__ import annotations

from typing import Any


def build_jwks_url(region: str, user_pool_id: str) -> str:
    """Build the JWKS URL for a Cognito user pool.

    Args:
        region: AWS region (e.g., 'us-west-2')
        user_pool_id: Cognito User Pool ID

    Returns:
        JWKS URL string
    """
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"


def fetch_jwks(region: str, user_pool_id: str) -> dict[str, Any]:
    """Fetch JWKS from Cognito.

    Args:
        region: AWS region
        user_pool_id: Cognito User Pool ID

    Returns:
        JWKS dict

    Raises:
        NotImplementedError: This function is not yet implemented.
    """
    raise NotImplementedError(
        "JWKS fetching is not yet implemented. Token verification currently uses verify_signature=False."
    )


def verify_token_with_jwks(token: str, region: str, user_pool_id: str) -> dict[str, Any]:
    """Verify a JWT token using JWKS.

    Args:
        token: JWT token string
        region: AWS region
        user_pool_id: Cognito User Pool ID

    Returns:
        Decoded and verified token claims

    Raises:
        NotImplementedError: This function is not yet implemented.
    """
    raise NotImplementedError(
        "JWKS-based token verification is not yet implemented. Use verify_jwt_claims_unverified_signature() instead."
    )
