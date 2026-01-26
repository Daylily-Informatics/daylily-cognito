"""Tests for JWT token verification (unverified signature mode).

These tests are skipped if python-jose is not installed.
"""

import time

import pytest

# Skip all tests if jose is not available
jose = pytest.importorskip("jose", reason="python-jose not installed")

from fastapi import HTTPException

from daylily_cognito.tokens import (
    decode_jwt_unverified,
    verify_jwt_claims_unverified_signature,
)


def _create_test_token(claims: dict, exp_offset: int = 3600) -> str:
    """Create a test JWT token with given claims.

    Args:
        claims: Token claims
        exp_offset: Seconds from now for expiration (negative = expired)

    Returns:
        JWT token string
    """
    from jose import jwt

    full_claims = {
        "exp": int(time.time()) + exp_offset,
        **claims,
    }
    # Use a dummy key since we're not verifying signatures
    return jwt.encode(full_claims, "secret", algorithm="HS256")


class TestDecodeJwtUnverified:
    """Tests for decode_jwt_unverified()."""

    def test_decode_valid_token(self) -> None:
        """Decodes a valid token."""
        token = _create_test_token({"sub": "user123", "client_id": "client456"})
        claims = decode_jwt_unverified(token)

        assert claims["sub"] == "user123"
        assert claims["client_id"] == "client456"
        assert "exp" in claims

    def test_decode_expired_token(self) -> None:
        """Decodes expired token (no expiration check in this function)."""
        token = _create_test_token({"sub": "user123"}, exp_offset=-3600)
        claims = decode_jwt_unverified(token)

        assert claims["sub"] == "user123"
        # Note: decode_jwt_unverified does NOT check expiration


class TestVerifyJwtClaimsUnverifiedSignature:
    """Tests for verify_jwt_claims_unverified_signature()."""

    def test_valid_token(self) -> None:
        """Valid token with matching client_id passes."""
        token = _create_test_token({"sub": "user123", "client_id": "expected_client"})
        claims = verify_jwt_claims_unverified_signature(token, expected_client_id="expected_client")

        assert claims["sub"] == "user123"
        assert claims["client_id"] == "expected_client"

    def test_expired_token_raises(self) -> None:
        """Expired token raises HTTPException with 'Token has expired'."""
        token = _create_test_token({"sub": "user123", "client_id": "client"}, exp_offset=-3600)

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims_unverified_signature(token, expected_client_id="client")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has expired"

    def test_wrong_client_id_raises(self) -> None:
        """Wrong client_id raises HTTPException with 'Invalid token audience'."""
        token = _create_test_token({"sub": "user123", "client_id": "wrong_client"})

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims_unverified_signature(token, expected_client_id="expected_client")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token audience"

    def test_malformed_token_raises(self) -> None:
        """Malformed token raises HTTPException with 'Invalid authentication token'."""
        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims_unverified_signature("not.a.valid.token", expected_client_id="client")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    def test_missing_client_id_raises(self) -> None:
        """Token without client_id raises HTTPException."""
        token = _create_test_token({"sub": "user123"})  # No client_id

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims_unverified_signature(token, expected_client_id="expected_client")

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token audience"
