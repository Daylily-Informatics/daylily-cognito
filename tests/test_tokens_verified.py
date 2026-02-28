"""Tests for JWT token verification with signature verification path."""

from __future__ import annotations

import builtins
import time
from unittest import mock

import pytest
from fastapi import HTTPException

# Skip module if jose is not available in environment.
jose = pytest.importorskip("jose", reason="python-jose not installed")
from jose import JWTError

from daylily_cognito.tokens import verify_jwt_claims


class TestVerifyJwtClaims:
    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_valid_claims(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.return_value = {
            "sub": "user123",
            "client_id": "expected_client",
            "exp": int(time.time()) + 3600,
        }

        claims = verify_jwt_claims(
            "token",
            expected_client_id="expected_client",
            region="us-west-2",
            user_pool_id="us-west-2_pool",
        )

        assert claims["sub"] == "user123"
        assert claims["client_id"] == "expected_client"

    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_expired_claims_raise(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.return_value = {
            "sub": "user123",
            "client_id": "expected_client",
            "exp": int(time.time()) - 10,
        }

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims(
                "token",
                expected_client_id="expected_client",
                region="us-west-2",
                user_pool_id="us-west-2_pool",
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has expired"

    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_wrong_audience_raises(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.return_value = {
            "sub": "user123",
            "client_id": "wrong_client",
            "exp": int(time.time()) + 3600,
        }

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims(
                "token",
                expected_client_id="expected_client",
                region="us-west-2",
                user_pool_id="us-west-2_pool",
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token audience"

    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_key_error_maps_to_invalid_auth(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.side_effect = KeyError("kid")

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims(
                "token",
                expected_client_id="expected_client",
                region="us-west-2",
                user_pool_id="us-west-2_pool",
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_runtime_error_maps_to_invalid_auth(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.side_effect = RuntimeError("jwks unavailable")

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims(
                "token",
                expected_client_id="expected_client",
                region="us-west-2",
                user_pool_id="us-west-2_pool",
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    @mock.patch("daylily_cognito.jwks.verify_token_with_jwks")
    def test_jwt_error_maps_to_invalid_auth(self, mock_verify: mock.MagicMock) -> None:
        mock_verify.side_effect = JWTError("bad token")

        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_claims(
                "token",
                expected_client_id="expected_client",
                region="us-west-2",
                user_pool_id="us-west-2_pool",
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid authentication token"

    def test_import_error_when_jose_missing(self) -> None:
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "jose":
                raise ImportError("missing jose")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            with pytest.raises(ImportError) as exc_info:
                verify_jwt_claims(
                    "token",
                    expected_client_id="expected_client",
                    region="us-west-2",
                    user_pool_id="us-west-2_pool",
                )

        assert "python-jose is required for JWT verification" in str(exc_info.value)
