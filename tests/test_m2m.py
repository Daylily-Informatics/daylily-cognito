"""Tests for Cognito M2M JWT verification helpers."""

from __future__ import annotations

from unittest import mock

import pytest
from fastapi import HTTPException, status

from daylily_auth_cognito.runtime.m2m import verify_m2m_token_with_jwks


def test_verify_m2m_token_accepts_valid_token_with_required_scopes() -> None:
    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={
            "token_use": "access",
            "client_id": "client-123",
            "scope": "read write",
            "sub": "svc-123",
        },
    ):
        claims = verify_m2m_token_with_jwks(
            "token-123",
            expected_client_id="client-123",
            region="us-west-2",
            user_pool_id="pool-123",
            required_scopes=["read"],
        )

    assert claims["sub"] == "svc-123"


def test_verify_m2m_token_rejects_wrong_token_type_or_audience() -> None:
    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"token_use": "id", "client_id": "client-123", "scope": "read"},
    ):
        with pytest.raises(HTTPException, match="Invalid token type"):
            verify_m2m_token_with_jwks(
                "token-123",
                expected_client_id="client-123",
                region="us-west-2",
                user_pool_id="pool-123",
            )

    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"token_use": "access", "client_id": "wrong-client", "scope": "read"},
    ):
        with pytest.raises(HTTPException, match="Invalid token audience"):
            verify_m2m_token_with_jwks(
                "token-123",
                expected_client_id="client-123",
                region="us-west-2",
                user_pool_id="pool-123",
            )


def test_verify_m2m_token_rejects_missing_scopes() -> None:
    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"token_use": "access", "client_id": "client-123", "scope": "read"},
    ):
        with pytest.raises(HTTPException) as exc_info:
            verify_m2m_token_with_jwks(
                "token-123",
                expected_client_id="client-123",
                region="us-west-2",
                user_pool_id="pool-123",
                required_scopes=["read", "write"],
            )

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "Insufficient token scopes"
