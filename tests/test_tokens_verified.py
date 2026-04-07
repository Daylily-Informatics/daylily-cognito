"""Tests for signature-verified JWT claim handling."""

from __future__ import annotations

import time
from unittest import mock

import pytest
from fastapi import HTTPException

from daylily_auth_cognito.runtime.tokens import verify_jwt_claims
from daylily_auth_cognito.runtime.verifier import CognitoTokenVerifier


def test_verify_jwt_claims_accepts_valid_claims() -> None:
    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"sub": "user-123", "client_id": "client-123", "exp": time.time() + 60},
    ):
        claims = verify_jwt_claims(
            "token-123",
            expected_client_id="client-123",
            region="us-west-2",
            user_pool_id="pool-123",
        )

    assert claims["sub"] == "user-123"


def test_verify_jwt_claims_rejects_expired_or_wrong_audience() -> None:
    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"client_id": "client-123", "exp": time.time() - 1},
    ):
        with pytest.raises(HTTPException, match="Token has expired"):
            verify_jwt_claims(
                "token-123",
                expected_client_id="client-123",
                region="us-west-2",
                user_pool_id="pool-123",
            )

    with mock.patch(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        return_value={"client_id": "wrong-client", "exp": time.time() + 60},
    ):
        with pytest.raises(HTTPException, match="Invalid token audience"):
            verify_jwt_claims(
                "token-123",
                expected_client_id="client-123",
                region="us-west-2",
                user_pool_id="pool-123",
            )


def test_cognito_token_verifier_uses_jwks_path() -> None:
    cache = mock.Mock()
    with mock.patch(
        "daylily_auth_cognito.runtime.verifier.verify_token_with_jwks",
        return_value={"sub": "user-123", "client_id": "client-123", "exp": time.time() + 60},
    ) as mocked_verify:
        verifier = CognitoTokenVerifier(
            region="us-west-2",
            user_pool_id="pool-123",
            app_client_id="client-123",
            cache=cache,
        )
        claims = verifier.verify_token("token-123")

    assert claims["sub"] == "user-123"
    mocked_verify.assert_called_once_with("token-123", "us-west-2", "pool-123", cache=cache)


def test_cognito_token_verifier_supports_unverified_decode_path() -> None:
    fake_jwt = mock.Mock()
    fake_jwt.get_unverified_header.return_value = {"kid": "kid-1"}
    fake_jwt.decode.return_value = {"sub": "user-123", "client_id": "client-123", "exp": time.time() + 60}

    with mock.patch("daylily_auth_cognito.runtime.verifier.jwt", fake_jwt):
        verifier = CognitoTokenVerifier(
            region="us-west-2",
            user_pool_id="pool-123",
            app_client_id="client-123",
            cache=mock.Mock(),
        )
        claims = verifier.verify_token("token-123", verify_signature=False)

    assert claims["sub"] == "user-123"
    fake_jwt.get_unverified_header.assert_called_once_with("token-123")
    fake_jwt.decode.assert_called_once()
