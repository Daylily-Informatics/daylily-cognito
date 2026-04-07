"""Extra coverage for runtime/verifier.py."""

from __future__ import annotations

import time
from unittest import mock

import pytest
from fastapi import HTTPException

from daylily_auth_cognito.runtime import verifier as verifier_mod
from daylily_auth_cognito.runtime.verifier import CognitoTokenVerifier


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"region": "", "user_pool_id": "pool-123", "app_client_id": "client-123"}, "region is required"),
        ({"region": "us-west-2", "user_pool_id": "", "app_client_id": "client-123"}, "user_pool_id is required"),
        ({"region": "us-west-2", "user_pool_id": "pool-123", "app_client_id": ""}, "app_client_id is required"),
    ],
)
def test_cognito_token_verifier_requires_constructor_fields(kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        CognitoTokenVerifier(**kwargs)


def test_cognito_token_verifier_builds_default_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = mock.Mock()
    cache_cls = mock.Mock(return_value=cache)
    monkeypatch.setattr(verifier_mod, "JWKSCache", cache_cls)

    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
    )

    assert verifier.cache is cache
    cache_cls.assert_called_once_with("us-west-2", "pool-123")


def test_verify_token_requires_python_jose(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        cache=mock.Mock(),
    )
    monkeypatch.setattr(verifier_mod, "jwt", None)

    with pytest.raises(ImportError, match="python-jose is required for JWT verification"):
        verifier.verify_token("token-123")


def test_verify_token_supports_unverified_decode_path(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_jwt = mock.Mock()
    fake_jwt.get_unverified_header.return_value = {"kid": "kid-1"}
    fake_jwt.decode.return_value = {
        "sub": "user-123",
        "client_id": "client-123",
        "exp": time.time() + 60,
    }
    monkeypatch.setattr(verifier_mod, "jwt", fake_jwt)
    monkeypatch.setattr(verifier_mod, "verify_token_with_jwks", mock.Mock())

    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        cache=mock.Mock(),
    )
    claims = verifier.verify_token("token-123", verify_signature=False)

    assert claims["sub"] == "user-123"
    fake_jwt.get_unverified_header.assert_called_once_with("token-123")
    fake_jwt.decode.assert_called_once_with(
        "token-123",
        key="",
        options={"verify_signature": False, "verify_exp": False},
    )


@pytest.mark.parametrize(
    "claims, message",
    [
        ({"client_id": "client-123", "exp": time.time() - 1}, "Token has expired"),
        ({"client_id": "wrong-client", "exp": time.time() + 60}, "Invalid token audience"),
    ],
)
def test_verify_token_rejects_expired_and_wrong_audience(
    monkeypatch: pytest.MonkeyPatch,
    claims: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(verifier_mod, "verify_token_with_jwks", mock.Mock(return_value=claims))
    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        cache=mock.Mock(),
    )

    with pytest.raises(HTTPException, match=message):
        verifier.verify_token("token-123")


@pytest.mark.parametrize("exc_type", [KeyError, RuntimeError])
def test_verify_token_maps_key_and_runtime_errors(
    monkeypatch: pytest.MonkeyPatch,
    exc_type: type[Exception],
) -> None:
    monkeypatch.setattr(
        verifier_mod,
        "verify_token_with_jwks",
        mock.Mock(side_effect=exc_type("boom")),
    )
    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        cache=mock.Mock(),
    )

    with pytest.raises(HTTPException, match="Invalid authentication token"):
        verifier.verify_token("token-123")


def test_verify_token_maps_jwt_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeJWTError(Exception):
        pass

    monkeypatch.setattr(verifier_mod, "JWTError", FakeJWTError)
    monkeypatch.setattr(
        verifier_mod,
        "verify_token_with_jwks",
        mock.Mock(side_effect=FakeJWTError("boom")),
    )
    verifier = CognitoTokenVerifier(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        cache=mock.Mock(),
    )

    with pytest.raises(HTTPException, match="Invalid authentication token"):
        verifier.verify_token("token-123")
