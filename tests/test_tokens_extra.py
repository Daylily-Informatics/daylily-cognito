"""Extra coverage for runtime/tokens.py."""

from __future__ import annotations

import sys
import time
from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi import HTTPException

from daylily_auth_cognito.runtime.tokens import (
    decode_jwt_unverified,
    verify_jwt_claims,
    verify_jwt_claims_unverified_signature,
)


class _FakeJwt:
    @staticmethod
    def get_unverified_header(token: str) -> dict[str, str]:
        return {"kid": "kid-1"}

    @staticmethod
    def decode(token: str, *, key, options):
        return {"sub": "user-123", "client_id": "client-123", "exp": time.time() + 60}


class _NoExpJwt(_FakeJwt):
    @staticmethod
    def decode(token: str, *, key, options):
        return {"sub": "user-123", "client_id": "client-123"}


class _ExpiredJwt(_FakeJwt):
    @staticmethod
    def decode(token: str, *, key, options):
        return {"client_id": "client-123", "exp": time.time() - 1}


class _WrongAudienceJwt(_FakeJwt):
    @staticmethod
    def decode(token: str, *, key, options):
        return {"client_id": "wrong-client", "exp": time.time() + 60}


def test_decode_jwt_unverified_requires_python_jose(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "jose", None)

    with pytest.raises(ImportError, match="python-jose is required for JWT decoding"):
        decode_jwt_unverified("token-123")


def test_decode_jwt_unverified_returns_claims() -> None:
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setitem(sys.modules, "jose", SimpleNamespace(jwt=_FakeJwt))
        claims = decode_jwt_unverified("token-123")
    finally:
        monkeypatch.undo()

    assert claims["sub"] == "user-123"


def test_verify_jwt_claims_unverified_signature_requires_python_jose(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "jose", None)

    with pytest.raises(ImportError, match="python-jose is required for JWT verification"):
        verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")


def test_verify_jwt_claims_unverified_signature_accepts_tokens_without_exp() -> None:
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setitem(
            sys.modules,
            "jose",
            SimpleNamespace(
                ExpiredSignatureError=ValueError,
                JWTError=ValueError,
                jwt=_NoExpJwt,
            ),
        )
        claims = verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")
    finally:
        monkeypatch.undo()

    assert claims["client_id"] == "client-123"


@pytest.mark.parametrize(
    "jwt_cls, match",
    [(_ExpiredJwt, "Token has expired"), (_WrongAudienceJwt, "Invalid token audience")],
)
def test_verify_jwt_claims_unverified_signature_rejects_bad_claims(jwt_cls: type[_FakeJwt], match: str) -> None:
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setitem(
            sys.modules,
            "jose",
            SimpleNamespace(
                ExpiredSignatureError=ValueError,
                JWTError=ValueError,
                jwt=jwt_cls,
            ),
        )
        with pytest.raises(HTTPException, match=match):
            verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")
    finally:
        monkeypatch.undo()


def test_verify_jwt_claims_unverified_signature_maps_jwt_errors() -> None:
    class FakeJWTError(Exception):
        pass

    class FakeJwtErroring(_FakeJwt):
        @staticmethod
        def decode(token: str, *, key, options):
            raise FakeJWTError("boom")

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setitem(
            sys.modules,
            "jose",
            SimpleNamespace(
                ExpiredSignatureError=ValueError,
                JWTError=FakeJWTError,
                jwt=FakeJwtErroring,
            ),
        )
        with pytest.raises(HTTPException, match="Invalid authentication token"):
            verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")
    finally:
        monkeypatch.undo()


def test_verify_jwt_claims_requires_python_jose(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "jose", None)

    with pytest.raises(ImportError, match="python-jose is required for JWT verification"):
        verify_jwt_claims(
            "token-123",
            expected_client_id="client-123",
            region="us-west-2",
            user_pool_id="pool-123",
        )


@pytest.mark.parametrize("exc_type", [KeyError, RuntimeError])
def test_verify_jwt_claims_maps_key_and_runtime_errors(
    monkeypatch: pytest.MonkeyPatch,
    exc_type: type[Exception],
) -> None:
    monkeypatch.setitem(sys.modules, "jose", SimpleNamespace(JWTError=ValueError))
    monkeypatch.setattr(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        mock.Mock(side_effect=exc_type("boom")),
    )

    with pytest.raises(HTTPException, match="Invalid authentication token"):
        verify_jwt_claims(
            "token-123",
            expected_client_id="client-123",
            region="us-west-2",
            user_pool_id="pool-123",
        )


def test_verify_jwt_claims_maps_jwt_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeJWTError(Exception):
        pass

    monkeypatch.setitem(sys.modules, "jose", SimpleNamespace(JWTError=FakeJWTError))
    monkeypatch.setattr(
        "daylily_auth_cognito.runtime.jwks.verify_token_with_jwks",
        mock.Mock(side_effect=FakeJWTError("boom")),
    )

    with pytest.raises(HTTPException, match="Invalid authentication token"):
        verify_jwt_claims(
            "token-123",
            expected_client_id="client-123",
            region="us-west-2",
            user_pool_id="pool-123",
        )
