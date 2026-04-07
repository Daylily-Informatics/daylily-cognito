"""Tests for unverified JWT decoding and claim checks."""

from __future__ import annotations

import sys
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from daylily_auth_cognito.runtime.tokens import decode_jwt_unverified, verify_jwt_claims_unverified_signature


class _FakeJwt:
    @staticmethod
    def decode(token: str, *, key, options):
        return {"sub": "user-123", "client_id": "client-123", "exp": time.time() + 60}

    @staticmethod
    def get_unverified_header(token: str) -> dict[str, str]:
        return {"kid": "kid-1"}


class _ExpiredJwt(_FakeJwt):
    @staticmethod
    def decode(token: str, *, key, options):
        return {"client_id": "client-123", "exp": time.time() - 1}


class _WrongAudienceJwt(_FakeJwt):
    @staticmethod
    def decode(token: str, *, key, options):
        return {"client_id": "wrong-client", "exp": time.time() + 60}


def test_decode_jwt_unverified_returns_claims() -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(sys.modules, "jose", SimpleNamespace(jwt=_FakeJwt))
        claims = decode_jwt_unverified("token-123")

    assert claims["sub"] == "user-123"


def test_verify_jwt_claims_unverified_signature_enforces_expiration_and_audience() -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(
            sys.modules, "jose", SimpleNamespace(jwt=_FakeJwt, JWTError=ValueError, ExpiredSignatureError=ValueError)
        )
        claims = verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")
    assert claims["client_id"] == "client-123"

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(
            sys.modules, "jose", SimpleNamespace(jwt=_ExpiredJwt, JWTError=ValueError, ExpiredSignatureError=ValueError)
        )
        with pytest.raises(HTTPException, match="Token has expired"):
            verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setitem(
            sys.modules,
            "jose",
            SimpleNamespace(jwt=_WrongAudienceJwt, JWTError=ValueError, ExpiredSignatureError=ValueError),
        )
        with pytest.raises(HTTPException, match="Invalid token audience"):
            verify_jwt_claims_unverified_signature("token-123", expected_client_id="client-123")
