"""Tests for JWKS handling."""

from __future__ import annotations

import io
import json
import socket
import sys
import urllib.error
from types import SimpleNamespace
from unittest import mock

import pytest

from daylily_auth_cognito.runtime import jwks
from daylily_auth_cognito.runtime.jwks import JWKSCache, build_jwks_url, fetch_jwks, verify_token_with_jwks


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_build_jwks_url() -> None:
    assert (
        build_jwks_url("us-west-2", "pool-123")
        == "https://cognito-idp.us-west-2.amazonaws.com/pool-123/.well-known/jwks.json"
    )


def test_fetch_jwks_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "daylily_auth_cognito.runtime.jwks.urllib.request.urlopen",
        lambda request, timeout=10: _Response({"keys": [{"kid": "kid-1"}]}),
    )

    payload = fetch_jwks("us-west-2", "pool-123")

    assert payload == {"keys": [{"kid": "kid-1"}]}


def test_fetch_jwks_wraps_http_and_timeout_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    http_error = urllib.error.HTTPError(
        url="https://example.test",
        code=500,
        msg="boom",
        hdrs=None,
        fp=io.BytesIO(b"server-error"),
    )
    monkeypatch.setattr(
        "daylily_auth_cognito.runtime.jwks.urllib.request.urlopen",
        mock.Mock(side_effect=http_error),
    )
    with pytest.raises(RuntimeError, match="HTTP 500"):
        fetch_jwks("us-west-2", "pool-123")

    monkeypatch.setattr(
        "daylily_auth_cognito.runtime.jwks.urllib.request.urlopen",
        mock.Mock(side_effect=socket.timeout("timed out")),
    )
    with pytest.raises(RuntimeError, match="timed out"):
        fetch_jwks("us-west-2", "pool-123")


def test_jwks_cache_refreshes_once_for_cached_key(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_fetch(region: str, user_pool_id: str) -> dict[str, object]:
        assert region == "us-west-2"
        assert user_pool_id == "pool-123"
        calls.append(1)
        return {"keys": [{"kid": "kid-1", "kty": "RSA"}]}

    monkeypatch.setattr(jwks, "fetch_jwks", fake_fetch)
    cache = JWKSCache("us-west-2", "pool-123")

    assert cache.get_key("kid-1") == {"kid": "kid-1", "kty": "RSA"}
    assert cache.get_key("kid-1") == {"kid": "kid-1", "kty": "RSA"}
    assert len(calls) == 1


def test_verify_token_with_jwks_uses_cache_and_expected_issuer() -> None:
    captured: dict[str, object] = {}

    class FakeJwt:
        @staticmethod
        def get_unverified_header(token: str) -> dict[str, str]:
            assert token == "token-123"
            return {"kid": "kid-1"}

        @staticmethod
        def decode(token: str, *, key, algorithms, options, issuer):
            captured.update(
                {
                    "token": token,
                    "key": key,
                    "algorithms": algorithms,
                    "options": options,
                    "issuer": issuer,
                }
            )
            return {"sub": "user-123", "client_id": "client-123"}

    cache = mock.Mock()
    cache.get_key.return_value = {"kid": "kid-1", "pem": "fake"}

    with mock.patch.dict(sys.modules, {"jose": SimpleNamespace(jwt=FakeJwt, JWTError=ValueError)}):
        claims = verify_token_with_jwks("token-123", "us-west-2", "pool-123", cache=cache)

    assert claims["sub"] == "user-123"
    cache.get_key.assert_called_once_with("kid-1")
    assert captured["issuer"] == "https://cognito-idp.us-west-2.amazonaws.com/pool-123"
    assert captured["algorithms"] == ["RS256"]


def test_verify_token_with_jwks_requires_kid_header() -> None:
    class FakeJwt:
        @staticmethod
        def get_unverified_header(token: str) -> dict[str, str]:
            return {}

    with mock.patch.dict(sys.modules, {"jose": SimpleNamespace(jwt=FakeJwt, JWTError=ValueError)}):
        with pytest.raises(ValueError, match="missing 'kid'"):
            verify_token_with_jwks("token-123", "us-west-2", "pool-123")
