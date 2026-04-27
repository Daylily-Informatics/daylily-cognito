"""Tests for Cognito Hosted UI URL builders and code exchange."""

from __future__ import annotations

import asyncio
import io
import json
import urllib.error
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

from daylily_auth_cognito.browser.oauth import (
    build_authorization_url,
    build_logout_url,
    exchange_authorization_code,
    exchange_authorization_code_async,
)


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_build_authorization_url_includes_expected_query_fields() -> None:
    url = build_authorization_url(
        domain="auth.example.test",
        client_id="client-123",
        redirect_uri="https://app.example.test/auth/callback",
        state="state-123",
        code_challenge="challenge-123",
        code_challenge_method="S256",
    )

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.example.test"
    assert parsed.path == "/oauth2/authorize"
    assert params["client_id"] == ["client-123"]
    assert params["redirect_uri"] == ["https://app.example.test/auth/callback"]
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid email profile"]
    assert params["state"] == ["state-123"]
    assert params["code_challenge"] == ["challenge-123"]
    assert params["code_challenge_method"] == ["S256"]


def test_build_authorization_url_supports_custom_scope() -> None:
    url = build_authorization_url(
        domain="auth.example.test",
        client_id="client-123",
        redirect_uri="https://app.example.test/auth/callback",
        scope="openid",
    )

    params = parse_qs(urlparse(url).query)
    assert params["scope"] == ["openid"]


def test_build_logout_url_uses_normalized_domain() -> None:
    url = build_logout_url(
        domain="auth.example.test",
        client_id="client-123",
        logout_uri="https://app.example.test/logout",
    )

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.example.test"
    assert parsed.path == "/logout"
    assert params["client_id"] == ["client-123"]
    assert params["logout_uri"] == ["https://app.example.test/logout"]


def test_schemeful_domains_are_rejected() -> None:
    with pytest.raises(ValueError, match="bare host"):
        build_authorization_url(
            domain="https://auth.example.test",
            client_id="client-123",
            redirect_uri="https://app.example.test/auth/callback",
        )

    with pytest.raises(ValueError, match="bare host"):
        build_logout_url(
            domain="https://auth.example.test",
            client_id="client-123",
            logout_uri="https://app.example.test/logout",
        )


def test_build_logout_url_is_stable_across_calls() -> None:
    url1 = build_logout_url(
        domain="auth.example.test",
        client_id="client-123",
        logout_uri="https://app.example.test/logout",
    )
    url2 = build_logout_url(
        domain="auth.example.test",
        client_id="client-123",
        logout_uri="https://app.example.test/logout",
    )

    assert url1 == url2


def test_exchange_authorization_code_posts_form_and_returns_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_urlopen = mock.Mock(return_value=_Response({"access_token": "access-123", "id_token": "id-123"}))
    monkeypatch.setattr("daylily_auth_cognito.browser.oauth.urllib.request.urlopen", fake_urlopen)

    tokens = exchange_authorization_code(
        domain="auth.example.test",
        client_id="client-123",
        code="code-123",
        redirect_uri="https://app.example.test/auth/callback",
        client_secret="secret-123",
        code_verifier="verifier-123",
    )

    assert tokens["access_token"] == "access-123"
    request = fake_urlopen.call_args.args[0]
    body = request.data.decode("utf-8")
    assert request.method == "POST"
    assert request.full_url == "https://auth.example.test/oauth2/token"
    assert "grant_type=authorization_code" in body
    assert "client_id=client-123" in body
    assert "client_secret=secret-123" in body
    assert "code_verifier=verifier-123" in body


def test_exchange_authorization_code_wraps_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    http_error = urllib.error.HTTPError(
        url="https://auth.example.test/oauth2/token",
        code=401,
        msg="unauthorized",
        hdrs=None,
        fp=io.BytesIO(b"bad-code"),
    )
    monkeypatch.setattr(
        "daylily_auth_cognito.browser.oauth.urllib.request.urlopen",
        mock.Mock(side_effect=http_error),
    )

    with pytest.raises(RuntimeError, match="HTTP 401"):
        exchange_authorization_code(
            domain="auth.example.test",
            client_id="client-123",
            code="code-123",
            redirect_uri="https://app.example.test/auth/callback",
        )


def test_exchange_authorization_code_async_uses_thread_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "daylily_auth_cognito.browser.oauth.exchange_authorization_code",
        mock.Mock(return_value={"access_token": "access-123"}),
    )

    tokens = asyncio.run(
        exchange_authorization_code_async(
            domain="auth.example.test",
            client_id="client-123",
            code="code-123",
            redirect_uri="https://app.example.test/auth/callback",
        )
    )

    assert tokens == {"access_token": "access-123"}
