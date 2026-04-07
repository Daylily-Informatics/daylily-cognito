"""Tests for Google OAuth browser helpers."""

from __future__ import annotations

import io
import json
import socket
import urllib.error
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

from daylily_auth_cognito.browser.google import (
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_USERINFO_ENDPOINT,
    build_google_authorization_url,
    exchange_google_code_for_tokens,
    fetch_google_userinfo,
    generate_state_token,
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


def test_generate_state_token_is_nonempty_and_randomish() -> None:
    first = generate_state_token()
    second = generate_state_token()

    assert first
    assert second
    assert first != second


def test_build_google_authorization_url_includes_optional_fields() -> None:
    url = build_google_authorization_url(
        client_id="google-client-123",
        redirect_uri="https://app.example.test/auth/google/callback",
        state="state-123",
        login_hint="user@example.test",
        hd="example.test",
        nonce="nonce-123",
        prompt="select_account",
    )

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    assert params["client_id"] == ["google-client-123"]
    assert params["redirect_uri"] == ["https://app.example.test/auth/google/callback"]
    assert params["state"] == ["state-123"]
    assert params["login_hint"] == ["user@example.test"]
    assert params["hd"] == ["example.test"]
    assert params["nonce"] == ["nonce-123"]
    assert params["prompt"] == ["select_account"]


def test_exchange_google_code_for_tokens_posts_form(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_urlopen = mock.Mock(return_value=_Response({"access_token": "google-access"}))
    monkeypatch.setattr("daylily_auth_cognito.browser.google.urllib.request.urlopen", fake_urlopen)

    tokens = exchange_google_code_for_tokens(
        client_id="google-client-123",
        client_secret="google-secret-123",
        code="code-123",
        redirect_uri="https://app.example.test/auth/google/callback",
    )

    assert tokens == {"access_token": "google-access"}
    request = fake_urlopen.call_args.args[0]
    assert request.full_url == GOOGLE_TOKEN_ENDPOINT
    body = request.data.decode("utf-8")
    assert "client_id=google-client-123" in body
    assert "client_secret=google-secret-123" in body
    assert "grant_type=authorization_code" in body


def test_exchange_google_code_for_tokens_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "daylily_auth_cognito.browser.google.urllib.request.urlopen",
        mock.Mock(side_effect=socket.timeout("timed out")),
    )

    with pytest.raises(RuntimeError, match="timed out"):
        exchange_google_code_for_tokens(
            client_id="google-client-123",
            client_secret="google-secret-123",
            code="code-123",
            redirect_uri="https://app.example.test/auth/google/callback",
        )


def test_fetch_google_userinfo_returns_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_urlopen = mock.Mock(return_value=_Response({"sub": "user-123", "email": "user@example.test"}))
    monkeypatch.setattr("daylily_auth_cognito.browser.google.urllib.request.urlopen", fake_urlopen)

    userinfo = fetch_google_userinfo("access-123")

    assert userinfo["sub"] == "user-123"
    request = fake_urlopen.call_args.args[0]
    assert request.full_url == GOOGLE_USERINFO_ENDPOINT
    assert request.headers["Authorization"] == "Bearer access-123"


def test_fetch_google_userinfo_wraps_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    http_error = urllib.error.HTTPError(
        url=GOOGLE_USERINFO_ENDPOINT,
        code=403,
        msg="forbidden",
        hdrs=None,
        fp=io.BytesIO(b"forbidden"),
    )
    monkeypatch.setattr(
        "daylily_auth_cognito.browser.google.urllib.request.urlopen",
        mock.Mock(side_effect=http_error),
    )

    with pytest.raises(RuntimeError, match="HTTP 403"):
        fetch_google_userinfo("access-123")
