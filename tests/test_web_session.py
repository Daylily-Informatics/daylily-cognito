"""Tests for token-free Cognito browser session handling."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest
from fastapi import FastAPI, Request

from daylily_auth_cognito.browser import session as web_session
from daylily_auth_cognito.browser.session import (
    CONFIG_STATE_KEY,
    SESSION_EXPIRED_REASON,
    CognitoWebSessionConfig,
    SessionPrincipal,
    clear_session_principal,
    complete_cognito_callback,
    configure_session_middleware,
    load_session_principal,
    start_cognito_login,
    store_session_principal,
)


async def _receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


def _make_request(app: FastAPI | None = None, path: str = "/") -> Request:
    target_app = app or FastAPI()
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("app.example.test", 443),
        "app": target_app,
        "session": {},
        "state": {},
    }
    return Request(scope, _receive)


def _config(**overrides: Any) -> CognitoWebSessionConfig:
    defaults = {
        "domain": "auth.example.test",
        "client_id": "client-123",
        "redirect_uri": "https://app.example.test/auth/callback",
        "logout_uri": "https://app.example.test/logout",
        "session_secret_key": "secret-123",
        "session_cookie_name": "daycog_session",
        "public_base_url": "https://app.example.test",
        "server_instance_id": "server-123",
    }
    defaults.update(overrides)
    return CognitoWebSessionConfig(**defaults)


def test_configure_session_middleware_registers_shared_contract() -> None:
    app = FastAPI()
    config = _config()

    configure_session_middleware(app, config)

    assert app.state.__dict__[CONFIG_STATE_KEY] is config
    assert len(app.user_middleware) == 1


def test_start_cognito_login_sets_state_and_next_path() -> None:
    app = FastAPI()
    request = _make_request(app)
    config = _config()

    response = start_cognito_login(request, config, next_path="/reports?tab=1")

    assert request.session[config.state_session_key]
    assert request.session[config.next_path_session_key] == "/reports?tab=1"
    assert response.status_code == 302
    assert "state=" in response.headers["location"]
    assert "client_id=client-123" in response.headers["location"]


def test_store_session_principal_rejects_raw_tokens() -> None:
    request = _make_request()
    config = _config()

    with pytest.raises(ValueError, match="raw OAuth tokens"):
        store_session_principal(
            request,
            config,
            SessionPrincipal(
                user_sub="user-123",
                email="user@example.test",
                app_context={"nested": {"access_token": "secret"}},
            ),
        )


def test_complete_callback_awaits_async_exchange_and_stores_normalized_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    request = _make_request(app, path="/auth/callback")
    config = _config()
    request.session[config.state_session_key] = "state-123"
    request.session[config.next_path_session_key] = "/reports"

    exchange = mock.AsyncMock(
        return_value={
            "access_token": "access-123",
            "id_token": "id-123",
            "refresh_token": "refresh-123",
        }
    )
    monkeypatch.setattr(web_session, "exchange_authorization_code_async", exchange)

    async def resolve_principal(tokens: dict[str, str], request: Request) -> dict[str, Any]:
        assert tokens["access_token"] == "access-123"
        assert request.url.path == "/auth/callback"
        return {
            "user_sub": "user-123",
            "email": "user@example.test",
            "roles": ["admin"],
            "cognito_groups": ["scientists"],
            "app_context": {"workspace": "lab-a"},
        }

    response = asyncio.run(
        complete_cognito_callback(
            request,
            config,
            code="code-123",
            state="state-123",
            resolve_principal=resolve_principal,
        )
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/reports"
    assert exchange.await_count == 1
    assert request.session["email"] == "user@example.test"
    assert request.session["roles"] == ["admin"]
    assert request.session["app_context"] == {"workspace": "lab-a"}
    assert request.session["server_instance_id"] == "server-123"
    assert "access_token" not in request.session
    assert "id_token" not in request.session
    assert "refresh_token" not in request.session


def test_load_session_principal_invalidates_stale_server_instance() -> None:
    app = FastAPI()
    request = _make_request(app)
    config = _config(server_instance_id="server-new")
    app.state.__dict__[CONFIG_STATE_KEY] = config
    request.session.update(
        SessionPrincipal(
            user_sub="user-123",
            email="user@example.test",
            server_instance_id="server-old",
        ).to_session_dict()
    )

    principal = load_session_principal(request)

    assert principal is None
    assert request.state.cognito_auth_reason == SESSION_EXPIRED_REASON
    assert request.session == {}


def test_clear_session_principal_removes_principal_fields() -> None:
    request = _make_request()
    request.session.update(
        {
            "user_sub": "user-123",
            "email": "user@example.test",
            "roles": ["admin"],
            "access_token": "access-123",
            "refresh_token": "refresh-123",
        }
    )

    clear_session_principal(request)

    assert request.session == {}
