"""Extra coverage for browser/session.py."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from daylily_auth_cognito.browser import session as web_session
from daylily_auth_cognito.browser.session import (
    CONFIG_STATE_KEY,
    DEFAULT_AUTHENTICATED_REDIRECT,
    SESSION_EXPIRED_REASON,
    CognitoWebAuthError,
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
        "domain": "https://auth.example.test/",
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


def test_error_and_config_aliases_cover_public_surface() -> None:
    error = CognitoWebAuthError("missing_code", "Missing authorization code", status_code=401, redirect_to_error=True)
    config = _config()

    assert error.message == "Missing authorization code"
    assert error.reason == "missing_code"
    assert error.status_code == 401
    assert error.redirect_to_error is True
    assert config.secret_key == "secret-123"
    assert config.cookie_name == "daycog_session"
    assert config.normalized_domain == "auth.example.test"
    assert config.effective_public_base_url == "https://app.example.test"
    assert config.https_only is True


def test_config_aliases_cover_http_public_base_with_override() -> None:
    config = _config(
        public_base_url=None,
        allow_insecure_http=True,
        redirect_uri="http://app.example.test/auth/callback",
        logout_uri="http://app.example.test/logout",
    )

    assert config.effective_public_base_url == "http://app.example.test"
    assert config.https_only is False


def test_session_principal_round_trip_and_alias() -> None:
    principal = SessionPrincipal(
        user_sub="user-123",
        email="user@example.test",
        roles=("admin", "scientist"),
        cognito_groups=("group-a",),
        auth_mode="",
        authenticated_at=None,
        server_instance_id=None,
        app_context={"workspace": "lab-a"},
    )

    payload = principal.to_session_dict()
    loaded = SessionPrincipal.from_session(payload)
    loaded_alias = SessionPrincipal.from_session_dict(payload)

    assert payload["roles"] == ["admin", "scientist"]
    assert loaded == loaded_alias
    assert loaded is not None
    assert loaded.user_sub == "user-123"
    assert loaded.app_context == {"workspace": "lab-a"}


@pytest.mark.parametrize(
    "session",
    [
        {"user_sub": "user-123", "email": "user@example.test", "app_context": ["not", "a", "mapping"]},
        {"user_sub": "user-123", "email": "user@example.test", "roles": 123},
    ],
)
def test_session_principal_rejects_invalid_session_shapes(session: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        SessionPrincipal.from_session(session)


def test_configure_session_middleware_rejects_duplicate_middleware() -> None:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="existing-secret")

    with pytest.raises(ValueError, match="already configured"):
        configure_session_middleware(app, _config())


def test_start_login_sanitizes_redirect_targets() -> None:
    app = FastAPI()
    request = _make_request(app)
    config = _config()

    response = start_cognito_login(request, config, next_path="https://evil.example.test/phish")

    assert request.session[config.next_path_session_key] == DEFAULT_AUTHENTICATED_REDIRECT
    assert response.status_code == 302


def test_complete_callback_handles_missing_code_and_invalid_state(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    request = _make_request(app, path="/auth/callback")
    config = _config()

    with pytest.raises(CognitoWebAuthError, match="Missing authorization code"):
        asyncio.run(
            complete_cognito_callback(
                request,
                config,
                code=None,
                state="state-123",
                resolve_principal=lambda tokens, request: {},
            )
        )

    request.session[config.state_session_key] = "state-123"
    with pytest.raises(CognitoWebAuthError, match="Invalid state parameter"):
        asyncio.run(
            complete_cognito_callback(
                request,
                config,
                code="code-123",
                state="wrong-state",
                resolve_principal=lambda tokens, request: {},
            )
        )

    exchange = mock.AsyncMock(side_effect=RuntimeError("exchange-failed"))
    monkeypatch.setattr(web_session, "exchange_authorization_code_async", exchange)

    request.session[config.state_session_key] = "state-123"
    with pytest.raises(CognitoWebAuthError, match="exchange-failed"):
        asyncio.run(
            complete_cognito_callback(
                request,
                config,
                code="code-123",
                state="state-123",
                resolve_principal=lambda tokens, request: {},
            )
        )


def test_complete_callback_redirects_to_error_and_clears_session(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    request = _make_request(app, path="/auth/callback")
    config = _config()
    request.session[config.state_session_key] = "state-123"
    request.session[config.next_path_session_key] = "/reports"

    monkeypatch.setattr(
        web_session,
        "exchange_authorization_code_async",
        mock.AsyncMock(return_value={"access_token": "access-123"}),
    )

    def resolve_principal(tokens: dict[str, str], request: Request) -> None:
        raise CognitoWebAuthError("upstream_error", "bad", redirect_to_error=True)

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
    assert response.headers["location"] == "/auth/error?reason=upstream_error"
    assert request.session == {}


def test_store_session_principal_fills_missing_fields() -> None:
    request = _make_request()
    config = _config()
    principal = SessionPrincipal(
        user_sub="user-123",
        email="user@example.test",
        auth_mode="",
        authenticated_at=None,
        server_instance_id=None,
    )

    stored = store_session_principal(request, config, principal)

    assert stored.user_sub == "user-123"
    assert request.session["authenticated_at"]
    assert request.session["server_instance_id"] == "server-123"
    assert request.session["auth_mode"] == "cognito"
    assert request.state.cognito_auth_reason is None


def test_load_session_principal_covers_cached_invalid_and_missing_states() -> None:
    app = FastAPI()
    request = _make_request(app)
    config = _config()
    app.state.__dict__[CONFIG_STATE_KEY] = config

    cached = SessionPrincipal(user_sub="user-123", email="user@example.test")
    request.state.cognito_session_principal = cached
    assert load_session_principal(request) is cached

    request = _make_request(app)
    app.state.__dict__[CONFIG_STATE_KEY] = config
    request.session.update({"user_sub": "user-123", "email": "user@example.test", "app_context": ["bad"]})
    assert load_session_principal(request) is None
    assert request.state.cognito_auth_reason == "invalid_session"

    request = _make_request(app)
    app.state.__dict__[CONFIG_STATE_KEY] = config
    assert load_session_principal(request) is None
    assert request.state.cognito_auth_reason is None


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


def test_clear_session_principal_handles_missing_session() -> None:
    request = SimpleNamespace(session=None, state=SimpleNamespace())

    clear_session_principal(request)


@pytest.mark.parametrize(
    "config_kwargs, match",
    [
        ({"session_secret_key": ""}, "session_secret_key is required"),
        ({"session_cookie_name": "session"}, "must not use the Starlette default"),
        ({"same_site": "strict"}, "same_site must be 'lax'"),
        ({"session_max_age": 0}, "session_max_age must be positive"),
        ({"server_instance_id": ""}, "server_instance_id is required"),
        ({"domain": "", "server_instance_id": "server-123"}, "domain is required"),
        (
            {"redirect_uri": "http://evil.example.test/callback", "server_instance_id": "server-123"},
            "redirect_uri must share scheme and host",
        ),
        (
            {"logout_uri": "http://evil.example.test/logout", "server_instance_id": "server-123"},
            "logout_uri must share scheme and host",
        ),
        (
            {"public_base_url": "http://app.example.test", "server_instance_id": "server-123"},
            "HTTP public_base_url requires allow_insecure_http=True",
        ),
    ],
)
def test_validate_web_auth_contract_rejects_invalid_cases(config_kwargs: dict[str, Any], match: str) -> None:
    config = _config(**config_kwargs)

    with pytest.raises(ValueError, match=match):
        web_session.validate_web_auth_contract(config, config.public_base_url)


def test_private_helpers_cover_normalization_and_error_branches() -> None:
    config = _config(
        public_base_url=None,
        allow_insecure_http=True,
        redirect_uri="http://app.example.test/auth/callback",
        logout_uri="http://app.example.test/logout",
    )

    assert web_session._sanitize_next_path(None) == "/"
    assert web_session._sanitize_next_path("/auth/login") == "/"
    assert web_session._sanitize_next_path("/reports?tab=1") == "/reports?tab=1"
    assert web_session._build_error_redirect_path("/auth/error", "missing_code") == "/auth/error?reason=missing_code"
    assert web_session._normalize_domain("https://auth.example.test/") == "auth.example.test"
    assert web_session._normalized_public_base_url(config, None) == "http://app.example.test"
    assert web_session._origin("https://app.example.test/path") == "https://app.example.test"
    assert web_session._normalize_string_list(("a", "", "b")) == ["a", "b"]

    with pytest.raises(ValueError, match="raw OAuth tokens"):
        web_session._reject_token_fields([{"nested": {"refresh_token": "secret"}}])

    with pytest.raises(ValueError, match="absolute http\\(s\\) URL"):
        web_session._require_absolute_url("not-a-url", "redirect_uri")

    with pytest.raises(TypeError, match="must return SessionPrincipal or mapping"):
        web_session._coerce_principal(object())

    with pytest.raises(ValueError, match="incomplete principal"):
        web_session._coerce_principal({"email": "user@example.test"})

    with pytest.raises(ValueError, match="string lists"):
        web_session._normalize_string_list(123)

    request = _make_request()
    with pytest.raises(RuntimeError, match="Shared Cognito web-session config is not registered"):
        web_session._get_request_config(request)
