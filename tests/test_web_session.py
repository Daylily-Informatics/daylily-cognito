"""Tests for hosted-UI browser-session helpers."""

from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from daylily_cognito.web_session import (
    CognitoWebAuthError,
    CognitoWebSessionConfig,
    SessionPrincipal,
    clear_session_principal,
    complete_cognito_callback,
    configure_session_middleware,
    load_session_principal,
    start_cognito_login,
    store_session_principal,
    validate_web_auth_contract,
)


def _make_config(
    *,
    public_base_url: str = "https://localhost:8912",
    session_cookie_name: str = "bloom_session",
    server_instance_id: Optional[str] = "server-1",
) -> CognitoWebSessionConfig:
    return CognitoWebSessionConfig(
        domain="example.auth.us-west-2.amazoncognito.com",
        client_id="client-123",
        client_secret="secret-123",
        redirect_uri=f"{public_base_url}/auth/callback",
        logout_uri=f"{public_base_url}/auth/logout",
        public_base_url=public_base_url,
        session_cookie_name=session_cookie_name,
        session_secret_key="test-secret",
        server_instance_id=server_instance_id,
        allow_insecure_http=public_base_url.startswith("http://"),
    )


async def _resolve_principal(token_payload: dict, request: Request) -> SessionPrincipal:
    del request
    del token_payload
    return SessionPrincipal(
        user_sub="user-123",
        email="user@example.com",
        name="Test User",
        roles=["ADMIN"],
        cognito_groups=["atlas-admins"],
        auth_mode="cognito",
        authenticated_at="2026-04-02T00:00:00+00:00",
        server_instance_id="server-1",
        app_context={"tenant_id": "tenant-1"},
    )


def _make_app(config: CognitoWebSessionConfig) -> FastAPI:
    app = FastAPI()
    configure_session_middleware(app, config)

    @app.get("/auth/login")
    async def login(request: Request, next: str = "/"):
        return start_cognito_login(request, config, next)

    @app.get("/auth/callback")
    async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
        try:
            return await complete_cognito_callback(request, config, code, state, _resolve_principal)
        except CognitoWebAuthError as exc:
            return JSONResponse(
                {"reason": exc.reason, "detail": exc.detail},
                status_code=exc.status_code,
            )

    @app.get("/me")
    async def me(request: Request):
        principal = load_session_principal(request)
        if principal is None:
            return JSONResponse(
                {"user": None, "reason": getattr(request.state, "cognito_auth_reason", None)},
                status_code=401,
            )
        return JSONResponse(principal.to_session_dict())

    @app.get("/seed-stale")
    async def seed_stale(request: Request):
        store_session_principal(
            request,
            config,
            SessionPrincipal(
                user_sub="user-1",
                email="user@example.com",
                name="User One",
                roles=["ADMIN"],
                cognito_groups=["atlas-admins"],
                auth_mode="cognito",
                authenticated_at="2026-04-02T00:00:00+00:00",
                server_instance_id="old-server",
                app_context={"tenant_id": "tenant-1"},
            ),
        )
        return JSONResponse({"seeded": True})

    @app.get("/clear")
    async def clear(request: Request):
        clear_session_principal(request)
        return JSONResponse({"cleared": True})

    @app.get("/_session")
    async def session_dump(request: Request):
        return JSONResponse(dict(request.session))

    return app


def _make_client(config: CognitoWebSessionConfig) -> TestClient:
    scheme = urlparse(config.public_base_url or config.redirect_uri).scheme
    return TestClient(_make_app(config), base_url=f"{scheme}://testserver")


class TestConfigureSessionMiddleware:
    def test_https_public_base_sets_secure_cookie(self) -> None:
        app = FastAPI()
        configure_session_middleware(app, _make_config(public_base_url="https://localhost:8912"))

        middleware = app.user_middleware[0]
        assert middleware.kwargs["https_only"] is True
        assert middleware.kwargs["same_site"] == "lax"
        assert middleware.kwargs["session_cookie"] == "bloom_session"

    def test_http_public_base_disables_secure_cookie(self) -> None:
        app = FastAPI()
        configure_session_middleware(app, _make_config(public_base_url="http://localhost:8912"))

        middleware = app.user_middleware[0]
        assert middleware.kwargs["https_only"] is False


class TestValidateWebAuthContract:
    def test_valid_contract_passes(self) -> None:
        validate_web_auth_contract(_make_config(), "https://localhost:8912")

    def test_default_http_requires_override(self) -> None:
        config = CognitoWebSessionConfig(
            domain="example.auth.us-west-2.amazoncognito.com",
            client_id="client-123",
            client_secret="secret-123",
            redirect_uri="http://localhost:8912/auth/callback",
            logout_uri="http://localhost:8912/auth/logout",
            public_base_url="http://localhost:8912",
            session_cookie_name="bloom_session",
            session_secret_key="test-secret",
            server_instance_id="server-1",
        )
        with pytest.raises(ValueError, match="allow_insecure_http=True"):
            validate_web_auth_contract(config, "http://localhost:8912")


class TestHostedUiSessionFlow:
    def test_login_sets_state_and_next_path(self) -> None:
        config = _make_config()
        client = _make_client(config)

        response = client.get("/auth/login?next=/dashboard?tab=search", follow_redirects=False)

        assert response.status_code == 302
        location = response.headers["location"]
        params = parse_qs(urlparse(location).query)
        assert params["redirect_uri"] == [config.redirect_uri]
        assert params["state"]

        session_payload = client.get("/_session").json()
        assert session_payload["_cognito_post_auth_redirect"] == "/dashboard?tab=search"
        assert session_payload["_cognito_oauth_state"] == params["state"][0]

    def test_callback_without_prior_login_fails_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "daylily_cognito.web_session.exchange_authorization_code",
            lambda **_: {"id_token": "id-token", "access_token": "access-token"},
        )
        client = _make_client(_make_config())

        response = client.get("/auth/callback?code=auth-code&state=missing")

        assert response.status_code == 400
        assert response.json()["reason"] == "invalid_state"

    def test_callback_with_wrong_state_fails_cleanly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "daylily_cognito.web_session.exchange_authorization_code",
            lambda **_: {"id_token": "id-token", "access_token": "access-token"},
        )
        client = _make_client(_make_config())
        client.get("/auth/login?next=/dashboard", follow_redirects=False)

        response = client.get("/auth/callback?code=auth-code&state=wrong-state")

        assert response.status_code == 400
        assert response.json()["reason"] == "invalid_state"

    def test_successful_callback_stores_principal_without_raw_tokens(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "daylily_cognito.web_session.exchange_authorization_code",
            lambda **_: {
                "id_token": "id-token",
                "access_token": "access-token",
                "refresh_token": "refresh-token",
            },
        )
        client = _make_client(_make_config())

        login_response = client.get("/auth/login?next=/dashboard", follow_redirects=False)
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

        callback_response = client.get(
            f"/auth/callback?code=auth-code&state={state}",
            follow_redirects=False,
        )

        assert callback_response.status_code == 302
        assert callback_response.headers["location"] == "/dashboard"

        session_payload = client.get("/_session").json()
        assert "_cognito_oauth_state" not in session_payload
        assert "_cognito_post_auth_redirect" not in session_payload
        assert "access_token" not in session_payload
        assert "id_token" not in session_payload
        assert "refresh_token" not in session_payload
        assert session_payload["email"] == "user@example.com"
        assert session_payload["app_context"]["tenant_id"] == "tenant-1"

        me_response = client.get("/me")
        assert me_response.status_code == 200
        assert me_response.json()["roles"] == ["ADMIN"]

    def test_server_restart_invalidates_session(self) -> None:
        config = _make_config(server_instance_id="current-server")
        client = _make_client(config)

        client.get("/seed-stale")
        me_response = client.get("/me")

        assert me_response.status_code == 401
        assert me_response.json()["reason"] == "session_expired"
        assert client.get("/_session").json() == {}
