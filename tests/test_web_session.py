"""Tests for hosted-UI browser-session helpers."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Optional
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import daylily_cognito.web_session as web_session
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


def _make_app(config: CognitoWebSessionConfig, resolver=_resolve_principal) -> FastAPI:
    app = FastAPI()
    configure_session_middleware(app, config)

    @app.get("/auth/login")
    async def login(request: Request, next: str = "/"):
        return start_cognito_login(request, config, next)

    @app.get("/auth/callback")
    async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
        try:
            return await complete_cognito_callback(request, config, code, state, resolver)
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


def _make_client(config: CognitoWebSessionConfig, resolver=_resolve_principal) -> TestClient:
    scheme = urlparse(config.public_base_url or config.redirect_uri).scheme
    return TestClient(_make_app(config, resolver), base_url=f"{scheme}://testserver")


class TestWebSessionModels:
    def test_web_auth_error_message_alias(self) -> None:
        error = CognitoWebAuthError("invalid_state", "Missing authorization code")
        assert error.message == "Missing authorization code"

    def test_config_alias_properties(self) -> None:
        config = _make_config()
        assert config.normalized_domain == "example.auth.us-west-2.amazoncognito.com"
        assert config.effective_public_base_url == "https://localhost:8912"
        assert config.https_only is True
        assert config.secret_key == "test-secret"
        assert config.cookie_name == "bloom_session"

    @pytest.mark.parametrize(
        ("user_sub", "email", "match"),
        [
            ("", "user@example.com", "user_sub"),
            ("user-123", "", "email"),
        ],
    )
    def test_session_principal_requires_identity_fields(
        self,
        user_sub: str,
        email: str,
        match: str,
    ) -> None:
        with pytest.raises(ValueError, match=match):
            SessionPrincipal(user_sub=user_sub, email=email).to_session_dict()

    def test_session_principal_rejects_nested_token_fields(self) -> None:
        principal = SessionPrincipal(
            user_sub="user-123",
            email="user@example.com",
            app_context={"tenant": {"providers": [{"refresh_token": "raw-token"}]}},
        )
        with pytest.raises(ValueError, match=r"app_context\.tenant\.providers\[0\]\.refresh_token"):
            principal.to_session_dict()

    @pytest.mark.parametrize("payload", [{}, {"user_sub": "user-123"}, {"email": "user@example.com"}])
    def test_session_principal_from_session_requires_both_identity_fields(self, payload: dict[str, object]) -> None:
        assert SessionPrincipal.from_session(payload) is None

    def test_session_principal_from_session_normalizes_roles_groups_and_alias(self) -> None:
        principal = SessionPrincipal.from_session_dict(
            {
                "user_sub": "user-123",
                "email": "user@example.com",
                "roles": " admin ",
                "app_context": {"tenant_id": "tenant-1"},
            }
        )
        assert principal is not None
        assert principal.roles == ["admin"]
        assert principal.cognito_groups == []
        assert principal.app_context == {"tenant_id": "tenant-1"}

    def test_session_principal_from_session_rejects_invalid_shapes(self) -> None:
        with pytest.raises(ValueError, match="mapping"):
            SessionPrincipal.from_session(
                {
                    "user_sub": "user-123",
                    "email": "user@example.com",
                    "app_context": "tenant-1",
                }
            )
        with pytest.raises(ValueError, match="string lists"):
            SessionPrincipal.from_session(
                {
                    "user_sub": "user-123",
                    "email": "user@example.com",
                    "roles": 123,
                }
            )


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

    def test_duplicate_session_middleware_is_rejected(self) -> None:
        app = FastAPI()
        config = _make_config()
        configure_session_middleware(app, config)

        with pytest.raises(ValueError, match="already configured"):
            configure_session_middleware(app, config)


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

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({"session_secret_key": ""}, "session_secret_key is required"),
            ({"session_cookie_name": ""}, "session_cookie_name is required"),
            ({"session_cookie_name": "session"}, "must not use the Starlette default"),
            ({"same_site": "strict"}, "same_site must be 'lax'"),
            ({"session_max_age": 0}, "session_max_age must be positive"),
            ({"server_instance_id": None}, "server_instance_id is required"),
            ({"redirect_uri": "https://other.example.com/auth/callback"}, "redirect_uri must share"),
            ({"logout_uri": "https://other.example.com/auth/logout"}, "logout_uri must share"),
        ],
    )
    def test_invalid_contract_values_raise(self, overrides: dict[str, object], match: str) -> None:
        with pytest.raises(ValueError, match=match):
            validate_web_auth_contract(replace(_make_config(), **overrides), "https://localhost:8912")


class TestWebSessionHelpers:
    @pytest.mark.parametrize(
        ("next_path", "expected"),
        [
            (None, "/"),
            ("https://evil.example.com/dashboard", "/"),
            ("dashboard", "/"),
            ("//evil.example.com/dashboard", "/"),
            ("/auth/login", "/"),
            ("/dashboard?tab=search#pane", "/dashboard?tab=search#pane"),
        ],
    )
    def test_sanitize_next_path(self, next_path: str | None, expected: str) -> None:
        assert web_session._sanitize_next_path(next_path) == expected

    def test_build_error_redirect_path_preserves_existing_query(self) -> None:
        redirect = web_session._build_error_redirect_path("/auth/error?next=%2Fdashboard", "access_denied")
        parsed = urlparse(redirect)
        params = parse_qs(parsed.query)
        assert parsed.path == "/auth/error"
        assert params == {"next": ["/dashboard"], "reason": ["access_denied"]}

    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("https://example.auth.us-west-2.amazoncognito.com/", "example.auth.us-west-2.amazoncognito.com"),
            ("http://example.auth.us-west-2.amazoncognito.com/", "example.auth.us-west-2.amazoncognito.com"),
        ],
    )
    def test_normalize_domain_strips_scheme_and_slash(self, domain: str, expected: str) -> None:
        assert web_session._normalize_domain(domain) == expected

    def test_normalize_domain_requires_value(self) -> None:
        with pytest.raises(ValueError, match="domain is required"):
            web_session._normalize_domain("")

    def test_origin_and_absolute_url_helpers(self) -> None:
        assert web_session._origin("https://example.com/path") == "https://example.com"
        with pytest.raises(ValueError, match="redirect_uri must be an absolute http\\(s\\) URL"):
            web_session._require_absolute_url("/callback", "redirect_uri")

    def test_clear_session_principal_ignores_objects_without_session(self) -> None:
        clear_session_principal(SimpleNamespace(state=SimpleNamespace()))

    def test_get_request_config_requires_registered_config(self) -> None:
        app = FastAPI()

        @app.get("/config")
        async def config_route(request: Request):
            try:
                web_session._get_request_config(request)
            except RuntimeError as exc:
                return JSONResponse({"detail": str(exc)}, status_code=500)
            return JSONResponse({"detail": "unexpected"})

        client = TestClient(app)
        response = client.get("/config")
        assert response.status_code == 500
        assert "not registered" in response.json()["detail"]

    def test_coerce_principal_rejects_incomplete_or_invalid_values(self) -> None:
        with pytest.raises(ValueError, match="incomplete principal"):
            web_session._coerce_principal({"user_sub": "user-123"})
        with pytest.raises(TypeError, match="must return SessionPrincipal or mapping"):
            web_session._coerce_principal("user-123")


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

    def test_callback_without_code_fails_cleanly(self) -> None:
        client = _make_client(_make_config())

        response = client.get("/auth/callback")

        assert response.status_code == 400
        assert response.json()["reason"] == "missing_code"

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

    def test_token_exchange_failures_return_auth_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise_exchange_error(**_: object) -> dict[str, str]:
            raise RuntimeError("exchange failed")

        monkeypatch.setattr("daylily_cognito.web_session.exchange_authorization_code", _raise_exchange_error)
        client = _make_client(_make_config())

        login_response = client.get("/auth/login?next=/dashboard", follow_redirects=False)
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]
        response = client.get(f"/auth/callback?code=auth-code&state={state}")

        assert response.status_code == 401
        assert response.json()["reason"] == "token_exchange_failed"

    def test_callback_can_redirect_to_error_route(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "daylily_cognito.web_session.exchange_authorization_code",
            lambda **_: {"id_token": "id-token", "access_token": "access-token"},
        )

        async def _redirecting_resolver(token_payload: dict, request: Request) -> SessionPrincipal:
            del token_payload
            del request
            raise CognitoWebAuthError(
                "access_denied",
                "Denied by resolver",
                redirect_to_error=True,
            )

        client = _make_client(_make_config(), resolver=_redirecting_resolver)
        login_response = client.get("/auth/login?next=/dashboard", follow_redirects=False)
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

        response = client.get(
            f"/auth/callback?code=auth-code&state={state}",
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["location"] == "/auth/error?reason=access_denied"
        assert client.get("/_session").json() == {}

    def test_callback_re_raises_auth_errors_without_redirect_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "daylily_cognito.web_session.exchange_authorization_code",
            lambda **_: {"id_token": "id-token", "access_token": "access-token"},
        )

        async def _failing_resolver(token_payload: dict, request: Request) -> SessionPrincipal:
            del token_payload
            del request
            raise CognitoWebAuthError("access_denied", "Denied by resolver", status_code=403)

        client = _make_client(_make_config(), resolver=_failing_resolver)
        login_response = client.get("/auth/login?next=/dashboard", follow_redirects=False)
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

        response = client.get(f"/auth/callback?code=auth-code&state={state}")

        assert response.status_code == 403
        assert response.json() == {"reason": "access_denied", "detail": "Denied by resolver"}

    def test_server_restart_invalidates_session(self) -> None:
        config = _make_config(server_instance_id="current-server")
        client = _make_client(config)

        client.get("/seed-stale")
        me_response = client.get("/me")

        assert me_response.status_code == 401
        assert me_response.json()["reason"] == "session_expired"
        assert client.get("/_session").json() == {}

    def test_load_session_principal_handles_empty_cached_and_invalid_sessions(self) -> None:
        config = _make_config()
        app = _make_app(config)

        @app.get("/cached")
        async def cached(request: Request):
            request.state.cognito_session_principal = SessionPrincipal(
                user_sub="cached-user",
                email="cached@example.com",
            )
            principal = load_session_principal(request)
            assert principal is not None
            return JSONResponse(principal.to_session_dict())

        @app.get("/seed-invalid")
        async def seed_invalid(request: Request):
            request.session.update(
                {
                    "user_sub": "user-123",
                    "email": "user@example.com",
                    "app_context": "invalid",
                }
            )
            return JSONResponse({"seeded": True})

        client = TestClient(app, base_url="https://testserver")

        unauthenticated = client.get("/me")
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["reason"] is None

        cached = client.get("/cached")
        assert cached.status_code == 200
        assert cached.json()["user_sub"] == "cached-user"

        client.get("/seed-invalid")
        invalid = client.get("/me")
        assert invalid.status_code == 401
        assert invalid.json()["reason"] == "invalid_session"
        assert client.get("/_session").json() == {}

    def test_store_session_principal_populates_defaults(self) -> None:
        config = _make_config()
        app = FastAPI()
        configure_session_middleware(app, config)

        @app.get("/store")
        async def store(request: Request):
            principal = store_session_principal(
                request,
                config,
                {
                    "user_sub": "user-123",
                    "email": "user@example.com",
                    "auth_mode": "",
                    "app_context": {},
                },
            )
            return JSONResponse(principal.to_session_dict())

        @app.get("/session")
        async def session_dump(request: Request):
            return JSONResponse(dict(request.session))

        client = TestClient(app, base_url="https://testserver")
        response = client.get("/store")
        assert response.status_code == 200

        session_payload = client.get("/session").json()
        assert session_payload["authenticated_at"]
        assert session_payload["server_instance_id"] == "server-1"
        assert session_payload["auth_mode"] == "cognito"

    def test_store_session_principal_falls_back_to_config_auth_mode(self) -> None:
        config = _make_config()
        app = FastAPI()
        configure_session_middleware(app, config)

        @app.get("/store")
        async def store(request: Request):
            store_session_principal(
                request,
                config,
                SessionPrincipal(
                    user_sub="user-123",
                    email="user@example.com",
                    auth_mode="",
                ),
            )
            return JSONResponse(dict(request.session))

        client = TestClient(app, base_url="https://testserver")
        response = client.get("/store")
        assert response.status_code == 200
        assert response.json()["auth_mode"] == "cognito"
