"""Tests for FastAPI integration (daylily_cognito.fastapi)."""

from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from daylily_cognito.fastapi import create_auth_dependency, security


class TestCreateAuthDependency:
    """Tests for create_auth_dependency()."""

    def _make_app(self, *, optional: bool = False) -> tuple:
        """Build a minimal FastAPI app with the auth dependency wired in."""
        mock_auth = mock.MagicMock()
        mock_auth.get_current_user.return_value = {
            "sub": "user-1",
            "email": "u@example.com",
        }

        dep = create_auth_dependency(mock_auth, optional=optional)
        app = FastAPI()

        @app.get("/protected")
        def protected(user=dep):
            return {"user": user}

        # Need to use Depends explicitly for the dependency to work
        from fastapi import Depends

        app2 = FastAPI()

        @app2.get("/protected")
        def protected2(user=Depends(dep)):
            return {"user": user}

        return app2, mock_auth

    # -- required mode (optional=False) --

    def test_required_no_token_returns_401(self) -> None:
        app, _ = self._make_app(optional=False)
        client = TestClient(app)
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_required_with_valid_token(self) -> None:
        app, mock_auth = self._make_app(optional=False)
        client = TestClient(app)
        resp = client.get("/protected", headers={"Authorization": "Bearer fake-jwt"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["user"]["sub"] == "user-1"
        mock_auth.get_current_user.assert_called_once()

    def test_required_auth_raises_propagates(self) -> None:
        app, mock_auth = self._make_app(optional=False)
        from fastapi import HTTPException

        mock_auth.get_current_user.side_effect = HTTPException(status_code=403, detail="Forbidden")
        client = TestClient(app)
        resp = client.get("/protected", headers={"Authorization": "Bearer bad-jwt"})
        assert resp.status_code == 403

    # -- optional mode (optional=True) --

    def test_optional_no_token_returns_none(self) -> None:
        app, _ = self._make_app(optional=True)
        client = TestClient(app)
        resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["user"] is None

    def test_optional_with_valid_token(self) -> None:
        app, mock_auth = self._make_app(optional=True)
        client = TestClient(app)
        resp = client.get("/protected", headers={"Authorization": "Bearer fake-jwt"})
        assert resp.status_code == 200
        assert resp.json()["user"]["email"] == "u@example.com"


class TestSecurityScheme:
    """Test that the shared security object is an HTTPBearer."""

    def test_security_is_http_bearer(self) -> None:
        from fastapi.security import HTTPBearer

        assert isinstance(security, HTTPBearer)

    def test_security_auto_error_is_false(self) -> None:
        # auto_error=False means missing token doesn't auto-raise
        assert security.auto_error is False
