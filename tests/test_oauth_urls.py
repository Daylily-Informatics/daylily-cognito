"""Tests for OAuth URL builders and token exchange."""

import json
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

from daylily_cognito.config import CognitoConfig
from daylily_cognito.oauth import (
    build_authorization_url,
    build_logout_url,
    exchange_authorization_code,
    refresh_with_refresh_token,
)


class TestBuildAuthorizationUrl:
    """Tests for build_authorization_url()."""

    def test_basic_url(self) -> None:
        """Builds basic authorization URL with required params."""
        url = build_authorization_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            redirect_uri="http://localhost:8000/callback",
        )

        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "myapp.auth.us-west-2.amazoncognito.com"
        assert parsed.path == "/oauth2/authorize"

        params = parse_qs(parsed.query)
        assert params["client_id"] == ["abc123"]
        assert params["redirect_uri"] == ["http://localhost:8000/callback"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == ["openid email profile"]

    def test_with_state(self) -> None:
        """Includes state parameter when provided."""
        url = build_authorization_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            redirect_uri="http://localhost:8000/callback",
            state="csrf-token-123",
        )

        params = parse_qs(urlparse(url).query)
        assert params["state"] == ["csrf-token-123"]

    def test_with_pkce(self) -> None:
        """Includes PKCE parameters when provided."""
        url = build_authorization_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            redirect_uri="http://localhost:8000/callback",
            code_challenge="challenge123",
            code_challenge_method="S256",
        )

        params = parse_qs(urlparse(url).query)
        assert params["code_challenge"] == ["challenge123"]
        assert params["code_challenge_method"] == ["S256"]

    def test_custom_scope(self) -> None:
        """Uses custom scope when provided."""
        url = build_authorization_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            redirect_uri="http://localhost:8000/callback",
            scope="openid",
        )

        params = parse_qs(urlparse(url).query)
        assert params["scope"] == ["openid"]


class TestBuildLogoutUrl:
    """Tests for build_logout_url()."""

    def test_basic_url(self) -> None:
        """Builds basic logout URL."""
        url = build_logout_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            logout_uri="http://localhost:8000/",
        )

        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "myapp.auth.us-west-2.amazoncognito.com"
        assert parsed.path == "/logout"

        params = parse_qs(parsed.query)
        assert params["client_id"] == ["abc123"]
        assert params["logout_uri"] == ["http://localhost:8000/"]

    def test_stable_query_params(self) -> None:
        """Query params are stable across calls."""
        url1 = build_logout_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            logout_uri="http://localhost:8000/",
        )
        url2 = build_logout_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            logout_uri="http://localhost:8000/",
        )
        assert url1 == url2


# ---------------------------------------------------------------------------
# exchange_authorization_code (mocked HTTP)
# ---------------------------------------------------------------------------


class TestExchangeAuthorizationCode:
    """Tests for exchange_authorization_code()."""

    @mock.patch("daylily_cognito.oauth.urllib.request.urlopen")
    def test_successful_exchange(self, mock_urlopen: mock.MagicMock) -> None:
        token_body = {
            "access_token": "at-123",
            "id_token": "id-456",
            "refresh_token": "rt-789",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps(token_body).encode("utf-8")
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = exchange_authorization_code(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            code="auth-code",
            redirect_uri="http://localhost:8000/callback",
        )

        assert result["access_token"] == "at-123"
        assert result["id_token"] == "id-456"
        assert result["refresh_token"] == "rt-789"

        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        assert "myapp.auth.us-west-2.amazoncognito.com" in req.full_url
        assert b"grant_type=authorization_code" in req.data

    @mock.patch("daylily_cognito.oauth.urllib.request.urlopen")
    def test_with_client_secret_and_code_verifier(self, mock_urlopen: mock.MagicMock) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"access_token": "at"}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        exchange_authorization_code(
            domain="d.auth.us-west-2.amazoncognito.com",
            client_id="cid",
            code="code",
            redirect_uri="http://localhost/cb",
            client_secret="secret",
            code_verifier="verifier",
        )

        req = mock_urlopen.call_args[0][0]
        body = req.data.decode("utf-8")
        assert "client_secret=secret" in body
        assert "code_verifier=verifier" in body

    @mock.patch("daylily_cognito.oauth.urllib.request.urlopen")
    def test_exchange_failure(self, mock_urlopen: mock.MagicMock) -> None:
        import urllib.error

        err = urllib.error.HTTPError(
            url="https://x/oauth2/token",
            code=400,
            msg="Bad Request",
            hdrs=mock.MagicMock(),
            fp=mock.MagicMock(),
        )
        err.read = mock.MagicMock(return_value=b'{"error":"invalid_grant"}')
        mock_urlopen.side_effect = err

        with pytest.raises(RuntimeError, match="Token exchange failed"):
            exchange_authorization_code(
                domain="d.auth.us-west-2.amazoncognito.com",
                client_id="cid",
                code="bad",
                redirect_uri="http://localhost/cb",
            )


# ---------------------------------------------------------------------------
# refresh_with_refresh_token (mocked boto3)
# ---------------------------------------------------------------------------


class TestRefreshWithRefreshToken:
    """Tests for refresh_with_refresh_token()."""

    def _make_config(self, **overrides) -> CognitoConfig:
        defaults = {
            "name": "test",
            "region": "us-west-2",
            "user_pool_id": "us-west-2_TestPool",
            "app_client_id": "client123",
        }
        defaults.update(overrides)
        return CognitoConfig(**defaults)

    @mock.patch("boto3.Session")
    def test_successful_refresh(self, mock_session_cls: mock.MagicMock) -> None:
        mock_cognito = mock.MagicMock()
        mock_cognito.admin_initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "new-at",
                "IdToken": "new-id",
                "ExpiresIn": 3600,
                "TokenType": "Bearer",
            }
        }
        mock_session_cls.return_value.client.return_value = mock_cognito

        config = self._make_config()
        result = refresh_with_refresh_token(config, "old-refresh-token")

        assert result["access_token"] == "new-at"
        assert result["id_token"] == "new-id"
        assert result["expires_in"] == 3600
        assert result["token_type"] == "Bearer"

        mock_cognito.admin_initiate_auth.assert_called_once_with(
            UserPoolId="us-west-2_TestPool",
            ClientId="client123",
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": "old-refresh-token"},
        )

    @mock.patch("boto3.Session")
    def test_uses_profile_from_config(self, mock_session_cls: mock.MagicMock) -> None:
        mock_cognito = mock.MagicMock()
        mock_cognito.admin_initiate_auth.return_value = {"AuthenticationResult": {}}
        mock_session_cls.return_value.client.return_value = mock_cognito

        config = self._make_config(aws_profile="my-profile")
        refresh_with_refresh_token(config, "rt")

        mock_session_cls.assert_called_once_with(region_name="us-west-2", profile_name="my-profile")

    @mock.patch("boto3.Session")
    def test_profile_override(self, mock_session_cls: mock.MagicMock) -> None:
        mock_cognito = mock.MagicMock()
        mock_cognito.admin_initiate_auth.return_value = {"AuthenticationResult": {}}
        mock_session_cls.return_value.client.return_value = mock_cognito

        config = self._make_config(aws_profile="config-profile")
        refresh_with_refresh_token(config, "rt", profile="override-profile")

        mock_session_cls.assert_called_once_with(region_name="us-west-2", profile_name="override-profile")
