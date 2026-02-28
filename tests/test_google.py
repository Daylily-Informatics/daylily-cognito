"""Tests for Google OAuth integration (daylily_cognito.google)."""

import json
import socket
from typing import Any, Dict
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest

from daylily_cognito.google import (
    DEFAULT_SCOPES,
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_USERINFO_ENDPOINT,
    auto_create_cognito_user_from_google,
    build_google_authorization_url,
    exchange_google_code_for_tokens,
    fetch_google_userinfo,
    generate_state_token,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_USERINFO: Dict[str, Any] = {
    "sub": "1234567890",
    "email": "jsmith@example.com",
    "email_verified": True,
    "name": "John Smith",
    "given_name": "John",
    "family_name": "Smith",
    "picture": "https://lh3.googleusercontent.com/a/photo",
    "locale": "en",
    "hd": "example.com",
}


# ---------------------------------------------------------------------------
# generate_state_token
# ---------------------------------------------------------------------------


class TestGenerateStateToken:
    def test_returns_hex_string(self) -> None:
        token = generate_state_token()
        assert isinstance(token, str)
        int(token, 16)  # Should be valid hex

    def test_unique_each_call(self) -> None:
        assert generate_state_token() != generate_state_token()

    def test_length(self) -> None:
        # 32 bytes hex-encoded = 64 chars
        assert len(generate_state_token()) == 64


# ---------------------------------------------------------------------------
# build_google_authorization_url
# ---------------------------------------------------------------------------


class TestBuildGoogleAuthorizationUrl:
    def test_basic_url(self) -> None:
        url = build_google_authorization_url(
            client_id="test-client-id",
            redirect_uri="http://localhost:8000/auth/google/callback",
        )
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert "accounts.google.com" in parsed.netloc
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["test-client-id"]
        assert params["redirect_uri"] == ["http://localhost:8000/auth/google/callback"]
        assert params["response_type"] == ["code"]
        assert params["scope"] == [DEFAULT_SCOPES]
        assert params["access_type"] == ["offline"]

    def test_with_state(self) -> None:
        url = build_google_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            state="my-state-token",
        )
        params = parse_qs(urlparse(url).query)
        assert params["state"] == ["my-state-token"]

    def test_with_hd(self) -> None:
        url = build_google_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            hd="example.com",
        )
        params = parse_qs(urlparse(url).query)
        assert params["hd"] == ["example.com"]

    def test_with_prompt(self) -> None:
        url = build_google_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            prompt="consent",
        )
        params = parse_qs(urlparse(url).query)
        assert params["prompt"] == ["consent"]

    def test_custom_scope(self) -> None:
        url = build_google_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            scope="openid email",
        )
        params = parse_qs(urlparse(url).query)
        assert params["scope"] == ["openid email"]

    def test_with_login_hint_and_nonce(self) -> None:
        url = build_google_authorization_url(
            client_id="cid",
            redirect_uri="http://localhost/cb",
            login_hint="user@example.com",
            nonce="abc123",
        )
        params = parse_qs(urlparse(url).query)
        assert params["login_hint"] == ["user@example.com"]
        assert params["nonce"] == ["abc123"]


# ---------------------------------------------------------------------------
# exchange_google_code_for_tokens (mocked HTTP)
# ---------------------------------------------------------------------------


class TestExchangeGoogleCodeForTokens:
    def _mock_urlopen(self, response_body: dict, status: int = 200):
        """Create a mock context manager for urllib.request.urlopen."""
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
        mock_response.__exit__ = mock.MagicMock(return_value=False)
        return mock_response

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_successful_exchange(self, mock_urlopen: mock.MagicMock) -> None:
        token_response = {
            "access_token": "ya29.abc",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.xxx",
            "expires_in": 3599,
            "token_type": "Bearer",
            "refresh_token": "1//refresh",
        }
        mock_urlopen.return_value = self._mock_urlopen(token_response)

        result = exchange_google_code_for_tokens(
            client_id="cid",
            client_secret="csecret",
            code="auth-code-123",
            redirect_uri="http://localhost/cb",
        )

        assert result["access_token"] == "ya29.abc"
        assert result["refresh_token"] == "1//refresh"
        assert result["token_type"] == "Bearer"

        # Verify the request was made correctly
        call_args = mock_urlopen.call_args[0][0]
        assert call_args.method == "POST"
        assert GOOGLE_TOKEN_ENDPOINT in call_args.full_url

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_exchange_timeout(self, mock_urlopen: mock.MagicMock) -> None:
        mock_urlopen.side_effect = socket.timeout("timed out")

        with pytest.raises(RuntimeError, match="timed out"):
            exchange_google_code_for_tokens(
                client_id="cid",
                client_secret="csecret",
                code="auth-code",
                redirect_uri="http://localhost/cb",
            )

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_exchange_timeout_via_urlerror(self, mock_urlopen: mock.MagicMock) -> None:
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError(reason=socket.timeout("timed out"))

        with pytest.raises(RuntimeError, match="timed out"):
            exchange_google_code_for_tokens(
                client_id="cid",
                client_secret="csecret",
                code="auth-code",
                redirect_uri="http://localhost/cb",
            )

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_exchange_failure(self, mock_urlopen: mock.MagicMock) -> None:
        import urllib.error

        mock_error = urllib.error.HTTPError(
            url=GOOGLE_TOKEN_ENDPOINT,
            code=400,
            msg="Bad Request",
            hdrs=mock.MagicMock(),
            fp=mock.MagicMock(),
        )
        mock_error.fp.read.return_value = b'{"error": "invalid_grant"}'
        mock_error.read = mock.MagicMock(return_value=b'{"error": "invalid_grant"}')
        mock_urlopen.side_effect = mock_error

        with pytest.raises(RuntimeError, match="Google token exchange failed"):
            exchange_google_code_for_tokens(
                client_id="cid",
                client_secret="csecret",
                code="bad-code",
                redirect_uri="http://localhost/cb",
            )


# ---------------------------------------------------------------------------
# fetch_google_userinfo (mocked HTTP)
# ---------------------------------------------------------------------------


class TestFetchGoogleUserinfo:
    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_successful_fetch(self, mock_urlopen: mock.MagicMock) -> None:
        mock_response = mock.MagicMock()
        mock_response.read.return_value = json.dumps(SAMPLE_USERINFO).encode("utf-8")
        mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
        mock_response.__exit__ = mock.MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = fetch_google_userinfo("ya29.abc")

        assert result["sub"] == "1234567890"
        assert result["email"] == "jsmith@example.com"
        assert result["name"] == "John Smith"
        assert result["hd"] == "example.com"

        # Verify authorization header
        call_args = mock_urlopen.call_args[0][0]
        assert call_args.get_header("Authorization") == "Bearer ya29.abc"

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_fetch_timeout(self, mock_urlopen: mock.MagicMock) -> None:
        mock_urlopen.side_effect = socket.timeout("timed out")

        with pytest.raises(RuntimeError, match="timed out"):
            fetch_google_userinfo("ya29.abc")

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_fetch_timeout_via_urlerror(self, mock_urlopen: mock.MagicMock) -> None:
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError(reason=socket.timeout("timed out"))

        with pytest.raises(RuntimeError, match="timed out"):
            fetch_google_userinfo("ya29.abc")

    @mock.patch("daylily_cognito.google.urllib.request.urlopen")
    def test_fetch_failure(self, mock_urlopen: mock.MagicMock) -> None:
        import urllib.error

        mock_error = urllib.error.HTTPError(
            url=GOOGLE_USERINFO_ENDPOINT,
            code=401,
            msg="Unauthorized",
            hdrs=mock.MagicMock(),
            fp=mock.MagicMock(),
        )
        mock_error.read = mock.MagicMock(return_value=b"invalid token")
        mock_urlopen.side_effect = mock_error

        with pytest.raises(RuntimeError, match="Google userinfo request failed"):
            fetch_google_userinfo("bad-token")


# ---------------------------------------------------------------------------
# auto_create_cognito_user_from_google (mocked Cognito)
# ---------------------------------------------------------------------------


def _make_mock_auth(user_exists: bool = False, existing_user: Any = None) -> mock.MagicMock:
    """Build a mock CognitoAuth object with mocked boto3 cognito client."""
    auth = mock.MagicMock()
    auth.user_pool_id = "us-west-2_TestPool"

    if user_exists:
        auth.cognito.admin_get_user.return_value = existing_user or {
            "Username": "jsmith@example.com",
            "UserAttributes": [
                {"Name": "email", "Value": "jsmith@example.com"},
                {"Name": "custom:google_sub", "Value": "1234567890"},
            ],
            "UserStatus": "CONFIRMED",
        }
    else:
        # Simulate UserNotFoundException
        exc_class = type("UserNotFoundException", (Exception,), {})
        auth.cognito.exceptions.UserNotFoundException = exc_class
        auth.cognito.admin_get_user.side_effect = exc_class("User not found")
        auth.cognito.admin_create_user.return_value = {
            "User": {
                "Username": "jsmith@example.com",
                "Attributes": [
                    {"Name": "email", "Value": "jsmith@example.com"},
                ],
                "UserStatus": "FORCE_CHANGE_PASSWORD",
            }
        }

    return auth


class TestAutoCreateCognitoUserFromGoogle:
    def test_creates_new_user(self) -> None:
        auth = _make_mock_auth(user_exists=False)
        result = auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert result["created"] is True
        assert result["email"] == "jsmith@example.com"
        assert result["google_sub"] == "1234567890"

        # Verify admin_create_user was called
        auth.cognito.admin_create_user.assert_called_once()
        call_kwargs = auth.cognito.admin_create_user.call_args[1]
        assert call_kwargs["Username"] == "jsmith@example.com"
        assert call_kwargs["MessageAction"] == "SUPPRESS"

        # Verify attributes include Google profile data
        attrs = {a["Name"]: a["Value"] for a in call_kwargs["UserAttributes"]}
        assert attrs["email"] == "jsmith@example.com"
        assert attrs["custom:google_sub"] == "1234567890"
        assert attrs["custom:customer_id"] == "1234567890"  # defaults to sub
        assert attrs["name"] == "John Smith"
        assert attrs["given_name"] == "John"
        assert attrs["family_name"] == "Smith"
        assert attrs["picture"] == "https://lh3.googleusercontent.com/a/photo"
        assert attrs["locale"] == "en"
        assert attrs["custom:google_hd"] == "example.com"

        # Verify password was set
        auth.cognito.admin_set_user_password.assert_called_once()
        pw_kwargs = auth.cognito.admin_set_user_password.call_args[1]
        assert pw_kwargs["Permanent"] is True
        assert len(pw_kwargs["Password"]) > 20  # random password

    def test_returns_existing_user(self) -> None:
        auth = _make_mock_auth(user_exists=True)
        result = auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert result["created"] is False
        assert result["email"] == "jsmith@example.com"
        assert result["google_sub"] == "1234567890"

        # Should NOT have tried to create
        auth.cognito.admin_create_user.assert_not_called()

    def test_missing_email_raises(self) -> None:
        auth = _make_mock_auth(user_exists=False)
        bad_info = {"sub": "123"}
        with pytest.raises(ValueError, match="missing 'email'"):
            auto_create_cognito_user_from_google(auth, bad_info)

    def test_missing_sub_raises(self) -> None:
        auth = _make_mock_auth(user_exists=False)
        bad_info = {"email": "a@b.com"}
        with pytest.raises(ValueError, match="missing 'sub'"):
            auto_create_cognito_user_from_google(auth, bad_info)

    def test_custom_customer_id(self) -> None:
        auth = _make_mock_auth(user_exists=False)
        result = auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO, customer_id="CUST42")
        assert result["created"] is True

        call_kwargs = auth.cognito.admin_create_user.call_args[1]
        attrs = {a["Name"]: a["Value"] for a in call_kwargs["UserAttributes"]}
        assert attrs["custom:customer_id"] == "CUST42"

    def test_minimal_google_profile(self) -> None:
        """Only required fields — no optional attrs like name, picture, hd."""
        auth = _make_mock_auth(user_exists=False)
        minimal_info: Dict[str, Any] = {
            "sub": "9999",
            "email": "min@example.com",
            "email_verified": True,
        }
        result = auto_create_cognito_user_from_google(auth, minimal_info)

        assert result["created"] is True
        call_kwargs = auth.cognito.admin_create_user.call_args[1]
        attrs = {a["Name"]: a["Value"] for a in call_kwargs["UserAttributes"]}

        # Required attrs present
        assert attrs["email"] == "min@example.com"
        assert attrs["custom:google_sub"] == "9999"

        # Optional attrs absent
        assert "name" not in attrs
        assert "picture" not in attrs
        assert "custom:google_hd" not in attrs

    def test_cognito_create_failure_raises_runtime_error(self) -> None:
        auth = _make_mock_auth(user_exists=False)
        auth.cognito.admin_create_user.side_effect = Exception("Pool limit exceeded")

        with pytest.raises(RuntimeError, match="Failed to create Cognito user"):
            auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)


# ---------------------------------------------------------------------------
# Domain validation on Google SSO path
# ---------------------------------------------------------------------------


class TestGoogleSSODomainValidation:
    """Verify that auto_create_cognito_user_from_google enforces domain validation."""

    def test_blocked_domain_raises_403(self) -> None:
        """If _validate_email_domain raises HTTPException, it propagates."""
        from fastapi import HTTPException

        auth = _make_mock_auth(user_exists=False)
        # Wire up _validate_email_domain to reject the domain
        auth._validate_email_domain = mock.MagicMock(
            side_effect=HTTPException(status_code=403, detail="Domain blocked"),
        )

        with pytest.raises(HTTPException) as exc_info:
            auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert exc_info.value.status_code == 403
        auth._validate_email_domain.assert_called_once_with("jsmith@example.com")
        # Should NOT have attempted Cognito lookup or creation
        auth.cognito.admin_get_user.assert_not_called()
        auth.cognito.admin_create_user.assert_not_called()

    def test_allowed_domain_proceeds_normally(self) -> None:
        """If _validate_email_domain passes, user creation proceeds."""
        auth = _make_mock_auth(user_exists=False)
        auth._validate_email_domain = mock.MagicMock()  # no-op (no side effect)

        result = auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert result["created"] is True
        assert result["email"] == "jsmith@example.com"
        auth._validate_email_domain.assert_called_once_with("jsmith@example.com")
        auth.cognito.admin_create_user.assert_called_once()

    def test_no_settings_is_passthrough(self) -> None:
        """When auth has no _validate_email_domain, validation is skipped."""
        auth = _make_mock_auth(user_exists=False)
        # Remove _validate_email_domain so hasattr returns False
        del auth._validate_email_domain

        result = auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert result["created"] is True
        assert result["email"] == "jsmith@example.com"

    def test_blocked_domain_for_existing_user(self) -> None:
        """Even existing users are blocked if their domain fails validation."""
        from fastapi import HTTPException

        auth = _make_mock_auth(user_exists=True)
        auth._validate_email_domain = mock.MagicMock(
            side_effect=HTTPException(status_code=403, detail="Domain not allowed"),
        )

        with pytest.raises(HTTPException) as exc_info:
            auto_create_cognito_user_from_google(auth, SAMPLE_USERINFO)

        assert exc_info.value.status_code == 403
        # Should NOT have looked up the user since validation failed first
        auth.cognito.admin_get_user.assert_not_called()
