"""Tests for OAuth URL builders."""

from urllib.parse import parse_qs, urlparse

from daylily_cognito.oauth import build_authorization_url, build_logout_url


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
