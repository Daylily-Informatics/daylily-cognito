"""Tests for JWKS handling (daylily_cognito.jwks)."""

import pytest

from daylily_cognito.jwks import build_jwks_url, fetch_jwks, verify_token_with_jwks


class TestBuildJwksUrl:
    def test_returns_correct_url(self) -> None:
        url = build_jwks_url("us-west-2", "us-west-2_abc123")
        assert url == "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_abc123/.well-known/jwks.json"

    def test_different_region(self) -> None:
        url = build_jwks_url("eu-west-1", "eu-west-1_XYZ789")
        assert "eu-west-1" in url
        assert "eu-west-1_XYZ789" in url
        assert url.endswith("/.well-known/jwks.json")


class TestFetchJwks:
    def test_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            fetch_jwks("us-west-2", "us-west-2_abc123")


class TestVerifyTokenWithJwks:
    def test_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            verify_token_with_jwks("fake.jwt.token", "us-west-2", "us-west-2_abc123")
