"""Tests for JWKS handling (daylily_cognito.jwks)."""

import json
import time
from unittest import mock

import pytest

jose = pytest.importorskip("jose", reason="python-jose not installed")

from jose import jwt as jose_jwt
from jose.backends import RSAKey

from daylily_cognito.jwks import JWKSCache, build_jwks_url, fetch_jwks, verify_token_with_jwks

# ---------------------------------------------------------------------------
# RSA key fixtures
# ---------------------------------------------------------------------------


def _generate_rsa_jwk(kid: str = "test-kid-1") -> dict:
    """Generate an RSA key pair and return the JWK dict."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Get the public key in JWK format via python-jose
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rsa_key = RSAKey(pub_pem, algorithm="RS256")
    jwk = rsa_key.to_dict()
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    # Keep private key for signing test tokens
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {"jwk_public": jwk, "private_pem": priv_pem, "kid": kid}


@pytest.fixture
def rsa_key_pair():
    """Fixture providing an RSA key pair for testing."""
    return _generate_rsa_jwk("test-kid-1")


@pytest.fixture
def jwks_response(rsa_key_pair):
    """Fixture providing a JWKS response dict."""
    return {"keys": [rsa_key_pair["jwk_public"]]}


def _create_signed_token(private_pem: bytes, kid: str, claims: dict) -> str:
    """Create an RS256-signed JWT token."""
    return jose_jwt.encode(
        claims,
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# build_jwks_url
# ---------------------------------------------------------------------------


class TestBuildJwksUrl:
    def test_returns_correct_url(self) -> None:
        url = build_jwks_url("us-west-2", "us-west-2_abc123")
        assert url == "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_abc123/.well-known/jwks.json"

    def test_different_region(self) -> None:
        url = build_jwks_url("eu-west-1", "eu-west-1_XYZ789")
        assert "eu-west-1" in url
        assert "eu-west-1_XYZ789" in url
        assert url.endswith("/.well-known/jwks.json")


# ---------------------------------------------------------------------------
# fetch_jwks
# ---------------------------------------------------------------------------


class TestFetchJwks:
    def test_fetches_and_parses_json(self, jwks_response) -> None:
        body = json.dumps(jwks_response).encode("utf-8")
        mock_response = mock.MagicMock()
        mock_response.read.return_value = body
        mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
        mock_response.__exit__ = mock.MagicMock(return_value=False)

        with mock.patch("daylily_cognito.jwks.urllib.request.urlopen", return_value=mock_response):
            result = fetch_jwks("us-west-2", "us-west-2_abc123")

        assert "keys" in result
        assert len(result["keys"]) == 1
        assert result["keys"][0]["kid"] == "test-kid-1"

    def test_http_error_raises_runtime_error(self) -> None:
        import urllib.error

        http_err = urllib.error.HTTPError(url="https://example.com", code=404, msg="Not Found", hdrs={}, fp=None)
        with mock.patch("daylily_cognito.jwks.urllib.request.urlopen", side_effect=http_err):
            with pytest.raises(RuntimeError, match="JWKS fetch failed"):
                fetch_jwks("us-west-2", "us-west-2_abc123")

    def test_url_error_raises_runtime_error(self) -> None:
        import urllib.error

        url_err = urllib.error.URLError(reason="Connection refused")
        with mock.patch("daylily_cognito.jwks.urllib.request.urlopen", side_effect=url_err):
            with pytest.raises(RuntimeError, match="JWKS fetch failed"):
                fetch_jwks("us-west-2", "us-west-2_abc123")

    def test_timeout_raises_runtime_error(self) -> None:
        import socket

        with mock.patch("daylily_cognito.jwks.urllib.request.urlopen", side_effect=socket.timeout("timed out")):
            with pytest.raises(RuntimeError, match="JWKS fetch timed out"):
                fetch_jwks("us-west-2", "us-west-2_abc123")


# ---------------------------------------------------------------------------
# JWKSCache
# ---------------------------------------------------------------------------


class TestJWKSCache:
    def test_get_key_fetches_and_caches(self, jwks_response) -> None:
        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response) as mock_fetch:
            cache = JWKSCache("us-west-2", "us-west-2_abc123")
            key = cache.get_key("test-kid-1")
            assert key["kid"] == "test-kid-1"

            # Second call should use cache, not refetch
            key2 = cache.get_key("test-kid-1")
            assert key2["kid"] == "test-kid-1"
            assert mock_fetch.call_count == 1

    def test_ttl_expiry_triggers_refresh(self, jwks_response) -> None:
        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response) as mock_fetch:
            cache = JWKSCache("us-west-2", "us-west-2_abc123", ttl_seconds=1)
            cache.get_key("test-kid-1")
            assert mock_fetch.call_count == 1

            # Simulate expiry
            cache._fetched_at = time.time() - 2
            cache.get_key("test-kid-1")
            assert mock_fetch.call_count == 2

    def test_unknown_kid_triggers_refresh_then_raises(self, jwks_response) -> None:
        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response) as mock_fetch:
            cache = JWKSCache("us-west-2", "us-west-2_abc123")
            with pytest.raises(KeyError, match="unknown-kid"):
                cache.get_key("unknown-kid")
            # Should have tried a refresh
            assert mock_fetch.call_count == 1

    def test_key_rotation_refresh(self) -> None:
        """If a new kid appears, cache misses and refetches."""
        old_jwks = {"keys": [{"kid": "old-kid", "kty": "RSA"}]}
        new_key_data = _generate_rsa_jwk("new-kid")
        new_jwks = {"keys": [{"kid": "old-kid", "kty": "RSA"}, new_key_data["jwk_public"]]}

        call_count = [0]

        def mock_fetch(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return old_jwks
            return new_jwks

        with mock.patch("daylily_cognito.jwks.fetch_jwks", side_effect=mock_fetch):
            cache = JWKSCache("us-west-2", "us-west-2_abc123")
            cache.get_key("old-kid")
            assert call_count[0] == 1

            # new-kid not in cache → triggers refresh
            key = cache.get_key("new-kid")
            assert key["kid"] == "new-kid"
            assert call_count[0] == 2


# ---------------------------------------------------------------------------
# verify_token_with_jwks
# ---------------------------------------------------------------------------


class TestVerifyTokenWithJwks:
    def test_valid_token(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "user-1",
            "client_id": "test-client",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            result = verify_token_with_jwks(token, region, pool_id)

        assert result["sub"] == "user-1"
        assert result["client_id"] == "test-client"

    def test_expired_token_raises(self, rsa_key_pair, jwks_response) -> None:
        from jose import ExpiredSignatureError

        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "user-1",
            "iss": issuer,
            "exp": int(time.time()) - 100,
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(ExpiredSignatureError):
                verify_token_with_jwks(token, region, pool_id)

    def test_wrong_issuer_raises(self, rsa_key_pair, jwks_response) -> None:
        from jose import JWTError

        claims = {
            "sub": "user-1",
            "iss": "https://evil.example.com",
            "exp": int(time.time()) + 3600,
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(JWTError):
                verify_token_with_jwks(token, "us-west-2", "us-west-2_abc123")

    def test_invalid_signature_raises(self, rsa_key_pair, jwks_response) -> None:
        from jose import JWTError

        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"

        # Sign with a different key
        other_key = _generate_rsa_jwk("test-kid-1")  # same kid, different key
        claims = {
            "sub": "user-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
        }
        token = _create_signed_token(other_key["private_pem"], other_key["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(JWTError):
                verify_token_with_jwks(token, region, pool_id)

    def test_missing_kid_raises(self) -> None:
        from jose import JWTError

        # Create a token without kid in header
        token = jose_jwt.encode({"sub": "user-1"}, "secret", algorithm="HS256")
        with pytest.raises(JWTError, match="missing 'kid'"):
            verify_token_with_jwks(token, "us-west-2", "us-west-2_abc123")

    def test_uses_provided_cache(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "user-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            cache = JWKSCache(region, pool_id)
            result = verify_token_with_jwks(token, region, pool_id, cache=cache)
            assert result["sub"] == "user-1"
