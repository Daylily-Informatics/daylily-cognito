"""Tests for Cognito machine-to-machine JWT verification helpers."""

from __future__ import annotations

import builtins
import time
from unittest import mock

import pytest
from fastapi import HTTPException

pytest.importorskip("jose", reason="python-jose not installed")
from jose import jwt as jose_jwt
from jose.backends import RSAKey

from daylily_cognito.m2m import verify_m2m_token_with_jwks


def _generate_rsa_jwk(kid: str = "test-kid-1") -> dict[str, object]:
    """Generate an RSA key pair and JWK for token signing tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rsa_key = RSAKey(public_pem, algorithm="RS256")
    jwk = rsa_key.to_dict()
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {"jwk_public": jwk, "private_pem": private_pem, "kid": kid}


@pytest.fixture
def rsa_key_pair() -> dict[str, object]:
    return _generate_rsa_jwk("test-kid-1")


@pytest.fixture
def jwks_response(rsa_key_pair: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    return {"keys": [rsa_key_pair["jwk_public"]]}


def _create_signed_token(private_pem: bytes, kid: str, claims: dict[str, object]) -> str:
    return jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


class TestVerifyM2MTokenWithJwks:
    def test_valid_access_token_with_required_scopes(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "client-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
            "token_use": "access",
            "client_id": "atlas-client",
            "scope": "orders.read orders.write",
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            result = verify_m2m_token_with_jwks(
                token,
                expected_client_id="atlas-client",
                region=region,
                user_pool_id=pool_id,
                required_scopes=["orders.read"],
            )

        assert result["client_id"] == "atlas-client"
        assert result["token_use"] == "access"
        assert result["scope"] == "orders.read orders.write"

    def test_missing_required_scope_raises_forbidden(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "client-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
            "token_use": "access",
            "client_id": "atlas-client",
            "scope": "orders.read",
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(HTTPException) as exc_info:
                verify_m2m_token_with_jwks(
                    token,
                    expected_client_id="atlas-client",
                    region=region,
                    user_pool_id=pool_id,
                    required_scopes=("orders.write",),
                )

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Insufficient token scopes"

    def test_wrong_client_id_raises(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "client-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
            "token_use": "access",
            "client_id": "wrong-client",
            "scope": "orders.read",
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(HTTPException) as exc_info:
                verify_m2m_token_with_jwks(
                    token,
                    expected_client_id="atlas-client",
                    region=region,
                    user_pool_id=pool_id,
                    required_scopes=["orders.read"],
                )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token audience"

    def test_wrong_token_use_raises(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "client-1",
            "iss": issuer,
            "exp": int(time.time()) + 3600,
            "token_use": "id",
            "client_id": "atlas-client",
            "scope": "orders.read",
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(HTTPException) as exc_info:
                verify_m2m_token_with_jwks(
                    token,
                    expected_client_id="atlas-client",
                    region=region,
                    user_pool_id=pool_id,
                    required_scopes=["orders.read"],
                )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token type"

    def test_expired_token_raises(self, rsa_key_pair, jwks_response) -> None:
        region = "us-west-2"
        pool_id = "us-west-2_abc123"
        issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        claims = {
            "sub": "client-1",
            "iss": issuer,
            "exp": int(time.time()) - 100,
            "token_use": "access",
            "client_id": "atlas-client",
            "scope": "orders.read",
        }
        token = _create_signed_token(rsa_key_pair["private_pem"], rsa_key_pair["kid"], claims)

        with mock.patch("daylily_cognito.jwks.fetch_jwks", return_value=jwks_response):
            with pytest.raises(HTTPException) as exc_info:
                verify_m2m_token_with_jwks(
                    token,
                    expected_client_id="atlas-client",
                    region=region,
                    user_pool_id=pool_id,
                    required_scopes=["orders.read"],
                )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has expired"

    def test_import_error_when_jose_missing(self) -> None:
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "jose":
                raise ImportError("missing jose")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            with pytest.raises(ImportError) as exc_info:
                verify_m2m_token_with_jwks(
                    "token",
                    expected_client_id="atlas-client",
                    region="us-west-2",
                    user_pool_id="us-west-2_abc123",
                )

        assert "python-jose is required for JWT verification" in str(exc_info.value)
