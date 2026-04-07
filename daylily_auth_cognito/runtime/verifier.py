"""Verification-only Cognito bearer token handling."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status

from .jwks import JWKSCache, verify_token_with_jwks

try:
    from jose import JWTError, jwt
except (ImportError, SyntaxError):
    JWTError = Exception
    jwt = None

LOGGER = logging.getLogger("daylily_auth_cognito.runtime.verifier")


@dataclass
class CognitoTokenVerifier:
    """Verification-only boundary for Cognito JWTs."""

    region: str
    user_pool_id: str
    app_client_id: str
    cache: JWKSCache | None = None

    def __post_init__(self) -> None:
        if not self.region:
            raise ValueError("region is required")
        if not self.user_pool_id:
            raise ValueError("user_pool_id is required")
        if not self.app_client_id:
            raise ValueError("app_client_id is required")
        if self.cache is None:
            self.cache = JWKSCache(self.region, self.user_pool_id)

    def verify_token(self, token: str, *, verify_signature: bool = True) -> dict[str, Any]:
        if jwt is None:
            raise ImportError(
                "python-jose is required for JWT verification. Install with: pip install 'python-jose[cryptography]'"
            )

        try:
            if verify_signature:
                claims = verify_token_with_jwks(token, self.region, self.user_pool_id, cache=self.cache)
            else:
                jwt.get_unverified_header(token)
                claims = jwt.decode(
                    token,
                    key="",
                    options={"verify_signature": False, "verify_exp": False},
                )

            if "exp" in claims and claims["exp"] < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                )

            if claims.get("client_id") != self.app_client_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token audience",
                )

            return claims
        except HTTPException:
            raise
        except (KeyError, RuntimeError) as exc:
            LOGGER.error("JWKS verification error: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            ) from exc
        except JWTError as exc:
            LOGGER.error("JWT validation error: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            ) from exc
