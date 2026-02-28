"""JWKS (JSON Web Key Set) handling for Cognito.

Fetches keys from Cognito's well-known JWKS endpoint and verifies
JWT token signatures using python-jose.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

LOGGER = logging.getLogger("daylily_cognito.jwks")

# Default cache TTL: 1 hour
DEFAULT_CACHE_TTL_SECONDS = 3600


def build_jwks_url(region: str, user_pool_id: str) -> str:
    """Build the JWKS URL for a Cognito user pool.

    Args:
        region: AWS region (e.g., 'us-west-2')
        user_pool_id: Cognito User Pool ID

    Returns:
        JWKS URL string
    """
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"


def fetch_jwks(region: str, user_pool_id: str) -> dict[str, Any]:
    """Fetch JWKS from Cognito.

    Uses urllib.request (stdlib) to GET the JWKS JSON.

    Args:
        region: AWS region
        user_pool_id: Cognito User Pool ID

    Returns:
        JWKS dict with 'keys' list

    Raises:
        RuntimeError: If the JWKS fetch fails
    """
    url = build_jwks_url(region, user_pool_id)
    request = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"JWKS fetch failed: HTTP {e.code} - {error_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"JWKS fetch failed: {e.reason}") from e


class JWKSCache:
    """Thread-safe in-memory cache for JWKS keys, keyed by kid.

    Supports TTL-based expiry and automatic refetch on cache miss
    (handles key rotation).

    Args:
        region: AWS region
        user_pool_id: Cognito User Pool ID
        ttl_seconds: Cache time-to-live in seconds (default: 3600)
    """

    def __init__(
        self,
        region: str,
        user_pool_id: str,
        ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        self.region = region
        self.user_pool_id = user_pool_id
        self.ttl_seconds = ttl_seconds
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def _is_expired(self) -> bool:
        """Check if the cache has expired."""
        return (time.time() - self._fetched_at) >= self.ttl_seconds

    def _refresh(self) -> None:
        """Fetch JWKS and update the cache. Must be called under _lock."""
        jwks = fetch_jwks(self.region, self.user_pool_id)
        self._keys = {key["kid"]: key for key in jwks.get("keys", []) if "kid" in key}
        self._fetched_at = time.time()
        LOGGER.debug("JWKS cache refreshed, %d keys loaded", len(self._keys))

    def get_key(self, kid: str) -> dict[str, Any]:
        """Get a JWK by key ID.

        If the key is not found or the cache is expired, refetches JWKS once.

        Args:
            kid: Key ID from the JWT header

        Returns:
            JWK dict for the given kid

        Raises:
            KeyError: If kid is not found even after refresh
            RuntimeError: If JWKS fetch fails
        """
        with self._lock:
            # Try cache first if not expired
            if not self._is_expired() and kid in self._keys:
                return self._keys[kid]

            # Refresh and try again (handles expiry + key rotation)
            self._refresh()

            if kid not in self._keys:
                raise KeyError(f"Key ID '{kid}' not found in JWKS")
            return self._keys[kid]


def verify_token_with_jwks(
    token: str,
    region: str,
    user_pool_id: str,
    cache: Optional[JWKSCache] = None,
) -> dict[str, Any]:
    """Verify a JWT token using JWKS from Cognito.

    Decodes the JWT header to get the kid, looks up the key from
    cache/JWKS, then uses jose.jwt.decode() with signature verification.
    Verifies exp and iss claims.

    Args:
        token: JWT token string
        region: AWS region
        user_pool_id: Cognito User Pool ID
        cache: Optional JWKSCache instance (created if not provided)

    Returns:
        Decoded and verified token claims

    Raises:
        ImportError: If python-jose is not installed
        jose.JWTError: If token verification fails
        KeyError: If kid not found in JWKS
        RuntimeError: If JWKS fetch fails
    """
    try:
        from jose import jwt
    except ImportError as e:
        raise ImportError(
            "python-jose is required for JWT verification. Install with: pip install 'python-jose[cryptography]'"
        ) from e

    # Get kid from JWT header
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        from jose import JWTError

        raise JWTError("JWT header missing 'kid' claim")

    # Get the signing key
    if cache is None:
        cache = JWKSCache(region, user_pool_id)

    key = cache.get_key(kid)

    # Build expected issuer
    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    # Decode and verify
    claims: dict[str, Any] = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
        },
        issuer=issuer,
    )

    return claims
