"""Curated public API for daylily-auth-cognito."""

from __future__ import annotations

from .browser.session import (
    CognitoWebSessionConfig,
    SessionPrincipal,
    clear_session_principal,
    complete_cognito_callback,
    configure_session_middleware,
    load_session_principal,
    start_cognito_login,
    store_session_principal,
)
from .runtime.fastapi import create_auth_dependency
from .runtime.jwks import JWKSCache
from .runtime.m2m import verify_m2m_token_with_jwks
from .runtime.verifier import CognitoTokenVerifier
from .version import __version__

__all__ = [
    "CognitoWebSessionConfig",
    "SessionPrincipal",
    "configure_session_middleware",
    "start_cognito_login",
    "complete_cognito_callback",
    "load_session_principal",
    "store_session_principal",
    "clear_session_principal",
    "CognitoTokenVerifier",
    "create_auth_dependency",
    "JWKSCache",
    "verify_m2m_token_with_jwks",
    "__version__",
]
