"""Daylily Cognito - Shared AWS Cognito authentication library.

Provides JWT token validation, user management, and OAuth2 flows
for FastAPI + Jinja2 web applications.

Example usage:
    from daylily_cognito import CognitoConfig, CognitoAuth, create_auth_dependency

    # Load config from the canonical daycog config file
    config = CognitoConfig.from_file("~/.config/daycog/config.yaml")

    # Create auth handler
    auth = CognitoAuth(
        region=config.region,
        user_pool_id=config.user_pool_id,
        app_client_id=config.app_client_id,
        profile=config.aws_profile,
    )

    # Create FastAPI dependency
    get_current_user = create_auth_dependency(auth)
"""

from .auth import CognitoAuth
from .config import CognitoConfig
from .domain_validator import DomainValidator
from .fastapi import create_auth_dependency, security
from .google import (
    auto_create_cognito_user_from_google,
    build_google_authorization_url,
    exchange_google_code_for_tokens,
    fetch_google_userinfo,
    generate_state_token,
)
from .jwks import JWKSCache
from .m2m import verify_m2m_token_with_jwks
from .oauth import (
    build_authorization_url,
    build_logout_url,
    exchange_authorization_code,
    refresh_with_refresh_token,
)
from .tokens import decode_jwt_unverified, verify_jwt_claims, verify_jwt_claims_unverified_signature
from .web_session import (
    SESSION_EXPIRED_REASON,
    CognitoWebAuthError,
    CognitoWebSessionConfig,
    SessionPrincipal,
    clear_session_principal,
    complete_cognito_callback,
    configure_session_middleware,
    load_session_principal,
    start_cognito_login,
    store_session_principal,
    validate_web_auth_contract,
)

__all__ = [
    # Config
    "CognitoConfig",
    # Auth
    "CognitoAuth",
    # Domain validation
    "DomainValidator",
    # FastAPI
    "create_auth_dependency",
    "security",
    # Cognito OAuth
    "build_authorization_url",
    "build_logout_url",
    "exchange_authorization_code",
    "refresh_with_refresh_token",
    # Hosted UI web sessions
    "CognitoWebAuthError",
    "CognitoWebSessionConfig",
    "SESSION_EXPIRED_REASON",
    "SessionPrincipal",
    "configure_session_middleware",
    "start_cognito_login",
    "complete_cognito_callback",
    "load_session_principal",
    "store_session_principal",
    "clear_session_principal",
    "validate_web_auth_contract",
    # Google OAuth
    "build_google_authorization_url",
    "exchange_google_code_for_tokens",
    "fetch_google_userinfo",
    "auto_create_cognito_user_from_google",
    "generate_state_token",
    # Tokens
    "decode_jwt_unverified",
    "verify_jwt_claims",
    "verify_jwt_claims_unverified_signature",
    # JWKS
    "JWKSCache",
    # M2M
    "verify_m2m_token_with_jwks",
]

try:
    from importlib.metadata import version as _get_version

    __version__ = _get_version("daylily-cognito")
except Exception:
    __version__ = "0.0.0"  # fallback for editable installs without metadata
