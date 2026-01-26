"""Daylily Cognito - Shared AWS Cognito authentication library.

Provides JWT token validation, user management, and OAuth2 flows
for FastAPI + Jinja2 web applications.

Example usage:
    from daylily_cognito import CognitoConfig, CognitoAuth, create_auth_dependency

    # Load config from environment
    config = CognitoConfig.from_legacy_env()

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
from .cli import cognito_app, main
from .config import CognitoConfig
from .fastapi import create_auth_dependency, security
from .oauth import (
    build_authorization_url,
    build_logout_url,
    exchange_authorization_code,
    refresh_with_refresh_token,
)
from .tokens import decode_jwt_unverified, verify_jwt_claims_unverified_signature

__all__ = [
    # Config
    "CognitoConfig",
    # Auth
    "CognitoAuth",
    # FastAPI
    "create_auth_dependency",
    "security",
    # OAuth
    "build_authorization_url",
    "build_logout_url",
    "exchange_authorization_code",
    "refresh_with_refresh_token",
    # Tokens
    "decode_jwt_unverified",
    "verify_jwt_claims_unverified_signature",
    # CLI
    "cognito_app",
    "main",
]

__version__ = "0.1.0"
