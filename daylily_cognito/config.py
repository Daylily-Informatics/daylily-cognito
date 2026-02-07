"""Cognito configuration management.

Provides immutable configuration objects for AWS Cognito authentication.
Supports both namespaced env vars (DAYCOG_<NAME>_*) and legacy env vars (COGNITO_*).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CognitoConfig:
    """Immutable Cognito configuration.

    Attributes:
        name: Optional config name (for namespaced env loading)
        region: AWS region (e.g., 'us-west-2')
        user_pool_id: Cognito User Pool ID
        app_client_id: Cognito App Client ID
        aws_profile: Optional AWS profile name
        google_client_id: Optional Google OAuth2 client ID
        google_client_secret: Optional Google OAuth2 client secret
        cognito_domain: Optional Cognito hosted UI domain (for federated flows)
    """

    name: Optional[str]
    region: str
    user_pool_id: str
    app_client_id: str
    aws_profile: Optional[str] = None
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    cognito_domain: Optional[str] = None

    def validate(self) -> None:
        """Validate configuration fields.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        missing = []
        if not self.region:
            missing.append("region")
        if not self.user_pool_id:
            missing.append("user_pool_id")
        if not self.app_client_id:
            missing.append("app_client_id")

        if missing:
            raise ValueError(f"Missing required Cognito config fields: {', '.join(missing)}")

    @classmethod
    def from_env(cls, name: str, *, prefix: str = "DAYCOG") -> "CognitoConfig":
        """Load configuration from namespaced environment variables.

        Reads:
            {prefix}_{NAME}_REGION
            {prefix}_{NAME}_USER_POOL_ID
            {prefix}_{NAME}_APP_CLIENT_ID
            {prefix}_{NAME}_AWS_PROFILE (optional)
            {prefix}_{NAME}_GOOGLE_CLIENT_ID (optional)
            {prefix}_{NAME}_GOOGLE_CLIENT_SECRET (optional)
            {prefix}_{NAME}_COGNITO_DOMAIN (optional)

        Args:
            name: Config name (used in env var names, uppercased)
            prefix: Env var prefix (default: DAYCOG)

        Returns:
            CognitoConfig instance

        Raises:
            ValueError: If required env vars are missing.

        Example:
            # With DAYCOG_PROD_REGION=us-west-2, DAYCOG_PROD_USER_POOL_ID=..., etc.
            config = CognitoConfig.from_env("PROD")
        """
        name_upper = name.upper()
        env_prefix = f"{prefix}_{name_upper}_"

        region = os.environ.get(f"{env_prefix}REGION", "")
        user_pool_id = os.environ.get(f"{env_prefix}USER_POOL_ID", "")
        app_client_id = os.environ.get(f"{env_prefix}APP_CLIENT_ID", "")
        aws_profile = os.environ.get(f"{env_prefix}AWS_PROFILE")
        google_client_id = os.environ.get(f"{env_prefix}GOOGLE_CLIENT_ID")
        google_client_secret = os.environ.get(f"{env_prefix}GOOGLE_CLIENT_SECRET")
        cognito_domain = os.environ.get(f"{env_prefix}COGNITO_DOMAIN")

        config = cls(
            name=name,
            region=region,
            user_pool_id=user_pool_id,
            app_client_id=app_client_id,
            aws_profile=aws_profile,
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            cognito_domain=cognito_domain,
        )

        # Validate and provide helpful error message
        missing = []
        if not region:
            missing.append(f"{env_prefix}REGION")
        if not user_pool_id:
            missing.append(f"{env_prefix}USER_POOL_ID")
        if not app_client_id:
            missing.append(f"{env_prefix}APP_CLIENT_ID")

        if missing:
            raise ValueError(f"Missing required environment variables for config '{name}': {', '.join(missing)}")

        return config

    @classmethod
    def from_legacy_env(cls) -> "CognitoConfig":
        """Load configuration from legacy environment variables.

        Reads:
            COGNITO_REGION (fallback: AWS_REGION, then 'us-west-2')
            COGNITO_USER_POOL_ID
            COGNITO_APP_CLIENT_ID (fallback: COGNITO_CLIENT_ID)
            AWS_PROFILE (optional)
            GOOGLE_CLIENT_ID (optional)
            GOOGLE_CLIENT_SECRET (optional)
            COGNITO_DOMAIN (optional)

        Returns:
            CognitoConfig instance

        Raises:
            ValueError: If required env vars are missing.
        """
        # Region: COGNITO_REGION > AWS_REGION > us-west-2
        region = os.environ.get("COGNITO_REGION") or os.environ.get("AWS_REGION") or "us-west-2"

        # Pool ID
        user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")

        # Client ID: COGNITO_APP_CLIENT_ID > COGNITO_CLIENT_ID
        app_client_id = os.environ.get("COGNITO_APP_CLIENT_ID") or os.environ.get("COGNITO_CLIENT_ID", "")

        # AWS profile (optional)
        aws_profile = os.environ.get("AWS_PROFILE")

        # Google OAuth (optional)
        google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
        google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
        cognito_domain = os.environ.get("COGNITO_DOMAIN")

        config = cls(
            name=None,
            region=region,
            user_pool_id=user_pool_id,
            app_client_id=app_client_id,
            aws_profile=aws_profile,
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            cognito_domain=cognito_domain,
        )

        # Validate required fields
        missing = []
        if not user_pool_id:
            missing.append("COGNITO_USER_POOL_ID")
        if not app_client_id:
            missing.append("COGNITO_APP_CLIENT_ID (or COGNITO_CLIENT_ID)")

        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        return config
