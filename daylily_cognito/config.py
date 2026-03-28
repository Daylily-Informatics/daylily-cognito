"""Cognito configuration management.

Provides immutable configuration objects for AWS Cognito authentication.
Supports the canonical ~/.config/daycog/config.yaml store plus environment overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


def _config_dir() -> Path:
    return Path.home() / ".config" / "daycog"


def get_config_store_path() -> Path:
    return _config_dir() / "config.yaml"


def load_config_store() -> dict:
    path = get_config_store_path()
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return raw if isinstance(raw, dict) else {}


def save_config_store(payload: dict) -> None:
    path = get_config_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def get_active_context_name() -> str:
    raw = load_config_store()
    return str(raw.get("active_context") or "").strip()


def list_context_values() -> dict[str, dict[str, str]]:
    raw = load_config_store()
    contexts = raw.get("contexts") if isinstance(raw.get("contexts"), dict) else {}
    if not isinstance(contexts, dict):
        return {}
    normalized: dict[str, dict[str, str]] = {}
    for name, values in contexts.items():
        if not isinstance(values, dict):
            continue
        normalized[str(name)] = {str(key): str(value) for key, value in values.items() if value is not None}
    return normalized


def get_context_values(name: Optional[str] = None) -> dict[str, str]:
    contexts = list_context_values()
    context_name = str(name or get_active_context_name()).strip()
    node = contexts.get(context_name) if context_name else {}
    return dict(node) if isinstance(node, dict) else {}


def save_context_values(name: str, values: dict[str, str], *, set_active: bool = False) -> None:
    payload = load_config_store()
    contexts = payload.setdefault("contexts", {})
    if not isinstance(contexts, dict):
        contexts = {}
        payload["contexts"] = contexts
    contexts[name] = dict(values)
    if set_active:
        payload["active_context"] = name
    save_config_store(payload)


def set_active_context(name: str) -> None:
    payload = load_config_store()
    payload["active_context"] = name
    save_config_store(payload)


def delete_context(name: str) -> bool:
    payload = load_config_store()
    contexts = payload.get("contexts") if isinstance(payload.get("contexts"), dict) else {}
    if not isinstance(contexts, dict) or name not in contexts:
        return False
    del contexts[name]
    if str(payload.get("active_context") or "").strip() == name:
        payload["active_context"] = ""
    save_config_store(payload)
    return True


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
        """Load configuration from the canonical config store or env vars.

        The YAML store is authoritative; DAYCOG_<NAME>_* variables still override
        it when they are present in the process environment.
        """
        name_upper = name.upper()
        env_prefix = f"{prefix}_{name_upper}_"
        stored = get_context_values(name)

        region = os.environ.get(f"{env_prefix}REGION", stored.get("COGNITO_REGION", ""))
        user_pool_id = os.environ.get(f"{env_prefix}USER_POOL_ID", stored.get("COGNITO_USER_POOL_ID", ""))
        app_client_id = os.environ.get(f"{env_prefix}APP_CLIENT_ID", stored.get("COGNITO_APP_CLIENT_ID", ""))
        aws_profile = os.environ.get(f"{env_prefix}AWS_PROFILE") or stored.get("AWS_PROFILE")
        google_client_id = os.environ.get(f"{env_prefix}GOOGLE_CLIENT_ID") or stored.get("GOOGLE_CLIENT_ID")
        google_client_secret = os.environ.get(f"{env_prefix}GOOGLE_CLIENT_SECRET") or stored.get("GOOGLE_CLIENT_SECRET")
        cognito_domain = os.environ.get(f"{env_prefix}COGNITO_DOMAIN") or stored.get("COGNITO_DOMAIN")

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
        """Load configuration from the active config context or legacy env vars.

        The active YAML context is preferred; process env overrides it.
        """
        stored = get_context_values()
        # Region: COGNITO_REGION > AWS_REGION > us-west-2
        region = (
            os.environ.get("COGNITO_REGION")
            or os.environ.get("AWS_REGION")
            or stored.get("COGNITO_REGION")
            or stored.get("AWS_REGION")
            or "us-west-2"
        )

        # Pool ID
        user_pool_id = os.environ.get("COGNITO_USER_POOL_ID") or stored.get("COGNITO_USER_POOL_ID", "")

        # Client ID: COGNITO_APP_CLIENT_ID > COGNITO_CLIENT_ID
        app_client_id = (
            os.environ.get("COGNITO_APP_CLIENT_ID")
            or os.environ.get("COGNITO_CLIENT_ID")
            or stored.get("COGNITO_APP_CLIENT_ID", "")
        )

        # AWS profile (optional)
        aws_profile = os.environ.get("AWS_PROFILE") or stored.get("AWS_PROFILE")

        # Google OAuth (optional)
        google_client_id = os.environ.get("GOOGLE_CLIENT_ID") or stored.get("GOOGLE_CLIENT_ID")
        google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET") or stored.get("GOOGLE_CLIENT_SECRET")
        cognito_domain = os.environ.get("COGNITO_DOMAIN") or stored.get("COGNITO_DOMAIN")

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
