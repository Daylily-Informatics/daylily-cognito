"""Flat-file Cognito configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import yaml
from cli_core_yo.runtime import get_context

CONFIG_KEYS = {
    "AWS_PROFILE",
    "AWS_REGION",
    "COGNITO_REGION",
    "COGNITO_USER_POOL_ID",
    "COGNITO_APP_CLIENT_ID",
    "COGNITO_CLIENT_NAME",
    "COGNITO_CALLBACK_URL",
    "COGNITO_LOGOUT_URL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "COGNITO_DOMAIN",
}

REQUIRED_CONFIG_KEYS = {
    "COGNITO_REGION",
    "COGNITO_USER_POOL_ID",
    "COGNITO_APP_CLIENT_ID",
}

_SCALAR_TYPES = (str, int, float, bool)


class ConfigError(ValueError):
    """Raised when the flat config file is missing or invalid."""


def _validate_cognito_domain_value(value: Any) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if parsed.scheme or parsed.netloc:
        raise ConfigError("COGNITO_DOMAIN must be a bare host without scheme")
    if "/" in normalized:
        raise ConfigError("COGNITO_DOMAIN must be a bare host without path")
    if any(char.isspace() for char in normalized):
        raise ConfigError("COGNITO_DOMAIN must not contain whitespace")
    return normalized


@dataclass(frozen=True)
class CognitoConfig:
    """Immutable Cognito configuration loaded from a flat YAML file."""

    region: str
    user_pool_id: str
    app_client_id: str
    aws_profile: Optional[str] = None
    aws_region: Optional[str] = None
    client_name: Optional[str] = None
    callback_url: Optional[str] = None
    logout_url: Optional[str] = None
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    cognito_domain: Optional[str] = None

    @classmethod
    def from_file(cls, path: str | Path) -> "CognitoConfig":
        values = load_config_file(path, require_required_keys=True)
        return cls(
            region=values["COGNITO_REGION"],
            user_pool_id=values["COGNITO_USER_POOL_ID"],
            app_client_id=values["COGNITO_APP_CLIENT_ID"],
            aws_profile=values.get("AWS_PROFILE") or None,
            aws_region=values.get("AWS_REGION") or None,
            client_name=values.get("COGNITO_CLIENT_NAME") or None,
            callback_url=values.get("COGNITO_CALLBACK_URL") or None,
            logout_url=values.get("COGNITO_LOGOUT_URL") or None,
            google_client_id=values.get("GOOGLE_CLIENT_ID") or None,
            google_client_secret=values.get("GOOGLE_CLIENT_SECRET") or None,
            cognito_domain=values.get("COGNITO_DOMAIN") or None,
        )


@dataclass(frozen=True)
class RuntimeConfig:
    """Resolved config for a CLI invocation."""

    path: Path
    values: dict[str, str]
    aws_profile: Optional[str]
    aws_region: str

    def require_aws_profile(self) -> str:
        if self.aws_profile:
            return self.aws_profile
        raise ConfigError(
            "AWS profile not set. Pass --profile, set AWS_PROFILE, or add AWS_PROFILE to the config file."
        )

    def require(self, key: str) -> str:
        value = self.values.get(key, "").strip()
        if value:
            return value
        raise ConfigError(f"Missing required config value: {key}")


def validate_config_text(content: str, *, require_required_keys: bool = True) -> list[str]:
    """Validate raw YAML config text."""
    try:
        payload = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        return [f"Invalid YAML: {exc}"]
    return _validate_payload(payload, require_required_keys=require_required_keys)


def active_config_path() -> Path:
    """Return the effective config path for the current CLI invocation."""
    ctx = get_context()
    if ctx.config_path is None:
        raise ConfigError("daycog has no active config path for this invocation.")
    return ctx.config_path


def load_config_file(
    path: str | Path,
    *,
    require_required_keys: bool = True,
) -> dict[str, str]:
    """Load and validate a flat config file."""
    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    errors = _validate_payload(payload, require_required_keys=require_required_keys)
    if errors:
        raise ConfigError("\n".join(errors))

    return _normalize_payload(payload)


def load_config_file_if_present(
    path: str | Path,
    *,
    require_required_keys: bool = False,
) -> dict[str, str]:
    """Load config if it exists, otherwise return an empty mapping."""
    config_path = Path(path).expanduser()
    if not config_path.exists():
        return {}
    return load_config_file(config_path, require_required_keys=require_required_keys)


def write_config_file(path: str | Path, values: dict[str, Any]) -> Path:
    """Write a normalized flat config file."""
    config_path = Path(path).expanduser()
    normalized = _normalize_for_write(values)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(normalized, sort_keys=False), encoding="utf-8")
    return config_path


def resolve_runtime_config(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    require_config: bool = True,
    require_required_keys: bool = True,
) -> RuntimeConfig:
    """Load the effective CLI config file and resolve AWS precedence."""
    path = active_config_path()
    values = (
        load_config_file(path, require_required_keys=require_required_keys)
        if require_config
        else load_config_file_if_present(path, require_required_keys=require_required_keys)
    )
    resolved_region = (
        (region or "").strip()
        or values.get("COGNITO_REGION", "").strip()
        or values.get("AWS_REGION", "").strip()
        or str(os.environ.get("AWS_REGION") or "").strip()
    )
    if not resolved_region:
        raise ConfigError(
            "AWS region not set. Pass --region, set AWS_REGION, or add COGNITO_REGION/AWS_REGION to the config file."
        )

    resolved_profile = (
        (profile or "").strip()
        or values.get("AWS_PROFILE", "").strip()
        or str(os.environ.get("AWS_PROFILE") or "").strip()
        or None
    )
    return RuntimeConfig(
        path=path,
        values=values,
        aws_profile=resolved_profile,
        aws_region=resolved_region,
    )


def _validate_payload(payload: Any, *, require_required_keys: bool) -> list[str]:
    if not isinstance(payload, dict):
        return ["Config file must contain a top-level mapping."]

    keys = {str(key) for key in payload.keys()}
    rejected_keys = {"contexts", "active_context"} & keys
    errors: list[str] = []

    if rejected_keys:
        errors.append("Context-store YAML format is not supported; use a flat config file instead.")

    unknown_keys = sorted(keys - CONFIG_KEYS - rejected_keys)
    if unknown_keys:
        errors.append(f"Unknown config keys: {', '.join(unknown_keys)}")

    for key in sorted(CONFIG_KEYS & keys):
        value = payload.get(key)
        if value is None:
            continue
        if not isinstance(value, _SCALAR_TYPES):
            errors.append(f"{key} must be a scalar value")

    if require_required_keys:
        for key in sorted(REQUIRED_CONFIG_KEYS):
            value = payload.get(key)
            if value is None or not str(value).strip():
                errors.append(f"Missing required key: {key}")

    if "COGNITO_DOMAIN" in payload and payload.get("COGNITO_DOMAIN") is not None:
        try:
            _validate_cognito_domain_value(payload.get("COGNITO_DOMAIN"))
        except ConfigError as exc:
            errors.append(str(exc))

    return errors


def _normalize_payload(payload: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key in sorted(CONFIG_KEYS):
        if key not in payload or payload.get(key) is None:
            continue
        value = _validate_cognito_domain_value(payload[key]) if key == "COGNITO_DOMAIN" else str(payload[key]).strip()
        if value:
            normalized[key] = value
    return normalized


def _normalize_for_write(values: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key in [
        "COGNITO_REGION",
        "COGNITO_USER_POOL_ID",
        "COGNITO_APP_CLIENT_ID",
        "COGNITO_CLIENT_NAME",
        "COGNITO_CALLBACK_URL",
        "COGNITO_LOGOUT_URL",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "COGNITO_DOMAIN",
        "AWS_PROFILE",
        "AWS_REGION",
    ]:
        if key not in values or values.get(key) is None:
            continue
        value = _validate_cognito_domain_value(values[key]) if key == "COGNITO_DOMAIN" else str(values[key]).strip()
        if value:
            normalized[key] = value
    return normalized
