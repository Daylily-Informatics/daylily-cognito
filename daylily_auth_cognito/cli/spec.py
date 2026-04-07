from __future__ import annotations

from collections.abc import Mapping

import yaml
from cli_core_yo.spec import CliSpec, ConfigSpec, PluginSpec, PolicySpec, XdgSpec

_ALLOWED_KEYS = {
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

_REQUIRED_KEYS = {
    "COGNITO_REGION",
    "COGNITO_USER_POOL_ID",
    "COGNITO_APP_CLIENT_ID",
}


def _validate_config_template(content: str) -> list[str]:
    """Validate the flat daycog config file shape."""
    errors: list[str] = []
    try:
        payload = yaml.safe_load(content) or {}
    except Exception as exc:
        return [f"Invalid YAML: {exc}"]

    if not isinstance(payload, Mapping):
        return ["Config file must contain a top-level mapping."]

    keys = {str(key) for key in payload.keys()}
    rejected_keys = {"contexts", "active_context"} & keys
    if rejected_keys:
        errors.append("Context-store YAML format is not supported; use a flat config file instead.")

    unknown_keys = sorted(keys - _ALLOWED_KEYS - rejected_keys)
    if unknown_keys:
        errors.append(f"Unknown config keys: {', '.join(unknown_keys)}")

    for key in sorted(_REQUIRED_KEYS):
        value = payload.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"Missing required key: {key}")

    for key in sorted(_ALLOWED_KEYS & keys):
        value = payload.get(key)
        if isinstance(value, (Mapping, list, tuple, set)):
            errors.append(f"{key} must be a scalar value")

    return errors


spec = CliSpec(
    prog_name="daycog",
    app_display_name="Daycog CLI",
    dist_name="daylily-auth-cognito",
    root_help="Cognito authentication management commands",
    xdg=XdgSpec(app_dir_name="daycog"),
    policy=PolicySpec(profile="platform-v2"),
    config=ConfigSpec(
        xdg_relative_path="config.yaml",
        template_bytes=(
            b'COGNITO_REGION: ""\n'
            b'COGNITO_USER_POOL_ID: ""\n'
            b'COGNITO_APP_CLIENT_ID: ""\n'
            b'COGNITO_CLIENT_NAME: ""\n'
            b'COGNITO_CALLBACK_URL: ""\n'
            b'COGNITO_LOGOUT_URL: ""\n'
            b'GOOGLE_CLIENT_ID: ""\n'
            b'GOOGLE_CLIENT_SECRET: ""\n'
            b'COGNITO_DOMAIN: ""\n'
            b'AWS_PROFILE: ""\n'
            b'AWS_REGION: ""\n'
        ),
        validator=_validate_config_template,
    ),
    plugins=PluginSpec(
        explicit=[
            "daylily_auth_cognito.cli.plugins.register",
        ]
    ),
)
