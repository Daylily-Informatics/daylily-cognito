"""Tests for the flat-file CLI config helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from daylily_auth_cognito.cli.config import (
    CognitoConfig,
    ConfigError,
    active_config_path,
    load_config_file,
    load_config_file_if_present,
    resolve_runtime_config,
    validate_config_text,
    write_config_file,
)


def _write_yaml(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _set_active_config(monkeypatch: pytest.MonkeyPatch, path: Path | None) -> None:
    monkeypatch.setattr(
        "daylily_auth_cognito.cli.config.get_context",
        lambda: SimpleNamespace(config_path=path),
    )


class TestValidateConfigText:
    def test_accepts_valid_flat_config(self) -> None:
        content = """
COGNITO_REGION: us-west-2
COGNITO_USER_POOL_ID: us-west-2_pool
COGNITO_APP_CLIENT_ID: client-123
COGNITO_CLIENT_NAME: web-app
AWS_PROFILE: dev-profile
"""

        assert validate_config_text(content) == []

    def test_rejects_invalid_yaml(self) -> None:
        errors = validate_config_text("COGNITO_REGION: [")

        assert len(errors) == 1
        assert errors[0].startswith("Invalid YAML:")

    def test_rejects_legacy_context_store_yaml(self) -> None:
        errors = validate_config_text("contexts: {}\nactive_context: dev\n", require_required_keys=False)

        assert errors == ["Context-store YAML format is not supported; use a flat config file instead."]

    def test_rejects_unknown_and_non_scalar_keys(self) -> None:
        content = """
COGNITO_REGION: us-west-2
COGNITO_USER_POOL_ID: us-west-2_pool
COGNITO_APP_CLIENT_ID: client-123
EXTRA_KEY: nope
GOOGLE_CLIENT_ID:
  nested: value
"""

        errors = validate_config_text(content)

        assert "Unknown config keys: EXTRA_KEY" in errors
        assert "GOOGLE_CLIENT_ID must be a scalar value" in errors

    def test_can_skip_required_key_checks(self) -> None:
        assert validate_config_text("GOOGLE_CLIENT_ID: gid-123\n", require_required_keys=False) == []


class TestFlatFileLoadingAndWriting:
    def test_cognito_config_from_file_loads_optional_values(self, tmp_path: Path) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "us-west-2_pool",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "COGNITO_CLIENT_NAME": "web-app",
                "COGNITO_CALLBACK_URL": "https://example.test/callback",
                "COGNITO_LOGOUT_URL": "https://example.test/logout",
                "GOOGLE_CLIENT_ID": "gid-123",
                "GOOGLE_CLIENT_SECRET": "gsecret-456",
                "COGNITO_DOMAIN": "auth.example.test",
                "AWS_PROFILE": "dev-profile",
                "AWS_REGION": "eu-west-1",
            },
        )

        config = CognitoConfig.from_file(path)

        assert config.region == "us-west-2"
        assert config.user_pool_id == "us-west-2_pool"
        assert config.app_client_id == "client-123"
        assert config.client_name == "web-app"
        assert config.callback_url == "https://example.test/callback"
        assert config.logout_url == "https://example.test/logout"
        assert config.google_client_id == "gid-123"
        assert config.google_client_secret == "gsecret-456"
        assert config.cognito_domain == "auth.example.test"
        assert config.aws_profile == "dev-profile"
        assert config.aws_region == "eu-west-1"

    def test_load_config_file_requires_existing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config_file(tmp_path / "missing.yaml")

    def test_load_config_file_rejects_missing_required_keys(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path / "invalid.yaml", {"COGNITO_REGION": "us-west-2"})

        with pytest.raises(ConfigError) as exc_info:
            load_config_file(path)

        message = str(exc_info.value)
        assert "Missing required key: COGNITO_USER_POOL_ID" in message
        assert "Missing required key: COGNITO_APP_CLIENT_ID" in message

    def test_load_config_file_if_present_returns_empty_mapping_for_missing_file(self, tmp_path: Path) -> None:
        assert load_config_file_if_present(tmp_path / "missing.yaml") == {}

    def test_write_config_file_normalizes_values_and_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = write_config_file(
            tmp_path / "nested" / "config.yaml",
            {
                "COGNITO_REGION": " us-west-2 ",
                "COGNITO_USER_POOL_ID": "us-west-2_pool",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "GOOGLE_CLIENT_ID": "",
                "GOOGLE_CLIENT_SECRET": None,
                "AWS_PROFILE": " dev-profile ",
            },
        )

        assert path.exists()
        stored = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert stored == {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "us-west-2_pool",
            "COGNITO_APP_CLIENT_ID": "client-123",
            "AWS_PROFILE": "dev-profile",
        }


class TestRuntimeResolution:
    def test_active_config_path_requires_initialized_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_active_config(monkeypatch, None)

        with pytest.raises(ConfigError, match="no active config path"):
            active_config_path()

    def test_resolve_runtime_config_prefers_explicit_profile_and_region(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "us-west-2_pool",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "AWS_PROFILE": "file-profile",
                "AWS_REGION": "eu-west-1",
            },
        )
        _set_active_config(monkeypatch, path)
        monkeypatch.setenv("AWS_PROFILE", "env-profile")
        monkeypatch.setenv("AWS_REGION", "ap-south-1")

        runtime = resolve_runtime_config(profile="flag-profile", region="ca-central-1")

        assert runtime.path == path
        assert runtime.aws_profile == "flag-profile"
        assert runtime.aws_region == "ca-central-1"
        assert runtime.values["COGNITO_USER_POOL_ID"] == "us-west-2_pool"

    def test_resolve_runtime_config_prefers_file_profile_over_env(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "us-west-2_pool",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "AWS_PROFILE": "file-profile",
            },
        )
        _set_active_config(monkeypatch, path)
        monkeypatch.setenv("AWS_PROFILE", "env-profile")
        monkeypatch.setenv("AWS_REGION", "us-east-1")

        runtime = resolve_runtime_config()

        assert runtime.aws_profile == "file-profile"
        assert runtime.aws_region == "us-west-2"

    def test_resolve_runtime_config_uses_file_aws_region_when_cognito_region_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_USER_POOL_ID": "us-west-2_pool",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "AWS_REGION": "eu-west-1",
            },
        )
        _set_active_config(monkeypatch, path)
        monkeypatch.setenv("AWS_REGION", "ap-south-1")

        runtime = resolve_runtime_config(require_required_keys=False)

        assert runtime.aws_region == "eu-west-1"

    def test_resolve_runtime_config_can_skip_missing_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "missing.yaml"
        _set_active_config(monkeypatch, path)
        monkeypatch.setenv("AWS_PROFILE", "env-profile")
        monkeypatch.setenv("AWS_REGION", "us-west-2")

        runtime = resolve_runtime_config(require_config=False, require_required_keys=False)

        assert runtime.path == path
        assert runtime.values == {}
        assert runtime.aws_profile == "env-profile"
        assert runtime.aws_region == "us-west-2"

    def test_resolve_runtime_config_errors_without_region(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_USER_POOL_ID": "pool-123",
                "COGNITO_APP_CLIENT_ID": "client-123",
                "AWS_PROFILE": "dev-profile",
            },
        )
        _set_active_config(monkeypatch, path)
        monkeypatch.delenv("AWS_REGION", raising=False)

        with pytest.raises(ConfigError, match="AWS region not set"):
            resolve_runtime_config(require_required_keys=False)

    def test_runtime_config_require_helpers(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        path = _write_yaml(
            tmp_path / "config.yaml",
            {
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "pool-123",
                "COGNITO_APP_CLIENT_ID": "client-123",
            },
        )
        _set_active_config(monkeypatch, path)

        runtime = resolve_runtime_config()

        with pytest.raises(ConfigError, match="AWS profile not set"):
            runtime.require_aws_profile()
        assert runtime.require("COGNITO_USER_POOL_ID") == "pool-123"
        with pytest.raises(ConfigError, match="Missing required config value"):
            runtime.require("GOOGLE_CLIENT_ID")
