"""Tests for the daycog CLI spec and config validator."""

from __future__ import annotations

from daylily_cognito.spec import _validate_config_template, spec


class TestSpecValidator:
    def test_accepts_valid_flat_config(self) -> None:
        errors = _validate_config_template(
            """
COGNITO_REGION: us-west-2
COGNITO_USER_POOL_ID: us-west-2_pool
COGNITO_APP_CLIENT_ID: client-123
GOOGLE_CLIENT_ID: gid-123
AWS_PROFILE: dev-profile
"""
        )

        assert errors == []

    def test_rejects_invalid_yaml_and_non_mapping(self) -> None:
        invalid_yaml = _validate_config_template("COGNITO_REGION: [")
        non_mapping = _validate_config_template("- just\n- a\n- list\n")

        assert len(invalid_yaml) == 1
        assert invalid_yaml[0].startswith("Invalid YAML:")
        assert non_mapping == ["Config file must contain a top-level mapping."]

    def test_rejects_legacy_unknown_nonscalar_and_missing_keys(self) -> None:
        errors = _validate_config_template(
            """
contexts: {}
active_context: default
COGNITO_REGION:
  nested: value
EXTRA_KEY: nope
"""
        )

        assert "Context-store YAML format is not supported; use a flat config file instead." in errors
        assert "Unknown config keys: EXTRA_KEY" in errors
        assert "COGNITO_REGION must be a scalar value" in errors
        assert "Missing required key: COGNITO_USER_POOL_ID" in errors
        assert "Missing required key: COGNITO_APP_CLIENT_ID" in errors

    def test_spec_declares_expected_config_path_and_template(self) -> None:
        assert spec.prog_name == "daycog"
        assert spec.config is not None
        assert spec.config.xdg_relative_path == "config.yaml"
        template = spec.config.template_bytes.decode("utf-8")
        assert "COGNITO_REGION" in template
        assert "COGNITO_USER_POOL_ID" in template
        assert "COGNITO_APP_CLIENT_ID" in template
        assert "GOOGLE_CLIENT_SECRET" in template
        assert "AWS_REGION" in template
