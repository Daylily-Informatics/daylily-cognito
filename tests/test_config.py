"""Tests for CognitoConfig."""

import os
from unittest import mock

import pytest

from daylily_cognito.config import CognitoConfig


class TestCognitoConfigValidate:
    """Tests for CognitoConfig.validate()."""

    def test_validate_success(self) -> None:
        """Valid config passes validation."""
        config = CognitoConfig(
            name="test",
            region="us-west-2",
            user_pool_id="us-west-2_abc123",
            app_client_id="client123",
        )
        config.validate()  # Should not raise

    def test_validate_missing_region(self) -> None:
        """Missing region raises ValueError."""
        config = CognitoConfig(
            name="test",
            region="",
            user_pool_id="us-west-2_abc123",
            app_client_id="client123",
        )
        with pytest.raises(ValueError, match="region"):
            config.validate()

    def test_validate_missing_multiple(self) -> None:
        """Missing multiple fields lists all in error."""
        config = CognitoConfig(
            name="test",
            region="",
            user_pool_id="",
            app_client_id="",
        )
        with pytest.raises(ValueError) as exc_info:
            config.validate()
        assert "region" in str(exc_info.value)
        assert "user_pool_id" in str(exc_info.value)
        assert "app_client_id" in str(exc_info.value)


class TestCognitoConfigFromEnv:
    """Tests for CognitoConfig.from_env()."""

    def test_from_env_success(self) -> None:
        """Loads config from namespaced env vars."""
        env = {
            "DAYCOG_PROD_REGION": "us-east-1",
            "DAYCOG_PROD_USER_POOL_ID": "us-east-1_pool",
            "DAYCOG_PROD_APP_CLIENT_ID": "client_prod",
            "DAYCOG_PROD_AWS_PROFILE": "prod-profile",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_env("PROD")

        assert config.name == "PROD"
        assert config.region == "us-east-1"
        assert config.user_pool_id == "us-east-1_pool"
        assert config.app_client_id == "client_prod"
        assert config.aws_profile == "prod-profile"

    def test_from_env_missing_vars(self) -> None:
        """Missing env vars raises ValueError with var names."""
        env = {"DAYCOG_TEST_REGION": "us-west-2"}
        with mock.patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError) as exc_info:
                CognitoConfig.from_env("TEST")
        assert "DAYCOG_TEST_USER_POOL_ID" in str(exc_info.value)
        assert "DAYCOG_TEST_APP_CLIENT_ID" in str(exc_info.value)

    def test_from_env_custom_prefix(self) -> None:
        """Custom prefix works."""
        env = {
            "MYCOG_DEV_REGION": "eu-west-1",
            "MYCOG_DEV_USER_POOL_ID": "eu-west-1_dev",
            "MYCOG_DEV_APP_CLIENT_ID": "client_dev",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_env("DEV", prefix="MYCOG")

        assert config.region == "eu-west-1"

    def test_from_env_multi_config_isolation(self) -> None:
        """Two configs loaded concurrently don't cross-talk."""
        env = {
            "DAYCOG_A_REGION": "us-west-2",
            "DAYCOG_A_USER_POOL_ID": "pool_a",
            "DAYCOG_A_APP_CLIENT_ID": "client_a",
            "DAYCOG_B_REGION": "eu-central-1",
            "DAYCOG_B_USER_POOL_ID": "pool_b",
            "DAYCOG_B_APP_CLIENT_ID": "client_b",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config_a = CognitoConfig.from_env("A")
            config_b = CognitoConfig.from_env("B")

        assert config_a.region == "us-west-2"
        assert config_a.user_pool_id == "pool_a"
        assert config_b.region == "eu-central-1"
        assert config_b.user_pool_id == "pool_b"


class TestCognitoConfigFromLegacyEnv:
    """Tests for CognitoConfig.from_legacy_env()."""

    def test_from_legacy_env_success(self) -> None:
        """Loads config from legacy COGNITO_* env vars."""
        env = {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "us-west-2_legacy",
            "COGNITO_APP_CLIENT_ID": "client_legacy",
            "AWS_PROFILE": "legacy-profile",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_legacy_env()

        assert config.name is None
        assert config.region == "us-west-2"
        assert config.user_pool_id == "us-west-2_legacy"
        assert config.app_client_id == "client_legacy"
        assert config.aws_profile == "legacy-profile"

    def test_from_legacy_env_region_fallback(self) -> None:
        """Region falls back to AWS_REGION then us-west-2."""
        # AWS_REGION fallback
        env = {
            "AWS_REGION": "ap-southeast-1",
            "COGNITO_USER_POOL_ID": "pool",
            "COGNITO_APP_CLIENT_ID": "client",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_legacy_env()
        assert config.region == "ap-southeast-1"

        # Default fallback
        env = {
            "COGNITO_USER_POOL_ID": "pool",
            "COGNITO_APP_CLIENT_ID": "client",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_legacy_env()
        assert config.region == "us-west-2"

    def test_from_legacy_env_client_id_fallback(self) -> None:
        """Client ID falls back to COGNITO_CLIENT_ID."""
        env = {
            "COGNITO_USER_POOL_ID": "pool",
            "COGNITO_CLIENT_ID": "fallback_client",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = CognitoConfig.from_legacy_env()
        assert config.app_client_id == "fallback_client"

    def test_from_legacy_env_missing_vars(self) -> None:
        """Missing required vars raises ValueError."""
        env = {"COGNITO_REGION": "us-west-2"}
        with mock.patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError) as exc_info:
                CognitoConfig.from_legacy_env()
        assert "COGNITO_USER_POOL_ID" in str(exc_info.value)
