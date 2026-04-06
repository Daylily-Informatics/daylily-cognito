"""CLI tests for the cli-core-yo entrypoint and flat config model."""

from __future__ import annotations

import json
import os
import runpy
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest
import typer.testing
import yaml
from cli_core_yo.app import create_app

import daylily_cognito.plugins.core as core
from daylily_cognito.spec import spec

runner = typer.testing.CliRunner()


def _make_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    return create_app(spec)


def _write_flat_config(path: Path, **overrides: str) -> dict[str, str]:
    values = {
        "COGNITO_REGION": "us-west-2",
        "COGNITO_USER_POOL_ID": "us-west-2_pool",
        "COGNITO_APP_CLIENT_ID": "client-123",
        "AWS_PROFILE": "config-profile",
        "AWS_REGION": "us-west-2",
    }
    values.update({key: value for key, value in overrides.items() if value is not None})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
    return values


def _read_yaml(path: Path) -> dict[str, str]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _mock_cognito_client() -> mock.MagicMock:
    client = mock.MagicMock()
    client.describe_user_pool.return_value = {
        "UserPool": {
            "Name": "pool-a",
            "Id": "us-west-2_pool",
            "Domain": None,
            "CustomDomain": None,
        }
    }
    client.list_user_pools.return_value = {"UserPools": []}
    client.list_user_pool_clients.return_value = {"UserPoolClients": []}
    client.create_user_pool.return_value = {"UserPool": {"Id": "us-west-2_new"}}
    client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "client-new"}}
    client.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "web-app",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthScopes": ["openid", "email", "profile"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "CallbackURLs": ["http://localhost:8001/auth/callback"],
            "LogoutURLs": ["http://localhost:8001/logout"],
            "SupportedIdentityProviders": ["COGNITO"],
            "DefaultRedirectURI": "http://localhost:8001/auth/callback",
            "PreventUserExistenceErrors": "ENABLED",
            "EnableTokenRevocation": True,
            "AuthSessionValidity": 3,
            "ReadAttributes": ["email"],
            "WriteAttributes": ["email"],
        }
    }
    client.get_paginator.return_value.paginate.return_value = [{"UserPools": []}]
    return client


def _configure_session(mock_session_cls: mock.MagicMock, client: mock.MagicMock) -> mock.MagicMock:
    session = mock.MagicMock()
    session.client.return_value = client
    mock_session_cls.return_value = session
    return session


class TestRootAndConfigFileSelection:
    def test_root_config_override_controls_builtin_config_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        override = tmp_path / "override.yaml"

        result = runner.invoke(app, ["--config", str(override), "config", "path"])

        assert result.exit_code == 0
        assert "".join(result.output.splitlines()) == str(override.resolve())

    def test_config_init_writes_flat_template_at_default_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        default_path = tmp_path / "xdg-config" / "daycog" / "config.yaml"

        result = runner.invoke(app, ["config", "init"])

        assert result.exit_code == 0
        assert default_path.exists()
        content = default_path.read_text(encoding="utf-8")
        assert "COGNITO_REGION" in content
        assert "GOOGLE_CLIENT_ID" in content
        assert "AWS_PROFILE" in content

    def test_auth_config_print_reads_flat_yaml(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "auth.yaml"
        _write_flat_config(cfg, COGNITO_CLIENT_NAME="web-app")

        result = runner.invoke(app, ["--config", str(cfg), "auth-config", "print", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["config_path"] == str(cfg.resolve())
        assert payload["values"]["COGNITO_CLIENT_NAME"] == "web-app"

    def test_auth_config_print_errors_for_missing_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "missing.yaml"

        result = runner.invoke(app, ["--config", str(cfg), "auth-config", "print"])

        assert result.exit_code == 1
        assert "Config file not found" in result.output
        assert "daycog config init" in result.output

    def test_auth_config_print_rejects_legacy_context_yaml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "legacy.yaml"
        cfg.write_text("contexts: {}\nactive_context: default\n", encoding="utf-8")

        result = runner.invoke(app, ["--config", str(cfg), "auth-config", "print"])

        assert result.exit_code == 1
        assert "Context-store YAML format is not supported" in result.output


class TestStatusAndSetup:
    @mock.patch("boto3.Session")
    def test_status_uses_config_file_profile_and_cognito_region(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "status.yaml"
        _write_flat_config(
            cfg,
            AWS_PROFILE="file-profile",
            AWS_REGION="eu-west-1",
            COGNITO_REGION="us-west-2",
            COGNITO_USER_POOL_ID="us-west-2_pool",
            COGNITO_APP_CLIENT_ID="client-123",
        )
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "status"])

        assert result.exit_code == 0
        assert "us-west-2_pool" in result.output
        assert "pool-a" in result.output
        mock_session_cls.assert_called_once_with(profile_name="file-profile", region_name="us-west-2")

    @mock.patch("boto3.Session")
    def test_setup_writes_flat_config_file(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "setup.yaml"
        client = _mock_cognito_client()
        client.list_user_pools.return_value = {"UserPools": []}
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "us-west-2_new", "Domain": None, "CustomDomain": None}
        }
        client.create_user_pool.return_value = {"UserPool": {"Id": "us-west-2_new"}}
        client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "client-new"}}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "setup", "--name", "my-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["AWS_PROFILE"] == "env-profile"
        assert stored["COGNITO_USER_POOL_ID"] == "us-west-2_new"
        assert stored["COGNITO_APP_CLIENT_ID"] == "client-new"
        assert stored["COGNITO_CLIENT_NAME"] == "my-pool-client"
        assert stored["COGNITO_DOMAIN"] == "my-pool.auth.us-west-2.amazoncognito.com"
        mock_session_cls.assert_called_once_with(profile_name="env-profile", region_name="us-west-2")
        client.create_user_pool_domain.assert_called_once_with(UserPoolId="us-west-2_new", Domain="my-pool")

    @mock.patch("boto3.Session")
    def test_setup_prefers_file_aws_values_over_env(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "setup-from-file.yaml"
        _write_flat_config(cfg, AWS_PROFILE="file-profile", AWS_REGION="us-east-1")
        client = _mock_cognito_client()
        client.list_user_pools.return_value = {"UserPools": []}
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "us-west-2_new", "Domain": None, "CustomDomain": None}
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "setup", "--name", "my-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "eu-central-1"},
        )

        assert result.exit_code == 0
        mock_session_cls.assert_called_once_with(profile_name="file-profile", region_name="us-west-2")

    @mock.patch("boto3.Session")
    def test_setup_print_exports_only_emits_aws_exports(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "exports.yaml"
        client = _mock_cognito_client()
        client.list_user_pools.return_value = {"UserPools": []}
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "us-west-2_new", "Domain": None, "CustomDomain": None}
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "setup", "--name", "my-pool", "--print-exports"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        assert 'export AWS_PROFILE="env-profile"' in result.output
        assert 'export AWS_REGION="us-west-2"' in result.output
        assert "export COGNITO_" not in result.output

    @mock.patch("boto3.Session")
    def test_setup_rejects_invalid_mfa_value(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "invalid.yaml"
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "setup", "--name", "my-pool", "--mfa", "sometimes"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Invalid --mfa value" in result.output


class TestAuthConfigCommands:
    @mock.patch("boto3.Session")
    def test_auth_config_create_creates_file_from_live_aws_state(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "created.yaml"
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}
        ]
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "us-east-1_pool", "Domain": "domain-prefix", "CustomDomain": None}
        }
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientId": "client-999", "ClientName": "web-app"}]
        }
        client.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "CallbackURLs": ["http://localhost:8001/callback"],
                "LogoutURLs": ["http://localhost:8001/logout"],
            }
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "auth-config", "create", "--pool-name", "my-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["AWS_PROFILE"] == "env-profile"
        assert stored["COGNITO_USER_POOL_ID"] == "us-east-1_pool"
        assert stored["COGNITO_APP_CLIENT_ID"] == "client-999"
        assert stored["COGNITO_CLIENT_NAME"] == "web-app"
        assert stored["COGNITO_CALLBACK_URL"] == "http://localhost:8001/callback"
        assert stored["COGNITO_LOGOUT_URL"] == "http://localhost:8001/logout"
        assert stored["COGNITO_DOMAIN"] == "domain-prefix.auth.us-east-1.amazoncognito.com"

    def test_auth_config_create_fails_when_target_file_exists(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "existing.yaml"
        _write_flat_config(cfg)

        result = runner.invoke(app, ["--config", str(cfg), "auth-config", "create", "--pool-id", "pool-123"])

        assert result.exit_code == 1
        assert "Config file already exists" in result.output

    @mock.patch("boto3.Session")
    def test_auth_config_update_merges_existing_optional_values(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "update.yaml"
        _write_flat_config(
            cfg,
            COGNITO_USER_POOL_ID="old-pool",
            COGNITO_APP_CLIENT_ID="old-client",
            GOOGLE_CLIENT_ID="keep-google-id",
            GOOGLE_CLIENT_SECRET="keep-google-secret",
            COGNITO_DOMAIN="keep.domain.example",
        )
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "my-pool", "Id": "us-west-2_pool"}]}
        ]
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "us-west-2_pool", "Domain": None, "CustomDomain": None}
        }
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientId": "updated-client", "ClientName": "atlas"}]
        }
        client.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "atlas",
                "CallbackURLs": ["https://atlas.example/callback"],
                "LogoutURLs": ["https://atlas.example/logout"],
            }
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "auth-config", "update", "--pool-name", "my-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["COGNITO_APP_CLIENT_ID"] == "updated-client"
        assert stored["COGNITO_CLIENT_NAME"] == "atlas"
        assert stored["COGNITO_CALLBACK_URL"] == "https://atlas.example/callback"
        assert stored["GOOGLE_CLIENT_ID"] == "keep-google-id"
        assert stored["GOOGLE_CLIENT_SECRET"] == "keep-google-secret"
        assert "COGNITO_DOMAIN" not in stored

    @mock.patch("boto3.Session")
    def test_auth_config_update_errors_when_multiple_clients_without_selector(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "update.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "my-pool", "Id": "us-west-2_pool"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientId": "client-a", "ClientName": "atlas"},
                {"ClientId": "client-b", "ClientName": "bloom"},
            ]
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "auth-config", "update", "--pool-name", "my-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Pool has multiple app clients" in result.output


class TestGoogleCommands:
    @mock.patch("boto3.Session")
    def test_add_google_idp_uses_google_values_from_config_file(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "google.yaml"
        _write_flat_config(cfg, GOOGLE_CLIENT_ID="gid-123", GOOGLE_CLIENT_SECRET="gsecret-456")
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "us-west-2_pool"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "web-app", "ClientId": "client-123"}]
        }
        client.describe_identity_provider.side_effect = Exception("not found")
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "add-google-idp", "--pool-name", "pool-a", "--app-name", "web-app"],
        )

        assert result.exit_code == 0
        provider_details = client.create_identity_provider.call_args.kwargs["ProviderDetails"]
        assert provider_details["client_id"] == "gid-123"
        assert provider_details["client_secret"] == "gsecret-456"
        update_kwargs = client.update_user_pool_client.call_args.kwargs
        assert "Google" in update_kwargs["SupportedIdentityProviders"]

    @mock.patch("boto3.Session")
    def test_setup_with_google_writes_google_keys_to_config(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "setup-google.yaml"
        client = _mock_cognito_client()
        client.list_user_pools.return_value = {"UserPools": []}
        client.create_user_pool.return_value = {"UserPool": {"Id": "us-east-1_new"}}
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "pool-a", "Id": "us-east-1_new", "Domain": None, "CustomDomain": None}
        }
        client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "client-new"}}
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "us-east-1_new"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "web-app", "ClientId": "client-new"}]
        }
        client.describe_identity_provider.side_effect = Exception("not found")
        client.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/auth/callback"],
                "LogoutURLs": [],
                "SupportedIdentityProviders": ["COGNITO"],
                "DefaultRedirectURI": "http://localhost:8001/auth/callback",
                "PreventUserExistenceErrors": "ENABLED",
                "EnableTokenRevocation": True,
            }
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "setup-with-google",
                "--name",
                "pool-a",
                "--client-name",
                "web-app",
                "--google-client-id",
                "gid-123",
                "--google-client-secret",
                "gsecret-456",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["GOOGLE_CLIENT_ID"] == "gid-123"
        assert stored["GOOGLE_CLIENT_SECRET"] == "gsecret-456"
        assert "Setup with Google IdP complete" in result.output

    def test_setup_google_writes_google_credentials_into_existing_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "google-only.yaml"
        _write_flat_config(cfg)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "setup-google",
                "--client-id",
                "gid-123",
                "--client-secret",
                "gsecret-456",
            ],
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["GOOGLE_CLIENT_ID"] == "gid-123"
        assert stored["GOOGLE_CLIENT_SECRET"] == "gsecret-456"


class TestFlagDrivenAwsCommands:
    @mock.patch("boto3.Session")
    def test_list_pools_lists_user_pools(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "pool-a-id"}, {"Name": "pool-b", "Id": "pool-b-id"}]}
        ]
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["list-pools"], env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"})

        assert result.exit_code == 0
        assert "pool-a" in result.output
        assert "pool-b" in result.output
        mock_session_cls.assert_called_once_with(profile_name="env-profile", region_name="us-east-1")

    @mock.patch("boto3.Session")
    def test_list_apps_lists_clients(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "pool-a-id"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientName": "app-1", "ClientId": "cid-1"},
                {"ClientName": "app-2", "ClientId": "cid-2"},
            ]
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["list-apps", "--pool-name", "pool-a"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        assert "app-1" in result.output
        assert "app-2" in result.output

    @mock.patch("boto3.Session")
    def test_add_app_set_default_only_prompts_for_manual_config_refresh(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "existing-config.yaml"
        before = _write_flat_config(cfg, COGNITO_APP_CLIENT_ID="existing-client", COGNITO_CLIENT_NAME="existing-app")
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "pool-a-id"}]}
        ]
        client.list_user_pool_clients.return_value = {"UserPoolClients": []}
        client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "new-client"}}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "add-app",
                "--pool-name",
                "pool-a",
                "--app-name",
                "new-app",
                "--callback-url",
                "http://localhost:8001/callback",
                "--set-default",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        assert "Run daycog auth-config update" in result.output
        assert _read_yaml(cfg)["COGNITO_APP_CLIENT_ID"] == before["COGNITO_APP_CLIENT_ID"]

    @mock.patch("boto3.Session")
    def test_edit_app_set_default_only_prompts_for_manual_config_refresh(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "existing-config.yaml"
        before = _write_flat_config(cfg, COGNITO_APP_CLIENT_ID="existing-client", COGNITO_CLIENT_NAME="existing-app")
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "pool-a-id"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "edit-app",
                "--pool-name",
                "pool-a",
                "--app-name",
                "web-app",
                "--new-app-name",
                "web-app-v2",
                "--callback-url",
                "http://localhost:9000/callback",
                "--set-default",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        assert "Run daycog auth-config update" in result.output
        assert _read_yaml(cfg)["COGNITO_APP_CLIENT_ID"] == before["COGNITO_APP_CLIENT_ID"]

    @mock.patch("boto3.Session")
    def test_remove_app_reports_config_file_noop(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "pool-a-id"}]}
        ]
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["remove-app", "--pool-name", "pool-a", "--app-name", "web-app", "--force"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-east-1"},
        )

        assert result.exit_code == 0
        assert "Config files are no longer updated by remove-app" in result.output


class TestConfigBackedUserManagement:
    @mock.patch("boto3.Session")
    def test_fix_auth_flows_uses_pool_and_client_from_config(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "fix.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "fix-auth-flows"])

        assert result.exit_code == 0
        kwargs = client.update_user_pool_client.call_args.kwargs
        assert kwargs["UserPoolId"] == "us-west-2_pool"
        assert kwargs["ClientId"] == "client-123"

    @mock.patch("boto3.Session")
    def test_set_password_uses_pool_from_config(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "set-password.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "set-password", "--email", "u@example.com", "--password", "Secret123"],
        )

        assert result.exit_code == 0
        client.admin_set_user_password.assert_called_once_with(
            UserPoolId="us-west-2_pool",
            Username="u@example.com",
            Password="Secret123",
            Permanent=True,
        )

    @mock.patch("boto3.Session")
    def test_add_user_generates_password_and_uses_pool_from_config(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "add-user.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "add-user", "new@example.com"])

        assert result.exit_code == 0
        assert "Temporary password" in result.output
        kwargs = client.admin_create_user.call_args.kwargs
        assert kwargs["UserPoolId"] == "us-west-2_pool"
        assert kwargs["Username"] == "new@example.com"

    @mock.patch("boto3.Session")
    def test_export_users_writes_json_export(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "export.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [
            {
                "Users": [
                    {
                        "Username": "a@x.com",
                        "UserStatus": "CONFIRMED",
                        "Enabled": True,
                        "UserCreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                        "UserLastModifiedDate": datetime(2024, 1, 2, tzinfo=timezone.utc),
                        "Attributes": [{"Name": "email", "Value": "a@x.com"}],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        _configure_session(mock_session_cls, client)
        out_file = tmp_path / "users.json"

        result = runner.invoke(app, ["--config", str(cfg), "export", "--output", str(out_file)])

        assert result.exit_code == 0
        payload = json.loads(out_file.read_text(encoding="utf-8"))
        assert payload["user_count"] == 1
        assert payload["users"][0]["username"] == "a@x.com"
        assert payload["region"] == "us-west-2"

    @mock.patch("boto3.Session")
    def test_delete_user_delete_all_users_and_teardown_use_config_file(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "destructive.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"Users": [{"Username": "u1@x.com"}, {"Username": "u2@x.com"}]}]
        client.get_paginator.return_value = paginator
        _configure_session(mock_session_cls, client)

        delete_result = runner.invoke(
            app,
            ["--config", str(cfg), "delete-user", "--email", "u1@x.com", "--force"],
        )
        delete_all_result = runner.invoke(app, ["--config", str(cfg), "delete-all-users", "--force"])
        teardown_result = runner.invoke(app, ["--config", str(cfg), "teardown", "--force"])

        assert delete_result.exit_code == 0
        assert delete_all_result.exit_code == 0
        assert teardown_result.exit_code == 0
        assert client.admin_delete_user.call_count >= 3
        client.delete_user_pool.assert_called_once_with(UserPoolId="us-west-2_pool")


class TestEntrypointAndHelpers:
    def test_cli_module_main_exits_via_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        exit_info: dict[str, int] = {}

        def _fake_exit(code: int) -> None:
            exit_info["code"] = code
            raise SystemExit(code)

        monkeypatch.setattr("cli_core_yo.app.run", lambda passed_spec: 7)
        monkeypatch.setattr(sys, "exit", _fake_exit)
        monkeypatch.setattr(sys, "argv", ["daycog"])

        with pytest.raises(SystemExit) as exc:
            runpy.run_module("daylily_cognito.cli", run_name="__main__")

        assert exc.value.code == 7
        assert exit_info["code"] == 7

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"}, clear=True)
    def test_resolve_profile_region_prefers_flags(self) -> None:
        assert core._resolve_profile_region("flag-profile", "us-east-1") == ("flag-profile", "us-east-1")

    def test_parse_tags_and_resolve_mfa_validation(self) -> None:
        assert core._parse_tags("env=dev,owner=team") == {"env": "dev", "owner": "team"}
        with pytest.raises(Exception):
            core._parse_tags("invalid")
        assert core._resolve_mfa_configuration("required") == "ON"
        with pytest.raises(Exception):
            core._resolve_mfa_configuration("sometimes")

    def test_resolve_google_client_details_reads_json_file(self, tmp_path: Path) -> None:
        path = tmp_path / "google-client.json"
        path.write_text(json.dumps({"web": {"client_id": "gid123", "client_secret": "gsec456"}}), encoding="utf-8")

        assert core._resolve_google_client_details(
            google_client_id=None,
            google_client_secret=None,
            google_client_json=str(path),
        ) == ("gid123", "gsec456")

    def test_find_pool_id_and_client_helpers_fail_cleanly(self) -> None:
        cognito = mock.MagicMock()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"UserPools": [{"Name": "other-pool", "Id": "pool-999"}]}]
        cognito.get_paginator.return_value = paginator

        with pytest.raises(Exception):
            core._find_pool_id_by_name(cognito, "wanted-pool")

        cognito.list_user_pool_clients.return_value = {"UserPoolClients": []}
        with pytest.raises(Exception):
            core._find_client(cognito, "pool-123", client_name="web-app")
