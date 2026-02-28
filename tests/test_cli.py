"""Tests for daylily_cognito CLI (cli.py)."""

from __future__ import annotations

import json
import os
from unittest import mock

import typer.testing

from daylily_cognito.cli import cognito_app

runner = typer.testing.CliRunner()

# Common env vars for tests (all lazy-imported boto3 calls need to be mocked separately)
_BASE_ENV = {
    "AWS_PROFILE": "test-profile",
    "AWS_REGION": "us-west-2",
    "COGNITO_USER_POOL_ID": "us-west-2_TestPool",
    "COGNITO_APP_CLIENT_ID": "test-client-id",
    "COGNITO_REGION": "us-west-2",
}


def _mock_cognito_client() -> mock.MagicMock:
    """Return a pre-configured mock cognito-idp client."""
    client = mock.MagicMock()
    # Defaults — tests override as needed
    client.describe_user_pool.return_value = {"UserPool": {"Name": "test-pool", "Id": "us-west-2_TestPool"}}
    client.list_user_pools.return_value = {"UserPools": []}
    client.list_user_pool_clients.return_value = {"UserPoolClients": []}
    client.create_user_pool.return_value = {"UserPool": {"Id": "us-west-2_New"}}
    client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "new-cid"}}
    client.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "test",
            "ReadAttributes": ["email"],
            "WriteAttributes": ["email"],
        }
    }
    # Paginator helper
    mock_paginator = mock.MagicMock()
    mock_paginator.paginate.return_value = [{"Users": []}]
    client.get_paginator.return_value = mock_paginator
    return client


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatusCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_status_shows_pool_info(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["status"])
        assert result.exit_code == 0
        assert "us-west-2_TestPool" in result.output


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------


class TestSetupCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_creates_pool_and_client(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["setup", "--name", "my-pool"])
        assert result.exit_code == 0
        assert "new-cid" in result.output
        assert "Profile: test-profile" in result.output
        assert "Region: us-west-2" in result.output
        normalized = result.output.replace("\n", "")
        assert str(tmp_path / ".config" / "daycog" / "default.env") in normalized
        mock_boto_client.assert_called_once_with("cognito-idp", region_name="us-west-2")
        mc.create_user_pool.assert_called_once()
        mc.create_user_pool_client.assert_called_once()
        assert (tmp_path / ".config" / "daycog" / "my-pool.us-west-2.env").exists()
        assert (tmp_path / ".config" / "daycog" / "default.env").exists()
        content = (tmp_path / ".config" / "daycog" / "default.env").read_text(encoding="utf-8")
        assert "COGNITO_CALLBACK_URL=http://localhost:8001/auth/callback" in content

    @mock.patch.dict(
        os.environ,
        {
            "COGNITO_USER_POOL_ID": "us-west-2_TestPool",
            "COGNITO_APP_CLIENT_ID": "test-client-id",
        },
        clear=True,
    )
    def test_setup_errors_when_aws_profile_or_region_missing(self) -> None:
        result = runner.invoke(cognito_app, ["setup"])
        assert result.exit_code == 1
        assert "AWS profile not set" in result.output

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_flags_override_env_and_set_process_env(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["setup", "--name", "my-pool", "--profile", "flag-profile", "--region", "us-east-1"],
            )
        assert result.exit_code == 0
        assert "Profile: flag-profile" in result.output
        assert "Region: us-east-1" in result.output
        mock_boto_client.assert_called_once_with("cognito-idp", region_name="us-east-1")
        assert os.environ["AWS_PROFILE"] == "flag-profile"
        assert os.environ["AWS_REGION"] == "us-east-1"

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_print_exports_outputs_shell_exports(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["setup", "--name", "my-pool", "--profile", "flag-profile", "--region", "us-east-1", "--print-exports"],
            )
        assert result.exit_code == 0
        assert 'export AWS_PROFILE="flag-profile"' in result.output
        assert 'export AWS_REGION="us-east-1"' in result.output
        assert 'export COGNITO_REGION="us-east-1"' in result.output
        assert 'export COGNITO_USER_POOL_ID="us-west-2_New"' in result.output
        assert 'export COGNITO_APP_CLIENT_ID="new-cid"' in result.output
        assert 'export COGNITO_CALLBACK_URL="http://localhost:8001/auth/callback"' in result.output

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_accepts_advanced_creation_flags(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "setup",
                    "--name",
                    "my-pool",
                    "--client-name",
                    "my-client",
                    "--callback-path",
                    "/cb",
                    "--logout-url",
                    "http://localhost:8001/logout",
                    "--generate-secret",
                    "--oauth-flows",
                    "code,implicit",
                    "--scopes",
                    "openid,email",
                    "--idp",
                    "COGNITO,Google",
                    "--password-min-length",
                    "12",
                    "--no-require-symbols",
                    "--mfa",
                    "optional",
                    "--tags",
                    "env=dev,owner=team",
                ],
            )
        assert result.exit_code == 0
        pool_kwargs = mc.create_user_pool.call_args.kwargs
        assert pool_kwargs["MfaConfiguration"] == "OPTIONAL"
        assert pool_kwargs["Policies"]["PasswordPolicy"]["MinimumLength"] == 12
        assert pool_kwargs["Policies"]["PasswordPolicy"]["RequireUppercase"] is True
        assert pool_kwargs["Policies"]["PasswordPolicy"]["RequireLowercase"] is True
        assert pool_kwargs["Policies"]["PasswordPolicy"]["RequireNumbers"] is True
        assert pool_kwargs["Policies"]["PasswordPolicy"]["RequireSymbols"] is False
        assert pool_kwargs["UserPoolTags"] == {"env": "dev", "owner": "team"}

        client_kwargs = mc.create_user_pool_client.call_args.kwargs
        assert client_kwargs["ClientName"] == "my-client"
        assert client_kwargs["GenerateSecret"] is True
        assert client_kwargs["AllowedOAuthFlows"] == ["code", "implicit"]
        assert client_kwargs["AllowedOAuthScopes"] == ["openid", "email"]
        assert client_kwargs["SupportedIdentityProviders"] == ["COGNITO", "Google"]
        assert client_kwargs["CallbackURLs"] == ["http://localhost:8001/cb"]
        assert client_kwargs["LogoutURLs"] == ["http://localhost:8001/logout"]

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_autoprovision_reuses_existing_client(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "my-client", "ClientId": "existing-cid"}]
        }
        mock_boto_client.return_value = mc

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["setup", "--name", "my-pool", "--client-name", "my-client", "--autoprovision"],
            )

        assert result.exit_code == 0
        assert "Reusing app client 'my-client': existing-cid" in result.output
        mc.create_user_pool_client.assert_not_called()

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_callback_url_overrides_port_and_path(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "setup",
                    "--name",
                    "my-pool",
                    "--callback-url",
                    "https://example.com/custom-callback",
                    "--callback-path",
                    "/ignored",
                    "--port",
                    "9999",
                ],
            )
        assert result.exit_code == 0
        client_kwargs = mc.create_user_pool_client.call_args.kwargs
        assert client_kwargs["CallbackURLs"] == ["https://example.com/custom-callback"]

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_invalid_mfa_value_errors(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["setup", "--name", "my-pool", "--mfa", "invalid"])
        assert result.exit_code == 1
        assert "Invalid --mfa value" in result.output

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_invalid_tags_errors(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["setup", "--name", "my-pool", "--tags", "invalidtag"])
        assert result.exit_code == 1
        assert "Invalid tag format" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


class TestConfigCommand:
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_shows_default_path(self, tmp_path) -> None:
        cfg_path = tmp_path / ".config" / "daycog" / "default.env"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("AWS_PROFILE=from-file\n", encoding="utf-8")
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print"])
        assert result.exit_code == 0
        normalized = result.output.replace("\n", "")
        assert str(tmp_path / ".config" / "daycog" / "default.env") in normalized
        assert "AWS_PROFILE=from-file" in result.output

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_accepts_pool_name(self, tmp_path) -> None:
        cfg_path = tmp_path / ".config" / "daycog" / "my-pool.us-west-2.env"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("COGNITO_USER_POOL_ID=pool_id\n", encoding="utf-8")
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print", "--pool-name", "my-pool", "--region", "us-west-2"])
        assert result.exit_code == 0
        assert "COGNITO_USER_POOL_ID=pool_id" in result.output

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_accepts_poor_name_alias(self, tmp_path) -> None:
        cfg_path = tmp_path / ".config" / "daycog" / "my-pool.us-west-2.env"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("AWS_REGION=us-west-2\n", encoding="utf-8")
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print", "--poor-name", "my-pool", "--region", "us-west-2"])
        assert result.exit_code == 0
        assert "AWS_REGION=us-west-2" in result.output

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_pool_name_requires_region(self) -> None:
        result = runner.invoke(cognito_app, ["config", "print", "--pool-name", "my-pool"])
        assert result.exit_code == 1
        assert "--region is required" in result.output

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_writes_and_prints_contents(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        cfg_path = tmp_path / ".config" / "daycog" / "my-pool.us-east-1.env"
        default_path = tmp_path / ".config" / "daycog" / "default.env"
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "client_123"}]}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "create", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        normalized = result.output.replace("\n", "")
        assert str(cfg_path) in normalized
        assert str(default_path) in normalized
        assert "AWS_PROFILE=dev-prof" in result.output
        assert "AWS_REGION=us-east-1" in result.output
        assert "COGNITO_USER_POOL_ID=us-east-1_pool" in result.output
        assert "COGNITO_APP_CLIENT_ID=client_123" in result.output
        assert cfg_path.exists()
        assert default_path.exists()
        mock_session_cls.assert_called_once_with(profile_name="dev-prof", region_name="us-east-1")

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "new-prof",
            "AWS_REGION": "us-west-2",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_update_merges_existing_and_known_values(
        self, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
        pool_path = tmp_path / ".config" / "daycog" / "my-pool.us-west-2.env"
        default_path = tmp_path / ".config" / "daycog" / "default.env"
        pool_path.parent.mkdir(parents=True, exist_ok=True)
        pool_path.write_text("GOOGLE_CLIENT_ID=keepme\n", encoding="utf-8")
        default_path.write_text("COGNITO_DOMAIN=example-domain\n", encoding="utf-8")

        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-west-2_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "updated-client"}]}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "update", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        pool_content = pool_path.read_text(encoding="utf-8")
        default_content = default_path.read_text(encoding="utf-8")
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in pool_content
        assert "COGNITO_APP_CLIENT_ID=updated-client" in pool_content
        assert "AWS_PROFILE=new-prof" in pool_content
        assert "AWS_REGION=us-west-2" in pool_content
        assert "GOOGLE_CLIENT_ID=keepme" in pool_content
        assert "COGNITO_DOMAIN=example-domain" in default_content
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in default_content

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_create_requires_pool_name(self) -> None:
        result = runner.invoke(cognito_app, ["config", "create"])
        assert result.exit_code != 0

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_errors_when_pool_not_found(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": []}]
        mc.get_paginator.return_value = mock_paginator
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "create", "--pool-name", "missing"])
        assert result.exit_code == 1
        assert "Pool not found: missing" in result.output

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_update_warns_when_multiple_clients(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientId": "client_1", "ClientName": "a"},
                {"ClientId": "client_2", "ClientName": "b"},
            ]
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "update", "--pool-name", "my-pool"])
        assert result.exit_code == 0
        assert "using first: client_1" in result.output


# ---------------------------------------------------------------------------
# list-pools
# ---------------------------------------------------------------------------


class TestListPoolsCommand:
    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_list_pools_lists_pools_for_region(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [
            {"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}, {"Name": "pool-b", "Id": "us-east-1_B"}]}
        ]
        mc.get_paginator.return_value = mock_paginator
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(cognito_app, ["list-pools"])
        assert result.exit_code == 0
        assert "pool-a" in result.output
        assert "pool-b" in result.output
        assert "Total: 2 pools" in result.output
        mock_session_cls.assert_called_once_with(profile_name="p", region_name="us-east-1")

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_list_pools_requires_profile_and_region(self) -> None:
        result = runner.invoke(cognito_app, ["list-pools"])
        assert result.exit_code == 1
        assert "AWS profile not set" in result.output


# ---------------------------------------------------------------------------
# app clients
# ---------------------------------------------------------------------------


class TestAppClientCommands:
    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_list_apps_lists_app_clients(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "app1", "ClientId": "cid1"}, {"ClientName": "app2", "ClientId": "cid2"}]
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(cognito_app, ["list-apps", "--pool-name", "pool-a"])
        assert result.exit_code == 0
        assert "app1" in result.output
        assert "app2" in result.output
        assert "Total: 2 app clients" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_add_app_creates_app_and_app_env_file(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": []}
        mc.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "cid-new"}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "add-app",
                    "--pool-name",
                    "pool-a",
                    "--app-name",
                    "web-app",
                    "--callback-url",
                    "http://localhost:8001/callback",
                    "--set-default",
                ],
            )

        assert result.exit_code == 0
        assert "Created app client: web-app (cid-new)" in result.output
        app_path = tmp_path / ".config" / "daycog" / "pool-a.us-east-1.web-app.env"
        assert app_path.exists()
        app_content = app_path.read_text(encoding="utf-8")
        assert "COGNITO_APP_CLIENT_ID=cid-new" in app_content
        assert "COGNITO_CLIENT_NAME=web-app" in app_content

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_edit_app_updates_client(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]}
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/callback"],
                "LogoutURLs": ["http://localhost:8001/logout"],
                "SupportedIdentityProviders": ["COGNITO"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "edit-app",
                    "--pool-name",
                    "pool-a",
                    "--app-name",
                    "web-app",
                    "--new-app-name",
                    "web-app-v2",
                    "--callback-url",
                    "http://localhost:9000/callback",
                ],
            )

        assert result.exit_code == 0
        mc.update_user_pool_client.assert_called_once()
        kwargs = mc.update_user_pool_client.call_args.kwargs
        assert kwargs["ClientName"] == "web-app-v2"
        assert kwargs["CallbackURLs"] == ["http://localhost:9000/callback"]
        assert "Updated app client: web-app-v2 (cid-1)" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_remove_app_deletes_client_and_config(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        app_path = tmp_path / ".config" / "daycog" / "pool-a.us-east-1.web-app.env"
        app_path.parent.mkdir(parents=True, exist_ok=True)
        app_path.write_text("COGNITO_APP_CLIENT_ID=cid-1\n", encoding="utf-8")

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["remove-app", "--pool-name", "pool-a", "--app-name", "web-app", "--force"],
            )

        assert result.exit_code == 0
        mc.delete_user_pool_client.assert_called_once_with(UserPoolId="us-east-1_A", ClientId="cid-1")
        assert not app_path.exists()


# ---------------------------------------------------------------------------
# add-google-idp
# ---------------------------------------------------------------------------


class TestAddGoogleIdpCommand:
    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_add_google_idp_creates_idp_from_json(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]}
        mc.describe_identity_provider.side_effect = Exception("not found")
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/auth/callback"],
                "LogoutURLs": ["http://localhost:8001/"],
                "SupportedIdentityProviders": ["COGNITO"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        json_path = tmp_path / "google-client.json"
        json_path.write_text(
            '{"web":{"client_id":"gid-123","client_secret":"gsecret-456"}}',
            encoding="utf-8",
        )

        result = runner.invoke(
            cognito_app,
            [
                "add-google-idp",
                "--pool-name",
                "pool-a",
                "--app-name",
                "web-app",
                "--google-client-json",
                str(json_path),
            ],
        )

        assert result.exit_code == 0
        mc.create_identity_provider.assert_called_once()
        create_kwargs = mc.create_identity_provider.call_args.kwargs
        assert create_kwargs["ProviderDetails"]["client_id"] == "gid-123"
        assert create_kwargs["ProviderDetails"]["client_secret"] == "gsecret-456"
        mc.update_user_pool_client.assert_called_once()
        update_kwargs = mc.update_user_pool_client.call_args.kwargs
        assert "Google" in update_kwargs["SupportedIdentityProviders"]

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "p",
            "AWS_REGION": "us-east-1",
            "GOOGLE_CLIENT_ID": "env-gid",
            "GOOGLE_CLIENT_SECRET": "env-secret",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_add_google_idp_updates_existing_idp(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-1"}]}
        mc.describe_identity_provider.return_value = {"IdentityProvider": {"ProviderName": "Google"}}
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/auth/callback"],
                "LogoutURLs": [],
                "SupportedIdentityProviders": ["COGNITO", "Google"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(
            cognito_app,
            [
                "add-google-idp",
                "--pool-name",
                "pool-a",
                "--app-name",
                "web-app",
            ],
        )
        assert result.exit_code == 0
        mc.update_identity_provider.assert_called_once()
        mc.create_identity_provider.assert_not_called()


# ---------------------------------------------------------------------------
# delete-pool
# ---------------------------------------------------------------------------


class TestDeletePoolCommand:
    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_by_name_with_force(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "pool-a", "Domain": None, "CustomDomain": None}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(cognito_app, ["delete-pool", "--pool-name", "pool-a", "--force"])
        assert result.exit_code == 0
        mc.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_A")
        assert "Deleted Cognito pool: pool-a (us-east-1_A)" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_by_id_with_force(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "pool-b", "Domain": None, "CustomDomain": None}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(cognito_app, ["delete-pool", "--pool-id", "us-east-1_B", "--force"])
        assert result.exit_code == 0
        mc.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_B")
        assert "Deleted Cognito pool: pool-b (us-east-1_B)" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    def test_delete_pool_requires_name_or_id(self) -> None:
        result = runner.invoke(cognito_app, ["delete-pool", "--force"])
        assert result.exit_code == 1
        assert "Provide one of" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_cancelled_without_force(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "pool-a", "Domain": None, "CustomDomain": None}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session
        result = runner.invoke(cognito_app, ["delete-pool", "--pool-name", "pool-a"], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.output
        mc.delete_user_pool.assert_not_called()

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_delete_domain_first(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.side_effect = [
            {"UserPool": {"Name": "pool-a", "Domain": "pool-a-domain", "CustomDomain": None}},
            {"UserPool": {"Name": "pool-a", "Domain": None, "CustomDomain": None}},
        ]
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(
            cognito_app, ["delete-pool", "--pool-name", "pool-a", "--force", "--delete-domain-first"]
        )
        assert result.exit_code == 0
        mc.delete_user_pool_domain.assert_called_once_with(UserPoolId="us-east-1_A", Domain="pool-a-domain")
        mc.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_A")

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_delete_domain_first_no_domain(self, mock_session_cls: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "pool-a", "Domain": None, "CustomDomain": None}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        result = runner.invoke(
            cognito_app, ["delete-pool", "--pool-name", "pool-a", "--force", "--delete-domain-first"]
        )
        assert result.exit_code == 0
        mc.delete_user_pool_domain.assert_not_called()
        mc.delete_user_pool.assert_called_once_with(UserPoolId="us-east-1_A")


# ---------------------------------------------------------------------------
# fix-auth-flows
# ---------------------------------------------------------------------------


class TestFixAuthFlowsCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_fix_auth_flows_updates_client(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["fix-auth-flows"])
        assert result.exit_code == 0
        mc.update_user_pool_client.assert_called_once()
        assert "ALLOW_ADMIN_USER_PASSWORD_AUTH" in result.output


# ---------------------------------------------------------------------------
# set-password
# ---------------------------------------------------------------------------


class TestSetPasswordCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_set_password_calls_admin(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["set-password", "--email", "u@x.com", "--password", "P@ss1234"])
        assert result.exit_code == 0
        mc.admin_set_user_password.assert_called_once()
        assert "u@x.com" in result.output


# ---------------------------------------------------------------------------
# add-user
# ---------------------------------------------------------------------------


class TestAddUserCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_add_user_creates_user(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["add-user", "new@example.com", "--password", "Secure1234"])
        assert result.exit_code == 0
        mc.admin_create_user.assert_called_once()
        assert "new@example.com" in result.output


# ---------------------------------------------------------------------------
# list-users
# ---------------------------------------------------------------------------


class TestListUsersCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_list_users_shows_table(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        # Override paginator to return one user
        mock_pag = mock.MagicMock()
        mock_pag.paginate.return_value = [
            {
                "Users": [
                    {
                        "Username": "a@x.com",
                        "Attributes": [{"Name": "email", "Value": "a@x.com"}],
                        "UserStatus": "CONFIRMED",
                        "Enabled": True,
                        "UserCreateDate": None,
                    }
                ]
            }
        ]
        mc.get_paginator.return_value = mock_pag
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["list-users"])
        assert result.exit_code == 0
        assert "a@x.com" in result.output


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


class TestExportCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_export_writes_file(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_pag = mock.MagicMock()
        mock_pag.paginate.return_value = [
            {
                "Users": [
                    {
                        "Username": "a@x.com",
                        "Attributes": [{"Name": "email", "Value": "a@x.com"}],
                        "UserStatus": "CONFIRMED",
                        "Enabled": True,
                        "UserCreateDate": None,
                        "UserLastModifiedDate": None,
                    }
                ]
            }
        ]
        mc.get_paginator.return_value = mock_pag
        mock_boto_client.return_value = mc

        out_file = str(tmp_path / "export.json")
        result = runner.invoke(cognito_app, ["export", "--output", out_file])
        assert result.exit_code == 0
        data = json.loads(open(out_file).read())
        assert data["user_count"] == 1
        assert data["users"][0]["username"] == "a@x.com"


# ---------------------------------------------------------------------------
# delete-user
# ---------------------------------------------------------------------------


class TestDeleteUserCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_delete_user_with_force(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["delete-user", "--email", "u@x.com", "--force"])
        assert result.exit_code == 0
        mc.admin_delete_user.assert_called_once()
        assert "Deleted" in result.output


# ---------------------------------------------------------------------------
# delete-all-users
# ---------------------------------------------------------------------------


class TestDeleteAllUsersCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_delete_all_users_with_force(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_pag = mock.MagicMock()
        mock_pag.paginate.return_value = [{"Users": [{"Username": "u1@x.com"}, {"Username": "u2@x.com"}]}]
        mc.get_paginator.return_value = mock_pag
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["delete-all-users", "--force"])
        assert result.exit_code == 0
        assert mc.admin_delete_user.call_count == 2


# ---------------------------------------------------------------------------
# teardown
# ---------------------------------------------------------------------------


class TestTeardownCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_teardown_with_force(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["teardown", "--force"])
        assert result.exit_code == 0
        mc.delete_user_pool.assert_called_once_with(UserPoolId="us-west-2_TestPool")


# ---------------------------------------------------------------------------
# setup-google
# ---------------------------------------------------------------------------


class TestSetupGoogleCommand:
    def test_setup_google_prints_env_vars(self) -> None:
        result = runner.invoke(
            cognito_app,
            ["setup-google", "--client-id", "gid123", "--client-secret", "gsec456"],
        )
        assert result.exit_code == 0
        assert "gid123" in result.output
        assert "gsec456" in result.output
        assert "GOOGLE_CLIENT_ID" in result.output


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    def test_main_is_callable(self) -> None:
        from daylily_cognito.cli import main

        assert callable(main)

    def test_help_flag(self) -> None:
        result = runner.invoke(cognito_app, ["--help"])
        assert result.exit_code == 0
        assert "Cognito" in result.output
