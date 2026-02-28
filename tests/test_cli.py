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
    def test_setup_creates_pool_and_client(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["setup", "--name", "my-pool"])
        assert result.exit_code == 0
        assert "new-cid" in result.output
        assert "Profile: test-profile" in result.output
        assert "Region: us-west-2" in result.output
        mock_boto_client.assert_called_once_with("cognito-idp", region_name="us-west-2")
        mc.create_user_pool.assert_called_once()
        mc.create_user_pool_client.assert_called_once()

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
    def test_setup_flags_override_env_and_set_process_env(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
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
