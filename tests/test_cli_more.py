"""Additional CLI and helper coverage for the current daycog surface."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import typer
import typer.testing
import yaml
from cli_core_yo.app import create_app

import daylily_cognito.plugins.core as core
from daylily_cognito.config import ConfigError
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


def _set_active_config(monkeypatch: pytest.MonkeyPatch, path: Path | None) -> None:
    monkeypatch.setattr("daylily_cognito.config.get_context", lambda: SimpleNamespace(config_path=path))


class TestHelperCoverage:
    def test_resolve_profile_region_errors_without_required_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        monkeypatch.delenv("AWS_REGION", raising=False)

        with pytest.raises(Exception):
            core._resolve_profile_region(None, "us-west-2")

        with pytest.raises(Exception):
            core._resolve_profile_region("dev-profile", None)

    def test_callback_domain_pool_and_client_helpers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert core._resolve_callback_url("https://example.test/callback", 8001, "/ignored") == "https://example.test/callback"
        assert core._resolve_cognito_domain({"CustomDomain": "custom.example.test"}, "us-west-2") == "custom.example.test"
        assert (
            core._resolve_cognito_domain({"CustomDomain": {"DomainName": "dict.example.test"}}, "us-west-2")
            == "dict.example.test"
        )

        cognito = mock.MagicMock()
        cognito.describe_user_pool.return_value = {"UserPool": {"Name": "real-pool", "Id": "pool-123"}}

        with pytest.raises(Exception):
            core._resolve_pool(cognito)

        with pytest.raises(Exception):
            core._resolve_pool(cognito, pool_name="wrong-pool", pool_id="pool-123")

        with pytest.raises(Exception):
            core._select_config_client(cognito, "pool-123", client_name="web", client_id="cid-1")

        monkeypatch.setattr(core, "_list_pool_clients", lambda *_args, **_kwargs: [])
        assert core._select_config_client(cognito, "pool-123") is None

        monkeypatch.setattr(core, "_list_pool_clients", lambda *_args, **_kwargs: [{"ClientId": "cid-1", "ClientName": "web"}])
        monkeypatch.setattr(
            core,
            "_describe_client",
            lambda *_args, **_kwargs: {"client_id": "cid-1", "client_name": "web"},
        )
        assert core._select_config_client(cognito, "pool-123") == {"client_id": "cid-1", "client_name": "web"}

        monkeypatch.setattr(
            core,
            "_list_pool_clients",
            lambda *_args, **_kwargs: [
                {"ClientId": "cid-1", "ClientName": "web"},
                {"ClientId": "cid-2", "ClientName": "admin"},
            ],
        )
        with pytest.raises(Exception):
            core._select_config_client(cognito, "pool-123")

    def test_resolve_google_client_details_reads_config_and_handles_errors(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        cfg = tmp_path / "config.yaml"
        _write_flat_config(cfg, GOOGLE_CLIENT_ID="gid-123", GOOGLE_CLIENT_SECRET="gsecret-456")
        _set_active_config(monkeypatch, cfg)

        assert core._resolve_google_client_details(
            google_client_id=None,
            google_client_secret=None,
            google_client_json=None,
        ) == ("gid-123", "gsecret-456")

        bad_json = tmp_path / "bad-google.json"
        bad_json.write_text("{", encoding="utf-8")
        with pytest.raises(Exception):
            core._resolve_google_client_details(
                google_client_id=None,
                google_client_secret=None,
                google_client_json=str(bad_json),
            )

        missing = tmp_path / "missing.yaml"
        _set_active_config(monkeypatch, missing)
        with pytest.raises(Exception):
            core._resolve_google_client_details(
                google_client_id=None,
                google_client_secret=None,
                google_client_json=None,
            )

    def test_runtime_helpers_wrap_config_errors(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        cfg = tmp_path / "active.yaml"
        _set_active_config(monkeypatch, cfg)

        with pytest.raises(SystemExit) as exc_info:
            core._handle_config_error(ConfigError("boom"))
        assert exc_info.value.code == 1

        monkeypatch.setattr(core, "load_config_file_if_present", mock.Mock(side_effect=ConfigError("bad config")))
        with pytest.raises(SystemExit):
            core._get_existing_config_values()

        monkeypatch.setattr(core, "resolve_runtime_config", mock.Mock(side_effect=ConfigError("no runtime")))
        with pytest.raises(SystemExit):
            core._get_runtime_config()

        runtime = SimpleNamespace(
            values={},
            aws_profile=None,
            aws_region="us-west-2",
            require_aws_profile=mock.Mock(side_effect=ConfigError("missing profile")),
        )
        monkeypatch.setattr(core, "resolve_runtime_config", mock.Mock(return_value=runtime))
        with pytest.raises(SystemExit):
            core._get_runtime_config(require_profile=True)

        monkeypatch.setattr(core, "_get_runtime_config", mock.Mock(return_value=SimpleNamespace(values={})))
        with pytest.raises(SystemExit):
            core._get_pool_id()
        with pytest.raises(SystemExit):
            core._get_client_id()

    def test_parse_attributes_validation(self) -> None:
        assert core._parse_attributes(["custom:tenant=tenant-1"]) == [{"Name": "custom:tenant", "Value": "tenant-1"}]

        with pytest.raises(Exception):
            core._parse_attributes(["custom:tenant"])

        with pytest.raises(Exception):
            core._parse_attributes(["=tenant-1"])


class TestStatusAndSetupCoverage:
    @mock.patch("boto3.Session")
    def test_status_renders_pool_lookup_error(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "status.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        client.describe_user_pool.side_effect = Exception("lookup failed")
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "status"])

        assert result.exit_code == 0
        assert "lookup failed" in result.output

    @mock.patch("boto3.Session")
    def test_status_errors_when_session_creation_fails(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "status.yaml"
        _write_flat_config(cfg)
        mock_session_cls.side_effect = Exception("session failed")

        result = runner.invoke(app, ["--config", str(cfg), "status"])

        assert result.exit_code == 1
        assert "session failed" in result.output

    @mock.patch("boto3.Session")
    def test_setup_reuses_existing_pool_client_and_existing_domain(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "existing-setup.yaml"
        client = _mock_cognito_client()
        client.list_user_pools.return_value = {"UserPools": [{"Name": "my-pool", "Id": "pool-123"}]}
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "my-pool", "Id": "pool-123", "Domain": "kept-domain", "CustomDomain": None}
        }
        client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientId": "client-existing", "ClientName": "my-app"}]
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "setup",
                "--name",
                "my-pool",
                "--client-name",
                "my-app",
                "--domain-prefix",
                "requested-domain",
                "--logout-url",
                "https://example.test/logout",
                "--autoprovision",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        assert "already exists" in result.output
        assert "Keeping existing domain" in result.output
        assert "Reusing app client" in result.output
        stored = _read_yaml(cfg)
        assert stored["COGNITO_APP_CLIENT_ID"] == "client-existing"
        assert stored["COGNITO_DOMAIN"] == "kept-domain.auth.us-west-2.amazoncognito.com"
        assert stored["COGNITO_LOGOUT_URL"] == "https://example.test/logout"
        client.create_user_pool.assert_not_called()
        client.create_user_pool_domain.assert_not_called()
        client.create_user_pool_client.assert_not_called()


class TestAuthConfigCoverage:
    def test_auth_config_create_rejects_conflicting_client_selectors(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "conflict.yaml"

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "auth-config",
                "create",
                "--pool-name",
                "pool-a",
                "--client-name",
                "web",
                "--client-id",
                "cid-1",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Provide only one of: --client-name or --client-id" in result.output

    @mock.patch("boto3.Session")
    def test_auth_config_create_errors_when_pool_has_no_clients(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "no-client.yaml"
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "pool-a", "Id": "pool-123", "Domain": None, "CustomDomain": None}
        }
        client.list_user_pool_clients.return_value = {"UserPoolClients": []}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "auth-config", "create", "--pool-name", "pool-a"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "flat config file requires an app client" in result.output

    def test_auth_config_update_errors_when_config_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "missing.yaml"

        result = runner.invoke(app, ["--config", str(cfg), "auth-config", "update", "--pool-name", "pool-a"])

        assert result.exit_code == 1
        assert "Config file not found" in result.output

    @mock.patch("boto3.Session")
    def test_auth_config_update_applies_callback_and_logout_overrides(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "update.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.describe_user_pool.return_value = {
            "UserPool": {"Name": "pool-a", "Id": "pool-123", "Domain": "domain-prefix", "CustomDomain": None}
        }
        client.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "cid-1", "ClientName": "web"}]}
        client.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web",
                "CallbackURLs": ["https://old.example.test/callback"],
                "LogoutURLs": ["https://old.example.test/logout"],
            }
        }
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "auth-config",
                "update",
                "--pool-name",
                "pool-a",
                "--callback-url",
                "https://new.example.test/callback",
                "--logout-url",
                "https://new.example.test/logout",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        stored = _read_yaml(cfg)
        assert stored["COGNITO_CALLBACK_URL"] == "https://new.example.test/callback"
        assert stored["COGNITO_LOGOUT_URL"] == "https://new.example.test/logout"


class TestAwsCommandCoverage:
    @mock.patch("boto3.Session")
    def test_list_pools_errors_when_boto3_fails(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.side_effect = Exception("broken paginator")
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["list-pools"], env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"})

        assert result.exit_code == 1
        assert "broken paginator" in result.output

    @mock.patch("boto3.Session")
    def test_list_apps_errors_when_pool_lookup_fails(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "other-pool", "Id": "pool-999"}]}]
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["list-apps", "--pool-name", "missing-pool"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Pool not found" in result.output

    @mock.patch("boto3.Session")
    def test_add_app_rejects_duplicate_client_name(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web", "ClientId": "cid-1"}]}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "add-app",
                "--pool-name",
                "pool-a",
                "--app-name",
                "web",
                "--callback-url",
                "https://example.test/callback",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "App client already exists" in result.output

    def test_edit_app_requires_app_name_or_client_id(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)

        result = runner.invoke(
            app,
            ["edit-app", "--pool-name", "pool-a"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Provide one of: --app-name or --client-id" in result.output

    @mock.patch("boto3.Session")
    def test_edit_app_applies_logout_flow_scope_and_idp_overrides(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web", "ClientId": "cid-1"}]}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "edit-app",
                "--pool-name",
                "pool-a",
                "--client-id",
                "cid-1",
                "--logout-url",
                "https://example.test/logout",
                "--oauth-flows",
                "code,implicit",
                "--scopes",
                "openid,email",
                "--idp",
                "COGNITO,Google",
            ],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        kwargs = client.update_user_pool_client.call_args.kwargs
        assert kwargs["LogoutURLs"] == ["https://example.test/logout"]
        assert kwargs["AllowedOAuthFlows"] == ["code", "implicit"]
        assert kwargs["AllowedOAuthScopes"] == ["openid", "email"]
        assert kwargs["SupportedIdentityProviders"] == ["COGNITO", "Google"]
        assert "Logout URL" in result.output

    def test_remove_app_requires_app_name_or_client_id(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)

        result = runner.invoke(
            app,
            ["remove-app", "--pool-name", "pool-a"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 1
        assert "Provide one of: --app-name or --client-id" in result.output

    @mock.patch("boto3.Session")
    def test_remove_app_can_cancel_confirmation(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web", "ClientId": "cid-1"}]}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["remove-app", "--pool-name", "pool-a", "--app-name", "web"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
            input="n\n",
        )

        assert result.exit_code == 0
        assert "Cancelled" in result.output
        client.delete_user_pool_client.assert_not_called()

    def test_delete_pool_requires_name_or_id(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)

        result = runner.invoke(app, ["delete-pool"], env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"})

        assert result.exit_code == 1
        assert "Provide one of" in result.output

    @mock.patch("boto3.Session")
    def test_delete_pool_can_cancel_confirmation(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["delete-pool", "--pool-name", "pool-a"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
            input="n\n",
        )

        assert result.exit_code == 0
        assert "Cancelled" in result.output
        client.delete_user_pool.assert_not_called()

    @mock.patch("boto3.Session")
    def test_delete_pool_delete_domain_first_detaches_and_deletes(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.describe_user_pool.side_effect = [
            {"UserPool": {"Name": "pool-a", "Id": "pool-123", "Domain": "domain-prefix", "CustomDomain": None}},
            {"UserPool": {"Name": "pool-a", "Id": "pool-123", "Domain": None, "CustomDomain": None}},
        ]
        _configure_session(mock_session_cls, client)
        monkeypatch.setattr(core.time, "sleep", lambda _seconds: None)

        result = runner.invoke(
            app,
            ["delete-pool", "--pool-name", "pool-a", "--delete-domain-first", "--force"],
            env={"AWS_PROFILE": "env-profile", "AWS_REGION": "us-west-2"},
        )

        assert result.exit_code == 0
        client.delete_user_pool_domain.assert_called_once_with(UserPoolId="pool-123", Domain="domain-prefix")
        client.delete_user_pool.assert_called_once_with(UserPoolId="pool-123")


class TestGoogleCoverage:
    def test_add_google_idp_requires_app_name_or_client_id(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "google.yaml"
        _write_flat_config(cfg, GOOGLE_CLIENT_ID="gid-123", GOOGLE_CLIENT_SECRET="gsecret-456")

        result = runner.invoke(app, ["--config", str(cfg), "add-google-idp", "--pool-name", "pool-a"])

        assert result.exit_code == 1
        assert "Provide one of: --app-name or --client-id" in result.output

    @mock.patch("boto3.Session")
    def test_add_google_idp_updates_existing_provider(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "google.yaml"
        _write_flat_config(cfg, GOOGLE_CLIENT_ID="gid-123", GOOGLE_CLIENT_SECRET="gsecret-456")
        client = _mock_cognito_client()
        client.get_paginator.return_value.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "pool-123"}]}]
        client.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientName": "web", "ClientId": "cid-1"}]}
        client.describe_identity_provider.return_value = {"IdentityProvider": {"ProviderName": "Google"}}
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "add-google-idp", "--pool-name", "pool-a", "--app-name", "web"],
        )

        assert result.exit_code == 0
        client.update_identity_provider.assert_called_once()
        client.create_identity_provider.assert_not_called()

    def test_setup_google_requires_existing_valid_config(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "missing.yaml"

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

        assert result.exit_code == 1
        assert "Config file not found" in result.output


class TestConfigBackedCommandCoverage:
    @mock.patch("boto3.Session")
    def test_ensure_group_reports_existing_group(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "groups.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"Groups": [{"GroupName": "admins"}]}]
        client.get_paginator.return_value = paginator
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "ensure-group", "admins"])

        assert result.exit_code == 0
        assert "Group already exists" in result.output
        client.create_group.assert_not_called()

    @mock.patch("boto3.Session")
    def test_ensure_group_creates_group_with_description(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "groups.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"Groups": []}]
        client.get_paginator.return_value = paginator
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "ensure-group", "admins", "--description", "Admin team"])

        assert result.exit_code == 0
        client.create_group.assert_called_once_with(UserPoolId="us-west-2_pool", GroupName="admins", Description="Admin team")

    @mock.patch("boto3.Session")
    def test_add_user_to_group_calls_admin_api(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "group-user.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "add-user-to-group", "--email", "user@example.com", "--group", "admins"],
        )

        assert result.exit_code == 0
        client.admin_add_user_to_group.assert_called_once_with(
            UserPoolId="us-west-2_pool",
            Username="user@example.com",
            GroupName="admins",
        )

    def test_set_user_attributes_requires_at_least_one_attribute(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "attrs.yaml"
        _write_flat_config(cfg)

        result = runner.invoke(app, ["--config", str(cfg), "set-user-attributes", "--email", "user@example.com"])

        assert result.exit_code == 1
        assert "Provide at least one --attribute" in result.output

    @mock.patch("boto3.Session")
    def test_set_user_attributes_updates_multiple_values(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "attrs.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "set-user-attributes",
                "--email",
                "user@example.com",
                "--attribute",
                "custom:tenant_id=tenant-1",
                "--attribute",
                "custom:roles=admin",
            ],
        )

        assert result.exit_code == 0
        client.admin_update_user_attributes.assert_called_once_with(
            UserPoolId="us-west-2_pool",
            Username="user@example.com",
            UserAttributes=[
                {"Name": "custom:tenant_id", "Value": "tenant-1"},
                {"Name": "custom:roles", "Value": "admin"},
            ],
        )
        assert "custom:tenant_id=tenant-1" in result.output

    @mock.patch("boto3.Session")
    def test_add_user_no_verify_sets_permanent_password(
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

        result = runner.invoke(
            app,
            [
                "--config",
                str(cfg),
                "add-user",
                "new@example.com",
                "--password",
                "Secret123",
                "--no-verify",
            ],
        )

        assert result.exit_code == 0
        create_kwargs = client.admin_create_user.call_args.kwargs
        assert {"Name": "email_verified", "Value": "true"} in create_kwargs["UserAttributes"]
        client.admin_set_user_password.assert_called_once_with(
            UserPoolId="us-west-2_pool",
            Username="new@example.com",
            Password="Secret123",
            Permanent=True,
        )

    @mock.patch("boto3.Session")
    def test_add_user_with_explicit_password_marks_it_temporary(
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

        result = runner.invoke(
            app,
            ["--config", str(cfg), "add-user", "new@example.com", "--password", "Secret123"],
        )

        assert result.exit_code == 0
        assert "Password set (temporary - must change on first login)" in result.output

    @mock.patch("boto3.Session")
    def test_add_user_reports_existing_username(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        class UsernameExists(Exception):
            pass

        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "add-user.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        client.exceptions = SimpleNamespace(UsernameExistsException=UsernameExists)
        client.admin_create_user.side_effect = UsernameExists()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "add-user", "existing@example.com"])

        assert result.exit_code == 1
        assert "User already exists" in result.output

    @mock.patch("boto3.Session")
    def test_list_users_renders_table_rows(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "list-users.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [
            {
                "Users": [
                    {
                        "Attributes": [
                            {"Name": "email", "Value": "a@example.com"},
                            {"Name": "custom:customer_id", "Value": "cust-1"},
                        ],
                        "UserStatus": "CONFIRMED",
                        "UserCreateDate": mock.Mock(strftime=mock.Mock(return_value="2024-01-01 12:00")),
                        "Enabled": True,
                    },
                    {
                        "Attributes": [{"Name": "email", "Value": "b@example.com"}],
                        "UserStatus": "COMPROMISED",
                        "UserCreateDate": None,
                        "Enabled": False,
                    },
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "list-users"])

        assert result.exit_code == 0
        assert "a@example.com" in result.output
        assert "cust-1" in result.output
        assert "COMPROMISED" in result.output
        assert "Total: 2 users" in result.output

    @mock.patch("boto3.Session")
    def test_delete_user_can_cancel_confirmation(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "delete-user.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(
            app,
            ["--config", str(cfg), "delete-user", "--email", "user@example.com"],
            input="n\n",
        )

        assert result.exit_code == 0
        assert "Cancelled" in result.output
        client.admin_delete_user.assert_not_called()

    @mock.patch("boto3.Session")
    def test_delete_all_users_can_cancel_confirmation(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "delete-all.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "delete-all-users"], input="n\n")

        assert result.exit_code == 0
        assert "Cancelled" in result.output
        client.admin_delete_user.assert_not_called()

    @mock.patch("boto3.Session")
    def test_delete_all_users_continues_when_one_delete_fails(
        self,
        mock_session_cls: mock.MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        app = _make_app(monkeypatch, tmp_path)
        cfg = tmp_path / "delete-all.yaml"
        _write_flat_config(cfg)
        client = _mock_cognito_client()
        paginator = mock.MagicMock()
        paginator.paginate.return_value = [{"Users": [{"Username": "u1"}, {"Username": "u2"}]}]
        client.get_paginator.return_value = paginator
        client.admin_delete_user.side_effect = [None, Exception("delete failed")]
        _configure_session(mock_session_cls, client)

        result = runner.invoke(app, ["--config", str(cfg), "delete-all-users", "--force"])

        assert result.exit_code == 0
        assert "Failed to delete u2" in result.output
        assert "Deleted 1 users" in result.output
