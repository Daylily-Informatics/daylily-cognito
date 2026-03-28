"""Tests for daylily_cognito CLI (cli.py)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from unittest import mock

import typer.testing
import yaml

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


def _cfg_dir(tmp_path) -> Path:
    return tmp_path / ".config" / "daycog"


def _pool_context_name(pool_key: str, region: str) -> str:
    return f"{pool_key}.{region}"


def _sanitize_context_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "app"


def _app_context_name(pool_key: str, region: str, client_name: str) -> str:
    return f"{pool_key}.{region}.{_sanitize_context_part(client_name)}"


def _cfg_path(tmp_path) -> Path:
    return _cfg_dir(tmp_path) / "config.yaml"


def _load_store(tmp_path) -> dict:
    path = _cfg_path(tmp_path)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _save_store(tmp_path, payload: dict) -> None:
    path = _cfg_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _write_store(tmp_path, *, contexts: dict[str, dict[str, str]], active_context: str = "") -> None:
    payload: dict[str, object] = {"contexts": contexts}
    if active_context:
        payload["active_context"] = active_context
    _save_store(tmp_path, payload)


def _get_context_values(tmp_path, name: str) -> dict[str, str]:
    store = _load_store(tmp_path)
    contexts = store.get("contexts") if isinstance(store.get("contexts"), dict) else {}
    values = contexts.get(name) if isinstance(contexts, dict) else {}
    return dict(values) if isinstance(values, dict) else {}


def _get_active_context_name(tmp_path) -> str:
    return str(_load_store(tmp_path).get("active_context") or "")


def _set_context_values(tmp_path, name: str, values: dict[str, str], *, set_active: bool = False) -> None:
    store = _load_store(tmp_path)
    contexts = store.setdefault("contexts", {})
    if not isinstance(contexts, dict):
        contexts = {}
        store["contexts"] = contexts
    contexts[name] = dict(values)
    if set_active:
        store["active_context"] = name
    _save_store(tmp_path, store)


def _parse_env_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _render_env_text(values: dict[str, str]) -> str:
    return "\n".join(f"{key}={value}" for key, value in values.items())


class _ContextRef:
    def __init__(self, tmp_path: Path, name: str):
        self.tmp_path = tmp_path
        self.name = name

    def __str__(self) -> str:
        return f"{_cfg_path(self.tmp_path)} :: {self.name}"

    @property
    def parent(self) -> Path:
        return _cfg_dir(self.tmp_path)

    def exists(self) -> bool:
        return bool(_get_context_values(self.tmp_path, self.name))

    def read_text(self, encoding: str = "utf-8") -> str:  # noqa: ARG002
        return _render_env_text(_get_context_values(self.tmp_path, self.name))

    def write_text(self, text: str, encoding: str = "utf-8") -> int:  # noqa: ARG002
        values = _parse_env_text(text)
        _set_context_values(self.tmp_path, self.name, values)
        return len(text)


def _pool_file(tmp_path, pool_key: str, region: str) -> _ContextRef:
    return _ContextRef(tmp_path, _pool_context_name(pool_key, region))


def _app_file(tmp_path, pool_key: str, region: str, client_name: str) -> _ContextRef:
    return _ContextRef(tmp_path, _app_context_name(pool_key, region, client_name))


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
        assert str(_cfg_path(tmp_path)) in normalized
        mock_boto_client.assert_called_once_with("cognito-idp", region_name="us-west-2")
        mc.create_user_pool.assert_called_once()
        mc.create_user_pool_domain.assert_called_once_with(UserPoolId="us-west-2_New", Domain="my-pool")
        mc.create_user_pool_client.assert_called_once()
        assert _pool_file(tmp_path, "us-west-2_New", "us-west-2").exists()
        assert _app_file(tmp_path, "us-west-2_New", "us-west-2", "my-pool-client").exists()
        assert _get_active_context_name(tmp_path) == _app_context_name("us-west-2_New", "us-west-2", "my-pool-client")
        content = _app_file(tmp_path, "us-west-2_New", "us-west-2", "my-pool-client").read_text(encoding="utf-8")
        assert "COGNITO_CALLBACK_URL=http://localhost:8001/auth/callback" in content
        assert "COGNITO_DOMAIN=my-pool.auth.us-west-2.amazoncognito.com" in content

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
        assert 'export COGNITO_DOMAIN="my-pool.auth.us-east-1.amazoncognito.com"' in result.output

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
    def test_setup_warns_when_contexts_exist(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        legacy_pool_path = _pool_file(tmp_path, "my-pool", "us-west-2")
        legacy_app_path = _app_file(tmp_path, "my-pool", "us-west-2", "my-pool-client")
        legacy_pool_path.write_text("COGNITO_USER_POOL_ID=old\n", encoding="utf-8")
        legacy_app_path.write_text("COGNITO_APP_CLIENT_ID=old\n", encoding="utf-8")
        _write_store(
            tmp_path,
            contexts={
                legacy_pool_path.name: _get_context_values(tmp_path, legacy_pool_path.name),
                legacy_app_path.name: _get_context_values(tmp_path, legacy_app_path.name),
            },
            active_context=legacy_app_path.name,
        )

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["setup", "--name", "my-pool"])

        assert result.exit_code == 0
        assert "Context already exists in" in result.output
        assert not legacy_pool_path.exists()
        assert not legacy_app_path.exists()
        assert _pool_file(tmp_path, "us-west-2_New", "us-west-2").exists()
        assert _app_file(tmp_path, "us-west-2_New", "us-west-2", "my-pool-client").exists()

    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_setup_can_skip_domain_attachment(self, mock_boto_client: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_boto_client.return_value = mc
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["setup", "--name", "my-pool", "--no-attach-domain"])
        assert result.exit_code == 0
        mc.create_user_pool_domain.assert_not_called()

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
        _write_store(
            tmp_path,
            contexts={"active.us-west-2": {"AWS_PROFILE": "from-file"}},
            active_context="active.us-west-2",
        )
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print"])
        assert result.exit_code == 0
        normalized = result.output.replace("\n", "")
        assert str(_cfg_path(tmp_path)) in normalized
        assert "active.us-west-2" in result.output
        assert "AWS_PROFILE=from-file" in result.output

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_accepts_pool_name(self, tmp_path) -> None:
        cfg_path = _pool_file(tmp_path, "my-pool", "us-west-2")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("COGNITO_USER_POOL_ID=pool_id\n", encoding="utf-8")
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print", "--pool-name", "my-pool", "--region", "us-west-2"])
        assert result.exit_code == 0
        assert "COGNITO_USER_POOL_ID=pool_id" in result.output

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_accepts_poor_name_alias(self, tmp_path) -> None:
        cfg_path = _pool_file(tmp_path, "my-pool", "us-west-2")
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

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_accepts_pool_id(self, tmp_path) -> None:
        cfg_path = _pool_file(tmp_path, "us-west-2_pool", "us-west-2")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("COGNITO_USER_POOL_ID=us-west-2_pool\n", encoding="utf-8")
        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app, ["config", "print", "--pool-id", "us-west-2_pool", "--region", "us-west-2"]
            )
        assert result.exit_code == 0
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in result.output

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "dev-prof"}, clear=True)
    @mock.patch("boto3.Session")
    def test_config_print_resolves_pool_name_to_pool_id_path(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        cfg_path = _pool_file(tmp_path, "us-west-2_pool", "us-west-2")
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("COGNITO_USER_POOL_ID=us-west-2_pool\n", encoding="utf-8")
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-west-2_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["config", "print", "--pool-name", "my-pool", "--region", "us-west-2"],
            )

        assert result.exit_code == 0
        assert str(cfg_path) in result.output.replace("\n", "")
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in result.output

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
        cfg_path = _pool_file(tmp_path, "us-east-1_pool", "us-east-1")
        app_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "web-app")
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientId": "client_123", "ClientName": "web-app"}]
        }
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "CallbackURLs": ["http://localhost:8001/callback"],
                "LogoutURLs": ["http://localhost:8001/logout"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "create", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        normalized = result.output.replace("\n", "")
        assert str(cfg_path) in normalized
        assert str(app_path) in normalized
        assert str(_cfg_path(tmp_path)) in normalized
        assert "AWS_PROFILE=dev-prof" in result.output
        assert "AWS_REGION=us-east-1" in result.output
        assert "COGNITO_USER_POOL_ID=us-east-1_pool" in result.output
        assert "COGNITO_APP_CLIENT_ID=client_123" in result.output
        assert "COGNITO_CLIENT_NAME=web-app" in result.output
        assert "COGNITO_CALLBACK_URL=http://localhost:8001/callback" in result.output
        assert cfg_path.exists()
        assert app_path.exists()
        assert _get_active_context_name(tmp_path) == app_path.name
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
    def test_config_update_migrates_legacy_contexts_and_merges_existing_values(
        self, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
        pool_path = _pool_file(tmp_path, "us-west-2_pool", "us-west-2")
        app_path = _app_file(tmp_path, "us-west-2_pool", "us-west-2", "web-app")
        legacy_pool_path = _pool_file(tmp_path, "my-pool", "us-west-2")
        legacy_app_path = _app_file(tmp_path, "my-pool", "us-west-2", "web-app")
        legacy_pool_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_pool_path.write_text("GOOGLE_CLIENT_ID=keepme\n", encoding="utf-8")
        legacy_app_path.write_text(
            "GOOGLE_CLIENT_SECRET=keepsecret\nCOGNITO_DOMAIN=example-domain\n",
            encoding="utf-8",
        )

        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-west-2_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "my-pool", "Id": "us-west-2_pool"}}
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientId": "updated-client", "ClientName": "web-app"}]
        }
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "CallbackURLs": ["http://localhost:8001/callback"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "update", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        pool_content = pool_path.read_text(encoding="utf-8")
        app_content = app_path.read_text(encoding="utf-8")
        assert not legacy_pool_path.exists()
        assert not legacy_app_path.exists()
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in pool_content
        assert "COGNITO_APP_CLIENT_ID=updated-client" in pool_content
        assert "COGNITO_CLIENT_NAME=web-app" in pool_content
        assert "AWS_PROFILE=new-prof" in pool_content
        assert "AWS_REGION=us-west-2" in pool_content
        assert "GOOGLE_CLIENT_ID=keepme" in pool_content
        assert "COGNITO_APP_CLIENT_ID=updated-client" in app_content
        assert "COGNITO_CLIENT_NAME=web-app" in app_content
        assert "COGNITO_CALLBACK_URL=http://localhost:8001/callback" in app_content
        assert "GOOGLE_CLIENT_SECRET=keepsecret" in app_content
        assert "COGNITO_DOMAIN=example-domain" in app_content
        assert "COGNITO_USER_POOL_ID=us-west-2_pool" in app_content
        assert _get_active_context_name(tmp_path) == app_path.name

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_create_requires_pool_name_or_id(self) -> None:
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
    def test_config_update_errors_when_multiple_clients_without_selector(
        self, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
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
        assert result.exit_code == 1
        assert "Pool has multiple app clients" in result.output
        assert "config create-all" in result.output

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_accepts_client_name_and_url_overrides(
        self, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
        pool_path = _pool_file(tmp_path, "us-east-1_pool", "us-east-1")
        app_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "bloom")
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientId": "client_atlas", "ClientName": "atlas"},
                {"ClientId": "client_bloom", "ClientName": "bloom"},
            ]
        }
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "bloom",
                "CallbackURLs": ["https://aws.example/callback"],
                "LogoutURLs": ["https://aws.example/logout"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "config",
                    "create",
                    "--pool-name",
                    "my-pool",
                    "--client-name",
                    "bloom",
                    "--callback-url",
                    "https://bloom.dev-v2.lsmc.bio/auth/callback",
                    "--logout-url",
                    "https://bloom.dev-v2.lsmc.bio/",
                ],
            )

        assert result.exit_code == 0
        pool_content = pool_path.read_text(encoding="utf-8")
        app_content = app_path.read_text(encoding="utf-8")
        assert "COGNITO_CLIENT_NAME=bloom" in pool_content
        assert "COGNITO_CALLBACK_URL=https://bloom.dev-v2.lsmc.bio/auth/callback" in app_content
        assert "COGNITO_LOGOUT_URL=https://bloom.dev-v2.lsmc.bio/" in app_content
        mc.update_user_pool_client.assert_not_called()

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_update_accepts_pool_id_and_client_id(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        pool_path = _pool_file(tmp_path, "us-east-1_pool", "us-east-1")
        app_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "bloom")
        mc = _mock_cognito_client()
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "my-pool", "Id": "us-east-1_pool"}}
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientId": "atlas_id", "ClientName": "atlas"},
                {"ClientId": "bloom_id", "ClientName": "bloom"},
            ]
        }
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "bloom",
                "CallbackURLs": ["https://bloom.example/callback"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "config",
                    "update",
                    "--pool-id",
                    "us-east-1_pool",
                    "--client-id",
                    "bloom_id",
                ],
            )

        assert result.exit_code == 0
        assert "COGNITO_APP_CLIENT_ID=bloom_id" in pool_path.read_text(encoding="utf-8")
        assert "COGNITO_CLIENT_NAME=bloom" in app_path.read_text(encoding="utf-8")

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_writes_pool_only_when_no_clients(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        pool_path = _pool_file(tmp_path, "us-east-1_pool", "us-east-1")
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": []}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "create", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        assert pool_path.exists()
        assert _get_active_context_name(tmp_path) == pool_path.name
        assert "Pool has no app clients" in result.output
        assert "COGNITO_APP_CLIENT_ID" not in pool_path.read_text(encoding="utf-8")

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_all_writes_app_files_and_default_selected_client(
        self, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
        atlas_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "atlas")
        bloom_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "bloom")
        pool_path = _pool_file(tmp_path, "us-east-1_pool", "us-east-1")
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {
            "UserPoolClients": [
                {"ClientId": "atlas_id", "ClientName": "atlas"},
                {"ClientId": "bloom_id", "ClientName": "bloom"},
            ]
        }
        mc.describe_user_pool_client.side_effect = [
            {"UserPoolClient": {"ClientName": "atlas", "CallbackURLs": ["https://atlas.example/callback"]}},
            {"UserPoolClient": {"ClientName": "bloom", "CallbackURLs": ["https://bloom.example/callback"]}},
            {"UserPoolClient": {"ClientName": "atlas", "CallbackURLs": ["https://atlas.example/callback"]}},
        ]
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["config", "create-all", "--pool-name", "my-pool", "--default-client", "atlas"],
            )

        assert result.exit_code == 0
        assert atlas_path.exists()
        assert bloom_path.exists()
        assert "COGNITO_CLIENT_NAME=atlas" in pool_path.read_text(encoding="utf-8")
        assert _get_active_context_name(tmp_path) == atlas_path.name

    @mock.patch.dict(
        os.environ,
        {
            "AWS_PROFILE": "dev-prof",
            "AWS_REGION": "us-east-1",
        },
        clear=True,
    )
    @mock.patch("boto3.Session")
    def test_config_create_all_skips_existing_app_contexts(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        atlas_path = _app_file(tmp_path, "us-east-1_pool", "us-east-1", "atlas")
        atlas_path.parent.mkdir(parents=True, exist_ok=True)
        atlas_path.write_text("GOOGLE_CLIENT_ID=keepme\n", encoding="utf-8")

        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "my-pool", "Id": "us-east-1_pool"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "atlas_id", "ClientName": "atlas"}]}
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "atlas",
                "CallbackURLs": ["https://atlas.example/callback"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "create-all", "--pool-name", "my-pool"])

        assert result.exit_code == 0
        assert "Skipping existing context" in result.output
        app_content = atlas_path.read_text(encoding="utf-8")
        assert "GOOGLE_CLIENT_ID=keepme" in app_content
        assert "COGNITO_CALLBACK_URL" not in app_content

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_json_uses_active_context(self, tmp_path) -> None:
        _write_store(
            tmp_path,
            contexts={"active.us-west-2": {"AWS_PROFILE": "from-file", "AWS_REGION": "us-west-2"}},
            active_context="active.us-west-2",
        )

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["config", "print", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["config_store_path"] == str(_cfg_path(tmp_path))
        assert payload["context_name"] == "active.us-west-2"
        assert payload["values"]["AWS_PROFILE"] == "from-file"

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_config_print_json_selects_app_context_by_client_name(self, tmp_path) -> None:
        _write_store(
            tmp_path,
            contexts={
                "us-west-2_pool.us-west-2": {
                    "COGNITO_USER_POOL_ID": "us-west-2_pool",
                    "AWS_REGION": "us-west-2",
                    "COGNITO_REGION": "us-west-2",
                },
                "us-west-2_pool.us-west-2.atlas": {
                    "COGNITO_USER_POOL_ID": "us-west-2_pool",
                    "COGNITO_APP_CLIENT_ID": "atlas-id",
                    "COGNITO_CLIENT_NAME": "atlas",
                    "AWS_REGION": "us-west-2",
                    "COGNITO_REGION": "us-west-2",
                },
            },
        )

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "config",
                    "print",
                    "--pool-id",
                    "us-west-2_pool",
                    "--region",
                    "us-west-2",
                    "--client-name",
                    "atlas",
                    "--json",
                ],
            )

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["context_name"] == "us-west-2_pool.us-west-2.atlas"
        assert payload["values"]["COGNITO_APP_CLIENT_ID"] == "atlas-id"


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
    def test_add_app_creates_app_and_app_context(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
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
        app_path = _app_file(tmp_path, "us-east-1_A", "us-east-1", "web-app")
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
                "DefaultRedirectURI": "http://localhost:8001/callback",
                "PreventUserExistenceErrors": "ENABLED",
                "EnableTokenRevocation": True,
                "AuthSessionValidity": 3,
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
        assert kwargs["LogoutURLs"] == ["http://localhost:8001/logout"]
        assert kwargs["DefaultRedirectURI"] == "http://localhost:8001/callback"
        assert kwargs["PreventUserExistenceErrors"] == "ENABLED"
        assert kwargs["EnableTokenRevocation"] is True
        assert kwargs["AuthSessionValidity"] == 3
        assert "Updated app client: web-app-v2 (cid-1)" in result.output
        assert _app_file(tmp_path, "us-east-1_A", "us-east-1", "web-app-v2").exists()

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
        app_path = _app_file(tmp_path, "us-east-1_A", "us-east-1", "web-app")
        legacy_app_path = _app_file(tmp_path, "pool-a", "us-east-1", "web-app")
        app_path.parent.mkdir(parents=True, exist_ok=True)
        app_path.write_text("COGNITO_APP_CLIENT_ID=cid-1\n", encoding="utf-8")
        legacy_app_path.write_text("COGNITO_APP_CLIENT_ID=cid-1\n", encoding="utf-8")

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                ["remove-app", "--pool-name", "pool-a", "--app-name", "web-app", "--force"],
            )

        assert result.exit_code == 0
        mc.delete_user_pool_client.assert_called_once_with(UserPoolId="us-east-1_A", ClientId="cid-1")
        assert not app_path.exists()
        assert not legacy_app_path.exists()


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
                "DefaultRedirectURI": "http://localhost:8001/auth/callback",
                "PreventUserExistenceErrors": "ENABLED",
                "EnableTokenRevocation": True,
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
        assert update_kwargs["LogoutURLs"] == ["http://localhost:8001/"]
        assert update_kwargs["DefaultRedirectURI"] == "http://localhost:8001/auth/callback"
        assert update_kwargs["PreventUserExistenceErrors"] == "ENABLED"
        assert update_kwargs["EnableTokenRevocation"] is True

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
# setup-with-google
# ---------------------------------------------------------------------------


class TestSetupWithGoogleCommand:
    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    @mock.patch("boto3.client")
    def test_setup_with_google_runs_both_steps(
        self, mock_boto_client: mock.MagicMock, mock_session_cls: mock.MagicMock, tmp_path
    ) -> None:
        # setup() path
        mc_setup = _mock_cognito_client()
        mc_setup.list_user_pools.return_value = {"UserPools": []}
        mc_setup.create_user_pool.return_value = {"UserPool": {"Id": "us-east-1_NEWPOOL"}}
        mc_setup.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "cid-new"}}
        mock_boto_client.return_value = mc_setup

        # add_google_idp() path
        mc_session = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_NEWPOOL"}]}]
        mc_session.get_paginator.return_value = mock_paginator
        mc_session.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "web-app", "ClientId": "cid-new"}]
        }
        mc_session.describe_identity_provider.side_effect = Exception("not found")
        mc_session.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "web-app",
                "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid", "email", "profile"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/auth/callback"],
                "LogoutURLs": [],
                "SupportedIdentityProviders": ["COGNITO"],
            }
        }
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc_session
        mock_session_cls.return_value = mock_session

        json_path = tmp_path / "google-client.json"
        json_path.write_text('{"web":{"client_id":"gid-123","client_secret":"gsecret-456"}}', encoding="utf-8")

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(
                cognito_app,
                [
                    "setup-with-google",
                    "--name",
                    "pool-a",
                    "--client-name",
                    "web-app",
                    "--google-client-json",
                    str(json_path),
                ],
            )

        assert result.exit_code == 0
        assert "Setup with Google IdP complete" in result.output
        mc_setup.create_user_pool.assert_called_once()
        mc_setup.create_user_pool_client.assert_called_once()
        mc_session.create_identity_provider.assert_called_once()
        mc_session.update_user_pool_client.assert_called_once()


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

    @mock.patch.dict(os.environ, {"AWS_PROFILE": "p", "AWS_REGION": "us-east-1"}, clear=True)
    @mock.patch("boto3.Session")
    def test_delete_pool_removes_related_contexts(self, mock_session_cls: mock.MagicMock, tmp_path) -> None:
        mc = _mock_cognito_client()
        mock_paginator = mock.MagicMock()
        mock_paginator.paginate.return_value = [{"UserPools": [{"Name": "pool-a", "Id": "us-east-1_A"}]}]
        mc.get_paginator.return_value = mock_paginator
        mc.describe_user_pool.return_value = {"UserPool": {"Name": "pool-a", "Domain": None, "CustomDomain": None}}
        mock_session = mock.MagicMock()
        mock_session.client.return_value = mc
        mock_session_cls.return_value = mock_session

        pool_file = _pool_file(tmp_path, "us-east-1_A", "us-east-1")
        app_file = _app_file(tmp_path, "us-east-1_A", "us-east-1", "web-app")
        legacy_pool_file = _pool_file(tmp_path, "pool-a", "us-east-1")
        legacy_app_file = _app_file(tmp_path, "pool-a", "us-east-1", "web-app")
        pool_file.write_text("COGNITO_USER_POOL_ID=us-east-1_A\n", encoding="utf-8")
        app_file.write_text("COGNITO_USER_POOL_ID=us-east-1_A\n", encoding="utf-8")
        legacy_pool_file.write_text("COGNITO_USER_POOL_ID=us-east-1_A\n", encoding="utf-8")
        legacy_app_file.write_text("COGNITO_USER_POOL_ID=us-east-1_A\n", encoding="utf-8")
        _write_store(
            tmp_path,
            contexts={
                pool_file.name: _get_context_values(tmp_path, pool_file.name),
                app_file.name: _get_context_values(tmp_path, app_file.name),
                legacy_pool_file.name: _get_context_values(tmp_path, legacy_pool_file.name),
                legacy_app_file.name: _get_context_values(tmp_path, legacy_app_file.name),
            },
            active_context=app_file.name,
        )

        with mock.patch("pathlib.Path.home", return_value=tmp_path):
            result = runner.invoke(cognito_app, ["delete-pool", "--pool-name", "pool-a", "--force"])

        assert result.exit_code == 0
        assert not pool_file.exists()
        assert not app_file.exists()
        assert not legacy_pool_file.exists()
        assert not legacy_app_file.exists()
        assert _get_active_context_name(tmp_path) == ""


# ---------------------------------------------------------------------------
# fix-auth-flows
# ---------------------------------------------------------------------------


class TestFixAuthFlowsCommand:
    @mock.patch.dict(os.environ, _BASE_ENV, clear=False)
    @mock.patch("boto3.client")
    def test_fix_auth_flows_updates_client(self, mock_boto_client: mock.MagicMock) -> None:
        mc = _mock_cognito_client()
        mc.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "test-client",
                "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
                "AllowedOAuthFlows": ["code"],
                "AllowedOAuthScopes": ["openid"],
                "AllowedOAuthFlowsUserPoolClient": True,
                "CallbackURLs": ["http://localhost:8001/callback"],
                "LogoutURLs": ["http://localhost:8001/logout"],
                "SupportedIdentityProviders": ["COGNITO"],
                "DefaultRedirectURI": "http://localhost:8001/callback",
            }
        }
        mock_boto_client.return_value = mc
        result = runner.invoke(cognito_app, ["fix-auth-flows"])
        assert result.exit_code == 0
        mc.update_user_pool_client.assert_called_once()
        kwargs = mc.update_user_pool_client.call_args.kwargs
        assert "ALLOW_ADMIN_USER_PASSWORD_AUTH" in kwargs["ExplicitAuthFlows"]
        assert "ALLOW_USER_SRP_AUTH" in kwargs["ExplicitAuthFlows"]
        assert kwargs["LogoutURLs"] == ["http://localhost:8001/logout"]
        assert kwargs["DefaultRedirectURI"] == "http://localhost:8001/callback"
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
