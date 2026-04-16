"""Seam tests for daylily_auth_cognito.cli.plugins.config."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import click
import pytest
import yaml
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import config as plugin
from daylily_auth_cognito.cli.spec import spec


def _write_yaml(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _patch_active_config(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setattr(plugin, "active_config_path", lambda: path)


def _runtime(
    *,
    path: Path,
    profile: str = "dev-profile",
    region: str = "us-west-2",
    values: dict[str, str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        path=path,
        aws_profile=profile,
        aws_region=region,
        values=values or {},
        require_aws_profile=lambda: profile,
    )


def test_parse_helpers_and_validation_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    assert plugin._parse_csv(" a, ,b,, c ") == ["a", "b", "c"]
    assert plugin._parse_tags("env=dev, team = auth") == {"env": "dev", "team": "auth"}
    assert plugin._parse_attributes(["email=user@example.test", "custom:role=scientist"]) == [
        {"Name": "email", "Value": "user@example.test"},
        {"Name": "custom:role", "Value": "scientist"},
    ]
    assert plugin._resolve_callback_url(None, 8080, "auth/callback") == "http://localhost:8080/auth/callback"
    assert (
        plugin._resolve_callback_url("https://example.test/callback", 8080, "/ignored")
        == "https://example.test/callback"
    )
    assert plugin._resolve_mfa_configuration("off") == "OFF"
    assert plugin._resolve_mfa_configuration("required") == "ON"

    with pytest.raises(click.exceptions.Exit):
        plugin._parse_tags("not-a-tag")
    with pytest.raises(click.exceptions.Exit):
        plugin._parse_tags(" =broken")
    with pytest.raises(click.exceptions.Exit):
        plugin._parse_attributes(["missing-separator"])
    with pytest.raises(click.exceptions.Exit):
        plugin._parse_attributes([" =value"])
    with pytest.raises(click.exceptions.Exit):
        plugin._resolve_mfa_configuration("unsupported")


def test_google_client_resolution_uses_json_then_config_and_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client_json = _write_json(
        tmp_path / "client.json",
        {
            "web": {
                "client_id": "gid-web",
                "client_secret": "gsecret-web",
            }
        },
    )
    assert plugin._resolve_google_client_details(
        google_client_id=None,
        google_client_secret=None,
        google_client_json=str(client_json),
    ) == ("gid-web", "gsecret-web")

    _patch_active_config(monkeypatch, tmp_path / "config.yaml")
    monkeypatch.setattr(
        plugin,
        "load_config_file",
        lambda path, require_required_keys=True: {
            "GOOGLE_CLIENT_ID": "gid-config",
            "GOOGLE_CLIENT_SECRET": "gsecret-config",
        },
    )
    assert plugin._resolve_google_client_details(
        google_client_id=None,
        google_client_secret=None,
        google_client_json=None,
    ) == ("gid-config", "gsecret-config")

    monkeypatch.setattr(
        plugin, "load_config_file", lambda *args, **kwargs: (_ for _ in ()).throw(plugin.ConfigError("missing"))
    )
    with pytest.raises(click.exceptions.Exit):
        plugin._resolve_google_client_details(
            google_client_id=None,
            google_client_secret=None,
            google_client_json=None,
        )

    broken_json = tmp_path / "broken.json"
    broken_json.write_text("{not-json}", encoding="utf-8")
    with pytest.raises(click.exceptions.Exit):
        plugin._resolve_google_client_details(
            google_client_id=None,
            google_client_secret=None,
            google_client_json=str(broken_json),
        )


def test_domain_and_config_builders_normalize_expected_values() -> None:
    assert (
        plugin._resolve_cognito_domain({"Domain": "auth-prefix"}, "us-west-2")
        == "auth-prefix.auth.us-west-2.amazoncognito.com"
    )
    assert (
        plugin._resolve_cognito_domain({"CustomDomain": {"DomainName": "auth.example.test"}}, "us-west-2")
        == "auth.example.test"
    )
    assert plugin._resolve_cognito_domain({}, "us-west-2") == ""
    with pytest.raises(ValueError, match="bare host"):
        plugin._resolve_cognito_domain({"CustomDomain": "https://auth.example.test"}, "us-west-2")

    pool = {
        "pool_id": "pool-123",
        "pool_name": "ursa-users",
        "pool_info": {"Domain": "auth-prefix"},
    }
    details = plugin._build_pool_details(pool, "us-west-2", {"client_id": "client-123", "client_name": "web-client"})
    assert details == {
        "pool_id": "pool-123",
        "pool_name": "ursa-users",
        "cognito_domain": "auth-prefix.auth.us-west-2.amazoncognito.com",
        "client_id": "client-123",
        "client_name": "web-client",
    }

    values = plugin._build_config_values(
        "dev-profile",
        "us-west-2",
        {
            "pool_id": "pool-123",
            "pool_name": "ursa-users",
            "client_id": "client-123",
            "client_name": "web-client",
            "callback_url": "https://example.test/callback",
            "logout_url": "https://example.test/logout",
            "cognito_domain": "auth.example.test",
        },
        existing={
            "AWS_PROFILE": "old",
            "AWS_REGION": "old",
            "COGNITO_REGION": "old",
            "COGNITO_USER_POOL_ID": "old",
            "COGNITO_APP_CLIENT_ID": "old",
            "COGNITO_CLIENT_NAME": "old",
            "COGNITO_CALLBACK_URL": "old",
            "COGNITO_LOGOUT_URL": "old",
            "COGNITO_DOMAIN": "old",
            "KEEP": "yes",
        },
    )
    assert values == {
        "KEEP": "yes",
        "AWS_PROFILE": "dev-profile",
        "AWS_REGION": "us-west-2",
        "COGNITO_REGION": "us-west-2",
        "COGNITO_USER_POOL_ID": "pool-123",
        "COGNITO_APP_CLIENT_ID": "client-123",
        "COGNITO_CLIENT_NAME": "web-client",
        "COGNITO_CALLBACK_URL": "https://example.test/callback",
        "COGNITO_LOGOUT_URL": "https://example.test/logout",
        "COGNITO_DOMAIN": "auth.example.test",
    }


def test_print_config_supports_json_and_human_modes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    printed = []
    emitted = []
    _patch_active_config(monkeypatch, tmp_path / "config.yaml")
    monkeypatch.setattr(plugin, "get_context", lambda: SimpleNamespace(json_mode=False))
    monkeypatch.setattr(plugin.ccyo_out, "info", lambda message: printed.append(message))
    monkeypatch.setattr(plugin.ccyo_out, "emit_json", lambda payload: emitted.append(payload))

    plugin._print_config(
        tmp_path / "config.yaml",
        {
            "AWS_PROFILE": "dev-profile",
            "AWS_REGION": "us-west-2",
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
            "COGNITO_CLIENT_NAME": "web-client",
            "COGNITO_CALLBACK_URL": "https://example.test/callback",
            "COGNITO_LOGOUT_URL": "https://example.test/logout",
            "COGNITO_DOMAIN": "auth.example.test",
        },
    )
    assert printed[0].endswith("config.yaml")
    assert "COGNITO_USER_POOL_ID=pool-123" in printed
    assert "COGNITO_APP_CLIENT_ID=client-123" in printed
    assert emitted == []

    printed.clear()
    monkeypatch.setattr(plugin, "get_context", lambda: SimpleNamespace(json_mode=True))
    plugin._print_config(tmp_path / "config.yaml", {"COGNITO_REGION": "us-west-2"}, as_json=None)
    assert emitted[-1]["config_path"].endswith("config.yaml")
    assert emitted[-1]["values"]["COGNITO_REGION"] == "us-west-2"


def test_runtime_and_admin_helpers_cover_error_and_success_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "config.yaml"
    _patch_active_config(monkeypatch, path)

    runtime = _runtime(path=path, values={"COGNITO_USER_POOL_ID": "pool-123", "COGNITO_APP_CLIENT_ID": "client-123"})
    monkeypatch.setattr(plugin, "_get_runtime_config", lambda **kwargs: runtime)
    monkeypatch.setattr(plugin, "load_config_file_if_present", lambda path, require_required_keys=False: {"A": "B"})

    assert plugin._get_existing_config_values() == {"A": "B"}
    assert plugin._get_pool_id() == "pool-123"
    assert plugin._get_client_id() == "client-123"

    admin = mock.Mock()
    monkeypatch.setattr(plugin, "CognitoAdminClient", lambda **kwargs: admin)
    resolved_admin, resolved_runtime = plugin._get_admin_client()
    assert resolved_admin is admin
    assert resolved_runtime is runtime
    assert admin.user_pool_id == "pool-123"
    assert admin.app_client_id == "client-123"

    bad_runtime = _runtime(path=path, values={})
    monkeypatch.setattr(plugin, "_get_runtime_config", lambda **kwargs: bad_runtime)
    with pytest.raises(SystemExit):
        plugin._get_pool_id()
    with pytest.raises(SystemExit):
        plugin._get_client_id()


def test_select_config_client_and_resolve_values_from_aws(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    admin = mock.Mock()
    pool_id = "pool-123"
    monkeypatch.setattr(
        plugin.app_client_admin,
        "list_app_clients",
        lambda admin, user_pool_id=None: [{"ClientId": "client-123", "ClientName": "web-client"}],
    )
    monkeypatch.setattr(
        plugin.app_client_admin,
        "describe_app_client",
        lambda admin, user_pool_id=None, client_name=None, client_id=None: {
            "ClientId": "client-123",
            "ClientName": "web-client",
            "CallbackURLs": ["https://example.test/callback"],
            "LogoutURLs": ["https://example.test/logout"],
        },
    )

    assert plugin._select_config_client(admin, pool_id, client_name="web-client") == {
        "client_id": "client-123",
        "client_name": "web-client",
        "callback_url": "https://example.test/callback",
        "logout_url": "https://example.test/logout",
    }

    monkeypatch.setattr(plugin.app_client_admin, "list_app_clients", lambda admin, user_pool_id=None: [])
    assert plugin._select_config_client(admin, pool_id) is None

    monkeypatch.setattr(
        plugin.app_client_admin,
        "list_app_clients",
        lambda admin, user_pool_id=None: [
            {"ClientId": "client-123", "ClientName": "web-client"},
            {"ClientId": "client-456", "ClientName": "api-client"},
        ],
    )
    with pytest.raises(click.exceptions.Exit):
        plugin._select_config_client(admin, pool_id)
    with pytest.raises(click.exceptions.Exit):
        plugin._select_config_client(admin, pool_id, client_name="web-client", client_id="client-123")

    monkeypatch.setattr(
        plugin.app_client_admin,
        "list_app_clients",
        lambda admin, user_pool_id=None: [{"ClientId": "client-123", "ClientName": "web-client"}],
    )
    monkeypatch.setattr(
        plugin.pool_admin,
        "resolve_pool",
        lambda admin, pool_name=None, pool_id=None: {
            "pool_id": "pool-123",
            "pool_name": "ursa-users",
            "pool_info": {"Domain": "auth-prefix"},
        },
    )
    monkeypatch.setattr(
        plugin,
        "_get_admin_client",
        lambda **kwargs: (admin, _runtime(path=tmp_path / "config.yaml", values={"AWS_PROFILE": "dev-profile"})),
    )
    monkeypatch.setattr(plugin, "active_config_path", lambda: tmp_path / "config.yaml")

    path, values = plugin._resolve_config_values_from_aws(
        pool_name="ursa-users",
        pool_id=None,
        client_name="web-client",
        client_id=None,
        callback_url=None,
        logout_url=None,
        profile="dev-profile",
        region="us-west-2",
        existing={"KEEP": "yes"},
    )
    assert path == tmp_path / "config.yaml"
    assert values["KEEP"] == "yes"
    assert values["COGNITO_APP_CLIENT_ID"] == "client-123"
    assert values["COGNITO_DOMAIN"] == "auth-prefix.auth.us-west-2.amazoncognito.com"

    monkeypatch.setattr(plugin, "_select_config_client", lambda *args, **kwargs: None)
    with pytest.raises(click.exceptions.Exit):
        plugin._resolve_config_values_from_aws(
            pool_name="ursa-users",
            pool_id=None,
            client_name=None,
            client_id=None,
            callback_url=None,
            logout_url=None,
            profile="dev-profile",
            region="us-west-2",
            existing={},
        )


def test_cli_commands_cover_create_update_and_print_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    app = create_app(spec)
    config_path = tmp_path / "config.yaml"
    _write_yaml(
        config_path,
        {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
            "AWS_PROFILE": "dev-profile",
        },
    )

    result = runner.invoke(app, ["--config", str(config_path), "auth-config", "print"])
    assert result.exit_code == 0
    assert "COGNITO_USER_POOL_ID=pool-123" in result.stdout

    result = runner.invoke(app, ["--config", str(config_path), "--json", "auth-config", "print"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["config_path"] == str(config_path)
    assert payload["values"]["COGNITO_APP_CLIENT_ID"] == "client-123"

    output_path = tmp_path / "written.yaml"
    monkeypatch.setattr(plugin, "active_config_path", lambda: output_path)
    monkeypatch.setattr(
        plugin,
        "_resolve_config_values_from_aws",
        lambda **kwargs: (
            output_path,
            {
                "AWS_PROFILE": "dev-profile",
                "AWS_REGION": "us-west-2",
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "pool-123",
                "COGNITO_APP_CLIENT_ID": "client-123",
            },
        ),
    )
    monkeypatch.setattr(plugin, "_write_effective_config", lambda values: output_path)
    create_result = runner.invoke(
        app,
        [
            "auth-config",
            "create",
            "--pool-name",
            "ursa-users",
            "--client-name",
            "web-client",
            "--profile",
            "dev-profile",
            "--region",
            "us-west-2",
        ],
    )
    assert create_result.exit_code == 0
    assert "COGNITO_USER_POOL_ID=pool-123" in create_result.stdout

    monkeypatch.setattr(
        plugin,
        "load_config_file",
        lambda path, require_required_keys=True: {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
            "AWS_PROFILE": "dev-profile",
        },
    )
    update_result = runner.invoke(
        app,
        [
            "auth-config",
            "update",
            "--pool-name",
            "ursa-users",
            "--client-name",
            "web-client",
            "--profile",
            "dev-profile",
            "--region",
            "us-west-2",
        ],
    )
    assert update_result.exit_code == 0
    assert "COGNITO_USER_POOL_ID=pool-123" in update_result.stdout
