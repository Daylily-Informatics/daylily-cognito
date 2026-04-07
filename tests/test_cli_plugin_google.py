"""Seam tests for daylily_auth_cognito.cli.plugins.google."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
import yaml
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import config as plugin_config
from daylily_auth_cognito.cli.plugins import google as plugin
from daylily_auth_cognito.cli.spec import spec


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_yaml(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_google_client_details_resolution_covers_direct_json_config_and_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    json_path = _write_json(
        tmp_path / "google-client.json",
        {"web": {"client_id": "gid-web", "client_secret": "gsecret-web"}},
    )
    assert plugin._resolve_google_client_details(
        google_client_id=None,
        google_client_secret=None,
        google_client_json=str(json_path),
    ) == ("gid-web", "gsecret-web")

    monkeypatch.setattr(
        plugin_config,
        "load_config_file",
        lambda path, require_required_keys=True: {
            "GOOGLE_CLIENT_ID": "gid-config",
            "GOOGLE_CLIENT_SECRET": "gsecret-config",
        },
    )
    monkeypatch.setattr(plugin_config, "active_config_path", lambda: tmp_path / "daycog.yaml")
    assert plugin._resolve_google_client_details(
        google_client_id=None,
        google_client_secret=None,
        google_client_json=None,
    ) == ("gid-config", "gsecret-config")

    monkeypatch.setattr(
        plugin_config,
        "load_config_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(plugin_config.ConfigError("missing")),
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


def test_add_google_idp_requires_app_or_client(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_app(spec)

    result = runner.invoke(app, ["add-google-idp", "--pool-name", "ursa-users"])

    assert result.exit_code == 1
    assert "Provide one of: --app-name or --client-id" in result.stdout


def test_add_google_idp_success_delegates_to_admin_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    calls: list[tuple[str, dict[str, object]]] = []

    admin = SimpleNamespace(region="us-west-2")
    monkeypatch.setattr(
        plugin,
        "_get_admin_client",
        lambda **kwargs: (admin, SimpleNamespace()),
    )
    monkeypatch.setattr(plugin, "find_user_pool_id_by_name", lambda admin, pool_name: "pool-123")
    monkeypatch.setattr(
        plugin,
        "_resolve_google_client_details",
        lambda **kwargs: ("gid-123", "gsecret-123"),
    )

    def _fake_ensure_google_federation(*args, **kwargs):
        calls.append(("ensure", kwargs))
        return {"client_name": "web-client", "client_id": "client-123"}

    monkeypatch.setattr(plugin, "ensure_google_federation", _fake_ensure_google_federation)

    result = runner.invoke(
        app,
        [
            "add-google-idp",
            "--pool-name",
            "ursa-users",
            "--app-name",
            "web-client",
            "--scopes",
            "openid email profile",
        ],
    )

    assert result.exit_code == 0
    assert calls[0][0] == "ensure"
    assert calls[0][1]["google_client_id"] == "gid-123"
    assert calls[0][1]["scopes"] == "openid email profile"
    assert "Enabled Google provider on app client: web-client (client-123)" in result.stdout


def test_setup_with_google_sequences_setup_and_config_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    app = create_app(spec)
    calls: list[str] = []
    config_path = tmp_path / "daycog.yaml"
    _write_yaml(
        config_path,
        {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
        },
    )

    monkeypatch.setattr(plugin, "setup", lambda **kwargs: calls.append("setup"))
    monkeypatch.setattr(plugin, "add_google_idp", lambda **kwargs: calls.append("add-google-idp"))
    monkeypatch.setattr(plugin, "_resolve_google_client_details", lambda **kwargs: ("gid-123", "gsecret-123"))
    monkeypatch.setattr(plugin, "active_config_path", lambda: config_path)
    monkeypatch.setattr(
        plugin_config,
        "load_config_file",
        lambda path, require_required_keys=True: {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
            "GOOGLE_CLIENT_ID": "old",
            "GOOGLE_CLIENT_SECRET": "old",
        },
    )
    monkeypatch.setattr(plugin, "_write_effective_config", lambda values: config_path)

    result = runner.invoke(
        app,
        [
            "setup-with-google",
            "--name",
            "ursa-users",
            "--client-name",
            "web-client",
            "--profile",
            "dev-profile",
            "--region",
            "us-west-2",
        ],
    )

    assert result.exit_code == 0
    assert calls == ["setup", "add-google-idp"]
    assert "Setup with Google IdP complete" in result.stdout


def test_setup_google_success_and_config_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    app = create_app(spec)
    config_path = tmp_path / "daycog.yaml"
    _write_yaml(
        config_path,
        {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
        },
    )

    monkeypatch.setattr(plugin, "active_config_path", lambda: config_path)
    monkeypatch.setattr(
        plugin,
        "load_config_file",
        lambda path, require_required_keys=True: {
            "COGNITO_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
        },
    )
    monkeypatch.setattr(plugin, "_write_effective_config", lambda values: config_path)

    result = runner.invoke(
        app,
        [
            "setup-google",
            "--client-id",
            "gid-123",
            "--client-secret",
            "gsecret-123",
            "--port",
            "9000",
        ],
    )

    assert result.exit_code == 0
    assert "Wrote Google OAuth credentials" in result.stdout
    assert "http://localhost:9000/auth/google/callback" in result.stdout

    monkeypatch.setattr(
        plugin, "load_config_file", lambda *args, **kwargs: (_ for _ in ()).throw(plugin.ConfigError("missing config"))
    )
    result = runner.invoke(
        app,
        [
            "setup-google",
            "--client-id",
            "gid-123",
            "--client-secret",
            "gsecret-123",
        ],
    )
    assert result.exit_code == 1
    assert "missing config" in result.stdout
