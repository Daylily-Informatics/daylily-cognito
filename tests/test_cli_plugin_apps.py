"""Seam tests for app-client daycog commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import typer
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import apps as apps_plugin
from daylily_auth_cognito.cli.spec import spec


def _runtime() -> SimpleNamespace:
    return SimpleNamespace(
        path=Path("/tmp/daycog.yaml"),
        aws_region="us-west-2",
        values={},
        require_aws_profile=lambda: "dev-profile",
    )


def _patch_admin(monkeypatch: pytest.MonkeyPatch, admin: object, runtime: object) -> None:
    monkeypatch.setattr(apps_plugin, "_get_admin_client", lambda **kwargs: (admin, runtime))


def _capture_messages(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    messages: list[str] = []
    monkeypatch.setattr(apps_plugin.ccyo_out, "info", lambda message: messages.append(str(message)))
    return messages


def test_list_apps_outputs_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    monkeypatch.setattr(apps_plugin, "find_user_pool_id_by_name", lambda current_admin, pool_name: "pool-123")
    monkeypatch.setattr(
        apps_plugin,
        "list_app_clients",
        lambda current_admin, user_pool_id=None: [
            {"ClientName": "web-client", "ClientId": "client-123"},
            {"ClientName": "batch-client", "ClientId": "client-456"},
        ],
    )

    result = runner.invoke(app, ["list-apps", "--pool-name", "ursa-users"])

    assert result.exit_code == 0
    assert "Cognito App Clients (ursa-users / us-west-2)" in result.stdout
    assert "web-client (client-123)" in result.stdout
    assert "Total: 2 app clients" in result.stdout


def test_add_app_creates_client_and_reports_duplicate_error(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    monkeypatch.setattr(apps_plugin, "find_user_pool_id_by_name", lambda current_admin, pool_name: "pool-123")
    create_calls: dict[str, object] = {}

    def fake_create_app_client(current_admin, **kwargs):
        create_calls.update(kwargs)
        return {"ClientId": "client-123", "ClientName": kwargs["client_name"]}

    monkeypatch.setattr(apps_plugin, "create_app_client", fake_create_app_client)

    apps_plugin.add_app(
        pool_name="ursa-users",
        app_name="web-client",
        profile="dev-profile",
        region="us-west-2",
        callback_url="http://localhost:8001/auth/callback",
        logout_url="http://localhost:8001/logout",
        generate_secret=True,
        oauth_flows="code,refresh_token",
        scopes="openid,email",
        idps="COGNITO,Google",
        set_default=True,
    )

    assert create_calls["client_name"] == "web-client"
    assert create_calls["allowed_oauth_flows"] == ["code", "refresh_token"]
    assert create_calls["allowed_oauth_scopes"] == ["openid", "email"]
    assert create_calls["callback_urls"] == ["http://localhost:8001/auth/callback"]
    assert create_calls["logout_urls"] == ["http://localhost:8001/logout"]
    assert create_calls["supported_identity_providers"] == ["COGNITO", "Google"]
    assert "Created app client: web-client (client-123)" in messages
    assert messages[-1] == "Run daycog auth-config update if you want the config file to point at this app."

    monkeypatch.setattr(
        apps_plugin,
        "create_app_client",
        mock.Mock(side_effect=ValueError("App client already exists: web-client")),
    )

    with pytest.raises(typer.Exit) as exc_info:
        apps_plugin.add_app(
            pool_name="ursa-users",
            app_name="web-client",
            profile="dev-profile",
            region="us-west-2",
            callback_url="http://localhost:8001/auth/callback",
            logout_url=None,
            generate_secret=False,
            oauth_flows="code",
            scopes="openid,email,profile",
            idps="COGNITO",
        )

    assert exc_info.value.exit_code == 1
    assert "App client already exists: web-client" in messages[-1]


def test_add_m2m_app_validates_and_emits_json(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    payloads: list[dict[str, object]] = []
    monkeypatch.setattr(apps_plugin.ccyo_out, "emit_json", lambda payload: payloads.append(payload))
    monkeypatch.setattr(apps_plugin, "find_user_pool_id_by_name", lambda current_admin, pool_name: "pool-123")
    monkeypatch.setattr(
        apps_plugin,
        "create_m2m_app_client",
        lambda current_admin, **kwargs: {"ClientId": "client-999", "ClientSecret": "secret-999"},
    )
    monkeypatch.setattr(apps_plugin, "get_context", lambda: SimpleNamespace(json_mode=True))

    apps_plugin.add_m2m_app(
        pool_name="ursa-users",
        app_name="worker-client",
        profile="dev-profile",
        region="us-west-2",
        scopes="api/read,api/write",
    )

    assert payloads == [
        {
            "pool_id": "pool-123",
            "client_name": "worker-client",
            "client_id": "client-999",
            "client_secret": "secret-999",
            "scopes": ["api/read", "api/write"],
        }
    ]

    with pytest.raises(typer.Exit) as exc_info:
        apps_plugin.add_m2m_app(
            pool_name="ursa-users",
            app_name="worker-client",
            profile="dev-profile",
            region="us-west-2",
            scopes="",
        )
    assert exc_info.value.exit_code == 1


def test_edit_and_remove_app_validate_and_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    monkeypatch.setattr(apps_plugin, "find_user_pool_id_by_name", lambda current_admin, pool_name: "pool-123")
    monkeypatch.setattr(
        apps_plugin, "find_app_client", lambda *args, **kwargs: {"client_id": "client-123", "client_name": "web-client"}
    )
    update_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        apps_plugin,
        "update_app_client",
        lambda current_admin, **kwargs: update_calls.append(kwargs) or kwargs,
    )
    delete_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        apps_plugin,
        "delete_app_client",
        lambda current_admin, **kwargs: delete_calls.append(kwargs) or True,
    )
    monkeypatch.setattr(typer, "confirm", lambda prompt: False)

    with pytest.raises(typer.Exit) as exc_info:
        apps_plugin.edit_app(pool_name="ursa-users", app_name=None, client_id=None)
    assert exc_info.value.exit_code == 1
    assert "Provide one of: --app-name or --client-id" in messages[-1]

    apps_plugin.edit_app(
        pool_name="ursa-users",
        app_name="web-client",
        client_id=None,
        new_app_name="web-client-v2",
        profile="dev-profile",
        region="us-west-2",
        callback_url="http://localhost:8001/callback",
        logout_url="http://localhost:8001/logout",
        oauth_flows="code,refresh_token",
        scopes="openid,email",
        idps="COGNITO,Google",
        set_default=True,
    )
    assert update_calls[0]["overrides"]["ClientName"] == "web-client-v2"
    assert update_calls[0]["overrides"]["CallbackURLs"] == ["http://localhost:8001/callback"]
    assert update_calls[0]["overrides"]["LogoutURLs"] == ["http://localhost:8001/logout"]
    assert update_calls[0]["overrides"]["AllowedOAuthFlows"] == ["code", "refresh_token"]
    assert update_calls[0]["overrides"]["AllowedOAuthScopes"] == ["openid", "email"]
    assert update_calls[0]["overrides"]["SupportedIdentityProviders"] == ["COGNITO", "Google"]
    assert "Updated app client: web-client-v2 (client-123)" in messages
    assert messages[-1] == "Run daycog auth-config update if you want the config file to point at this app."

    apps_plugin.remove_app(pool_name="ursa-users", app_name="web-client", force=False)
    assert delete_calls == []
    assert messages[-1] == "Cancelled"

    monkeypatch.setattr(typer, "confirm", lambda prompt: True)
    apps_plugin.remove_app(pool_name="ursa-users", client_id="client-123", force=True)
    assert delete_calls == [{"user_pool_id": "pool-123", "client_id": "client-123"}]
    assert messages[-1] == "Deleted app client: web-client (client-123)"
