"""Seam tests for pool-oriented daycog commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
import typer
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import pools as pools_plugin
from daylily_auth_cognito.cli.spec import spec


def _runtime(values: dict[str, str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        path=Path("/tmp/daycog.yaml"),
        aws_region="us-west-2",
        values=values or {},
        require_aws_profile=lambda: "dev-profile",
    )


def _patch_admin(monkeypatch: pytest.MonkeyPatch, admin: object, runtime: object) -> None:
    monkeypatch.setattr(pools_plugin, "_get_admin_client", lambda **kwargs: (admin, runtime))


def _capture_messages(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    messages: list[str] = []
    monkeypatch.setattr(pools_plugin.ccyo_out, "info", lambda message: messages.append(str(message)))
    return messages


def test_list_pools_outputs_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    monkeypatch.setattr(
        pools_plugin,
        "list_user_pools",
        lambda current_admin: [
            {"Name": "ursa-users", "Id": "pool-123"},
            {"Name": "ursa-admins", "Id": "pool-456"},
        ],
    )

    result = runner.invoke(app, ["list-pools"])

    assert result.exit_code == 0
    assert "Cognito User Pools (us-west-2)" in result.stdout
    assert "ursa-users (pool-123)" in result.stdout
    assert "Total: 2 pools" in result.stdout


def test_setup_creates_pool_domain_client_and_writes_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    admin = SimpleNamespace(region="us-west-2", aws_profile="dev-profile", user_pool_id=None, app_client_id=None)
    runtime = _runtime(values={"EXISTING": "keep"})
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)

    monkeypatch.setattr(pools_plugin, "list_user_pools", lambda current_admin: [])
    monkeypatch.setattr(
        pools_plugin,
        "ensure_user_pool",
        lambda current_admin, **kwargs: {
            "pool_id": "pool-123",
            "pool_name": "ursa-users",
            "pool_info": {"Name": "ursa-users"},
        },
    )
    monkeypatch.setattr(pools_plugin, "ensure_user_pool_domain", lambda current_admin, **kwargs: "auth.example.test")
    monkeypatch.setattr(
        pools_plugin, "find_app_client", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("missing"))
    )
    create_calls: dict[str, object] = {}

    def fake_create_app_client(current_admin, **kwargs):
        create_calls.update(kwargs)
        return {"ClientId": "client-123", "ClientName": kwargs["client_name"]}

    monkeypatch.setattr(pools_plugin, "create_app_client", fake_create_app_client)
    monkeypatch.setattr(
        pools_plugin,
        "_write_effective_config",
        lambda values: tmp_path / "config.yaml",
    )

    pools_plugin.setup(
        pool_name="ursa-users",
        client_name="web-client",
        domain_prefix="auth",
        attach_domain=True,
        port=8001,
        callback_path="/auth/callback",
        callback_url=None,
        logout_url="https://example.test/logout",
        profile="dev-profile",
        region="us-west-2",
        print_exports=True,
        autoprovision=False,
        generate_secret=True,
        oauth_flows="code,refresh_token",
        scopes="openid,email",
        idps="COGNITO,Google",
        password_min_length=12,
        require_uppercase=False,
        require_lowercase=True,
        require_numbers=True,
        require_symbols=False,
        mfa="required",
        tags="env=dev,team=auth",
    )

    assert admin.app_client_id is None
    assert create_calls["client_name"] == "web-client"
    assert create_calls["allowed_oauth_flows"] == ["code", "refresh_token"]
    assert create_calls["allowed_oauth_scopes"] == ["openid", "email"]
    assert create_calls["callback_urls"] == ["http://localhost:8001/auth/callback"]
    assert create_calls["logout_urls"] == ["https://example.test/logout"]
    assert create_calls["supported_identity_providers"] == ["COGNITO", "Google"]
    assert create_calls["generate_secret"] is True
    assert create_calls["reuse_if_exists"] is False
    assert messages[0] == "Created user pool: ursa-users"
    assert "Attached hosted UI domain: auth" in messages
    assert "Created app client: client-123" in messages
    assert any(message.startswith("Wrote config file:") for message in messages)
    assert "COGNITO_USER_POOL_ID=pool-123" in messages
    assert "COGNITO_APP_CLIENT_ID=client-123" in messages
    assert "COGNITO_DOMAIN=auth.example.test" in messages
    assert 'export AWS_PROFILE="dev-profile"' in messages
    assert 'export AWS_REGION="us-west-2"' in messages


def test_setup_reuses_existing_pool_and_app_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    admin = SimpleNamespace(region="us-west-2", aws_profile="dev-profile", user_pool_id=None, app_client_id=None)
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)

    monkeypatch.setattr(
        pools_plugin,
        "list_user_pools",
        lambda current_admin: [{"Name": "ursa-users", "Id": "pool-123"}],
    )
    monkeypatch.setattr(
        pools_plugin,
        "ensure_user_pool",
        lambda current_admin, **kwargs: {
            "pool_id": "pool-123",
            "pool_name": "ursa-users",
            "pool_info": {"Name": "ursa-users", "Domain": "existing-domain"},
        },
    )
    monkeypatch.setattr(
        pools_plugin,
        "ensure_user_pool_domain",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected domain create")),
    )
    monkeypatch.setattr(
        pools_plugin,
        "find_app_client",
        lambda *args, **kwargs: {"client_id": "client-999", "client_name": "web-client"},
    )
    create_app_client_mock = mock.Mock(side_effect=AssertionError("unexpected create_app_client"))
    monkeypatch.setattr(pools_plugin, "create_app_client", create_app_client_mock)
    monkeypatch.setattr(
        pools_plugin,
        "_write_effective_config",
        lambda values: tmp_path / "config.yaml",
    )

    pools_plugin.setup(
        pool_name="ursa-users",
        client_name="web-client",
        domain_prefix="requested-domain",
        attach_domain=True,
        port=8001,
        callback_path="/auth/callback",
        callback_url=None,
        logout_url=None,
        profile="dev-profile",
        region="us-west-2",
        print_exports=False,
        autoprovision=True,
        generate_secret=False,
        oauth_flows="code",
        scopes="openid,email,profile",
        idps="COGNITO",
        password_min_length=8,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_symbols=False,
        mfa="off",
        tags=None,
    )

    assert admin.app_client_id == "client-999"
    assert create_app_client_mock.call_count == 0
    assert "User pool 'ursa-users' already exists" in messages
    assert (
        "Pool already has domain 'existing-domain' (requested 'requested-domain'). Keeping existing domain." in messages
    )
    assert "Reusing app client 'web-client': client-999" in messages
    assert "COGNITO_DOMAIN=existing-domain.auth.us-west-2.amazoncognito.com" in messages


def test_delete_pool_validates_and_honors_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    resolved_pool = {"pool_name": "ursa-users", "pool_id": "pool-123"}
    delete_pool_mock = mock.Mock()
    monkeypatch.setattr(pools_plugin, "resolve_pool", lambda *args, **kwargs: resolved_pool)
    monkeypatch.setattr(pools_plugin, "delete_user_pool", delete_pool_mock)
    monkeypatch.setattr(typer, "confirm", lambda prompt: False)

    with pytest.raises(typer.Exit) as exc_info:
        pools_plugin.delete_pool(pool_name=None, pool_id=None)
    assert exc_info.value.exit_code == 1
    assert "Provide one of: --pool-name or --pool-id" in messages[0]

    pools_plugin.delete_pool(pool_name="ursa-users", force=False, delete_domain_first=False)
    assert delete_pool_mock.call_count == 0
    assert messages[-1] == "Cancelled"

    monkeypatch.setattr(typer, "confirm", lambda prompt: True)
    pools_plugin.delete_pool(pool_name="ursa-users", force=True, delete_domain_first=False)
    delete_pool_mock.assert_called_once_with(admin, user_pool_id="pool-123", delete_domain_first=False)
    assert messages[-1] == "Deleted Cognito pool: ursa-users (pool-123)"


def test_teardown_and_fix_auth_flows_delegate_through_config_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime(values={"COGNITO_USER_POOL_ID": "pool-123", "COGNITO_APP_CLIENT_ID": "client-123"})
    _patch_admin(monkeypatch, admin, runtime)
    monkeypatch.setattr(pools_plugin, "_get_pool_id", lambda: "pool-123")
    monkeypatch.setattr(pools_plugin, "_get_client_id", lambda: "client-123")
    delete_pool_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        pools_plugin,
        "delete_pool",
        lambda **kwargs: delete_pool_calls.append(kwargs),
    )
    update_calls: list[object] = []
    monkeypatch.setattr(
        pools_plugin,
        "update_app_client_auth_flows",
        lambda current_admin: update_calls.append(current_admin) or {"ClientId": "client-123"},
    )
    messages = _capture_messages(monkeypatch)

    pools_plugin.teardown(pool_name="ursa-users", force=True)
    pools_plugin.fix_auth_flows()

    assert delete_pool_calls == [{"pool_name": "ursa-users", "pool_id": "pool-123", "force": True}]
    assert update_calls == [admin]
    assert messages[-1] == "Enabled auth flows on app client client-123"
