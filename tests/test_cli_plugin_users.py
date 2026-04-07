"""Seam tests for user-management daycog commands."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import users as users_plugin
from daylily_auth_cognito.cli.spec import spec


def _runtime() -> SimpleNamespace:
    return SimpleNamespace(
        path=Path("/tmp/daycog.yaml"),
        aws_region="us-west-2",
        values={},
        require_aws_profile=lambda: "dev-profile",
    )


def _patch_admin(monkeypatch: pytest.MonkeyPatch, admin: object, runtime: object) -> None:
    monkeypatch.setattr(users_plugin, "_get_admin_client", lambda **kwargs: (admin, runtime))


def _capture_messages(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    messages: list[str] = []
    monkeypatch.setattr(users_plugin.ccyo_out, "info", lambda message: messages.append(str(message)))
    return messages


def test_set_password_and_group_commands_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    set_password_calls: list[tuple[str, str, bool]] = []
    ensure_group_calls: list[tuple[str, str]] = []
    add_to_group_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        users_plugin,
        "set_user_password",
        lambda current_admin, **kwargs: set_password_calls.append(
            (kwargs["email"], kwargs["password"], kwargs["permanent"])
        ),
    )
    monkeypatch.setattr(
        users_plugin,
        "ensure_group",
        lambda current_admin, **kwargs: (
            ensure_group_calls.append((kwargs["group_name"], kwargs["description"])) or True
        ),
    )
    monkeypatch.setattr(
        users_plugin,
        "add_user_to_group",
        lambda current_admin, **kwargs: add_to_group_calls.append((kwargs["email"], kwargs["group_name"])),
    )

    result = runner.invoke(app, ["set-password", "--email", "user@example.test", "--password", "Secret123"])

    assert result.exit_code == 0
    assert set_password_calls == [("user@example.test", "Secret123", True)]

    users_plugin.ensure_group_cmd(group_name="scientists", description="Research team")
    users_plugin.add_user_to_group_cmd(email="user@example.test", group_name="scientists")

    assert ensure_group_calls == [("scientists", "Research team")]
    assert add_to_group_calls == [("user@example.test", "scientists")]
    assert "Created: scientists" in messages or "Group already exists: scientists" in messages
    assert "Added user@example.test to group: scientists" in messages


def test_set_user_attributes_validation_and_update(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    attribute_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        users_plugin, "set_user_attributes", lambda current_admin, **kwargs: attribute_calls.append(kwargs)
    )

    with pytest.raises(typer.Exit) as exc_info:
        users_plugin.set_user_attributes_cmd(email="user@example.test", attribute=[])
    assert exc_info.value.exit_code == 1
    assert "Provide at least one --attribute Name=Value pair" in messages[0]

    users_plugin.set_user_attributes_cmd(email="user@example.test", attribute=["custom:role=scientist", "title=Lead"])

    assert attribute_calls == [
        {
            "email": "user@example.test",
            "attributes": [
                {"Name": "custom:role", "Value": "scientist"},
                {"Name": "title", "Value": "Lead"},
            ],
        }
    ]
    assert messages[-1] == "Updated attributes for: user@example.test"


def test_add_user_covers_temp_permanent_and_no_verify_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    create_calls: list[dict[str, object]] = []
    password_calls: list[dict[str, object]] = []
    monkeypatch.setattr(users_plugin, "generate_temporary_password", lambda: "TEMP-123456")
    monkeypatch.setattr(users_plugin, "create_user", lambda current_admin, **kwargs: create_calls.append(kwargs))
    monkeypatch.setattr(
        users_plugin, "set_user_password", lambda current_admin, **kwargs: password_calls.append(kwargs)
    )

    users_plugin.add_user(email="user@example.test", password=None, no_verify=False)
    users_plugin.add_user(email="user@example.test", password="Manual123", no_verify=False)
    users_plugin.add_user(email="user@example.test", password="Permanent123", no_verify=True)

    assert create_calls[0]["temporary_password"] == "TEMP-123456"
    assert create_calls[0]["suppress_message"] is True
    assert create_calls[1]["temporary_password"] == "Manual123"
    assert create_calls[2]["email_verified"] is True
    assert password_calls == [{"email": "user@example.test", "password": "Permanent123", "permanent": True}]
    assert "Temporary password: TEMP-123456" in messages
    assert "Password set (temporary - must change on first login)" in messages
    assert "Password set (permanent)" in messages


def test_list_export_delete_and_delete_all_users(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    admin = SimpleNamespace()
    runtime = _runtime()
    _patch_admin(monkeypatch, admin, runtime)
    messages = _capture_messages(monkeypatch)
    monkeypatch.setattr(
        users_plugin,
        "list_users",
        lambda current_admin, limit=None: [
            {
                "Username": "user@example.test",
                "UserStatus": "CONFIRMED",
                "Enabled": True,
                "Attributes": [
                    {"Name": "email", "Value": "user@example.test"},
                    {"Name": "custom:customer_id", "Value": "CUST-42"},
                ],
            }
        ],
    )
    monkeypatch.setattr(
        users_plugin,
        "export_users",
        lambda current_admin: {
            "exported_at": "2024-01-01T00:00:00+00:00",
            "pool_id": "pool-123",
            "region": "us-west-2",
            "user_count": 1,
            "users": [
                {
                    "username": "user@example.test",
                    "status": "CONFIRMED",
                    "enabled": True,
                    "created": None,
                    "modified": None,
                    "attributes": {"email": "user@example.test"},
                }
            ],
        },
    )
    delete_user_calls: list[str] = []
    monkeypatch.setattr(
        users_plugin, "delete_user", lambda current_admin, **kwargs: delete_user_calls.append(kwargs["email"]) or False
    )
    delete_all_calls: list[object] = []
    monkeypatch.setattr(
        users_plugin, "delete_all_users", lambda current_admin: delete_all_calls.append(current_admin) or 2
    )

    users_plugin.list_users_cmd(limit=1)
    output_file = tmp_path / "users.json"
    users_plugin.export_users_cmd(output=str(output_file))
    assert json.loads(output_file.read_text(encoding="utf-8"))["user_count"] == 1

    monkeypatch.setattr(typer, "confirm", lambda prompt: False)
    users_plugin.delete_user_cmd(email="user@example.test", force=False)
    assert delete_user_calls == []
    assert messages[-1] == "Cancelled"

    monkeypatch.setattr(typer, "confirm", lambda prompt: True)
    with pytest.raises(typer.Exit) as exc_info:
        users_plugin.delete_user_cmd(email="user@example.test", force=True)
    assert exc_info.value.exit_code == 1
    assert delete_user_calls == ["user@example.test"]
    assert messages[-1] == "Failed to delete user: user@example.test"

    monkeypatch.setattr(typer, "confirm", lambda prompt: False)
    users_plugin.delete_all_users_cmd(force=False)
    assert delete_all_calls == []
    assert messages[-1] == "Cancelled"

    monkeypatch.setattr(typer, "confirm", lambda prompt: True)
    users_plugin.delete_all_users_cmd(force=True)
    assert delete_all_calls == [admin]
    assert messages[-1] == "Deleted 2 users"
