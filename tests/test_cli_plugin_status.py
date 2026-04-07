"""Seam tests for daylily_auth_cognito.cli.plugins.status."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.plugins import config as plugin_config
from daylily_auth_cognito.cli.spec import spec


def _runtime(
    *,
    path: Path,
    region: str = "us-west-2",
    pool_id: str = "",
    client_id: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        path=path,
        aws_region=region,
        values={
            "COGNITO_USER_POOL_ID": pool_id,
            "COGNITO_APP_CLIENT_ID": client_id,
        },
    )


def test_status_json_active_and_error_branches(monkeypatch) -> None:
    runner = CliRunner()
    app = create_app(spec)

    active_admin = SimpleNamespace(
        cognito=SimpleNamespace(describe_user_pool=lambda UserPoolId: {"UserPool": {"Name": "ursa-users"}})
    )
    active_runtime = _runtime(path=Path("/tmp/daycog.yaml"), pool_id="pool-123", client_id="client-123")
    monkeypatch.setattr(
        plugin_config,
        "_get_admin_client",
        lambda **kwargs: (active_admin, active_runtime),
    )

    result = runner.invoke(app, ["--json", "status"])
    assert result.exit_code == 0
    assert '"status": "active"' in result.stdout
    assert '"pool_name": "ursa-users"' in result.stdout

    error_admin = SimpleNamespace(
        cognito=SimpleNamespace(describe_user_pool=lambda UserPoolId: (_ for _ in ()).throw(RuntimeError("boom")))
    )
    monkeypatch.setattr(
        plugin_config,
        "_get_admin_client",
        lambda **kwargs: (error_admin, active_runtime),
    )

    result = runner.invoke(app, ["--json", "status"])
    assert result.exit_code == 0
    assert '"status": "error: boom"' in result.stdout


def test_status_human_active_and_unconfigured_branches(monkeypatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    captured_tables = []
    captured_lines = []

    monkeypatch.setattr(plugin_config, "_print_rich", lambda table: captured_tables.append(table))
    monkeypatch.setattr(plugin_config.ccyo_out, "info", lambda message: captured_lines.append(message))

    active_admin = SimpleNamespace(
        cognito=SimpleNamespace(describe_user_pool=lambda UserPoolId: {"UserPool": {"Name": "ursa-users"}})
    )
    active_runtime = _runtime(path=Path("/tmp/daycog.yaml"), pool_id="pool-123", client_id="client-123")
    monkeypatch.setattr(
        plugin_config,
        "_get_admin_client",
        lambda **kwargs: (active_admin, active_runtime),
    )

    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert captured_tables
    assert captured_lines == ["[cyan]Checking Cognito configuration...[/cyan]\n"]

    captured_tables.clear()
    captured_lines.clear()
    unconfigured_runtime = _runtime(path=Path("/tmp/daycog.yaml"))
    monkeypatch.setattr(
        plugin_config,
        "_get_admin_client",
        lambda **kwargs: (active_admin, unconfigured_runtime),
    )

    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert captured_tables
    assert any("Cognito not fully configured" in line for line in captured_lines)


def test_status_generic_error_exits(monkeypatch) -> None:
    runner = CliRunner()
    app = create_app(spec)
    monkeypatch.setattr(
        plugin_config, "_get_admin_client", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "Error: boom" in result.stdout
