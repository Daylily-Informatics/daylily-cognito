"""CLI wiring tests for the split daycog surface."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import yaml
from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli import main as cli_main
from daylily_auth_cognito.cli.plugins import status as status_plugin
from daylily_auth_cognito.cli.spec import spec


def _write_config(path: Path) -> Path:
    path.write_text(
        yaml.safe_dump(
            {
                "AWS_PROFILE": "dev-profile",
                "COGNITO_REGION": "us-west-2",
                "COGNITO_USER_POOL_ID": "pool-123",
                "COGNITO_APP_CLIENT_ID": "client-123",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def test_root_help_exposes_curated_command_groups() -> None:
    runner = CliRunner()
    app = create_app(spec)

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "auth-config" in result.stdout
    assert "status" in result.stdout
    assert "setup" in result.stdout
    assert "add-app" in result.stdout


def test_auth_config_print_reads_flat_config(tmp_path: Path) -> None:
    runner = CliRunner()
    app = create_app(spec)
    config_path = _write_config(tmp_path / "config.yaml")

    result = runner.invoke(app, ["--config", str(config_path), "auth-config", "print"])

    assert result.exit_code == 0
    assert str(config_path).replace("\n", "") in result.stdout.replace("\n", "")
    assert "COGNITO_USER_POOL_ID=pool-123" in result.stdout
    assert "COGNITO_APP_CLIENT_ID=client-123" in result.stdout


def test_status_json_reports_pool_state(monkeypatch) -> None:
    runner = CliRunner()
    app = create_app(spec)

    fake_admin = SimpleNamespace(
        cognito=SimpleNamespace(describe_user_pool=lambda UserPoolId: {"UserPool": {"Name": "ursa-users"}})
    )
    fake_runtime = SimpleNamespace(
        path=Path("/tmp/daycog.yaml"),
        aws_region="us-west-2",
        values={
            "COGNITO_USER_POOL_ID": "pool-123",
            "COGNITO_APP_CLIENT_ID": "client-123",
        },
    )
    monkeypatch.setattr(status_plugin.plugin_config, "_get_admin_client", lambda **kwargs: (fake_admin, fake_runtime))

    result = runner.invoke(app, ["--json", "status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "config_path": "/tmp/daycog.yaml",
        "region": "us-west-2",
        "pool_id": "pool-123",
        "client_id": "client-123",
        "pool_name": "ursa-users",
        "status": "active",
    }


def test_main_exits_using_cli_core_run(monkeypatch) -> None:
    monkeypatch.setattr(cli_main, "run", lambda current_spec: 7)
    monkeypatch.setattr(cli_main.sys, "exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))

    try:
        cli_main.main()
    except SystemExit as exc:
        assert exc.code == 7
    else:  # pragma: no cover
        raise AssertionError("main() did not exit")
