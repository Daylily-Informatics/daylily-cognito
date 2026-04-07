from __future__ import annotations

import json
from importlib.metadata import version as dist_version

from cli_core_yo.app import create_app
from typer.testing import CliRunner

from daylily_auth_cognito.cli.spec import spec

runner = CliRunner()


def _app():
    return create_app(spec)


def test_cli_spec_uses_platform_v2_without_runtime_guard() -> None:
    assert spec.policy.profile == "platform-v2"
    assert spec.runtime is None
    assert spec.config is not None
    assert spec.plugins.explicit == ["daylily_auth_cognito.cli.plugins.register"]


def test_cli_registry_exposes_v2_command_tree_and_policies() -> None:
    app = _app()
    registry = app._cli_core_yo_registry

    for argv in (
        ["version"],
        ["info"],
        ["status"],
        ["config", "path"],
        ["config", "init"],
        ["auth-config", "print"],
        ["auth-config", "create"],
        ["list-pools"],
        ["setup"],
        ["list-users"],
    ):
        assert registry.resolve_command_args(argv) is not None

    version_cmd = registry.get_command(("version",))
    info_cmd = registry.get_command(("info",))
    status_cmd = registry.get_command(("status",))
    config_path_cmd = registry.get_command(("config", "path"))
    config_init_cmd = registry.get_command(("config", "init"))
    auth_config_print_cmd = registry.get_command(("auth-config", "print"))
    auth_config_create_cmd = registry.get_command(("auth-config", "create"))
    setup_cmd = registry.get_command(("setup",))

    assert version_cmd is not None
    assert version_cmd.policy.runtime_guard == "exempt"
    assert version_cmd.policy.supports_json is True

    assert info_cmd is not None
    assert info_cmd.policy.runtime_guard == "exempt"
    assert info_cmd.policy.supports_json is True

    assert status_cmd is not None
    assert status_cmd.policy.runtime_guard == "exempt"
    assert status_cmd.policy.supports_json is True

    assert config_path_cmd is not None
    assert config_path_cmd.policy.runtime_guard == "exempt"
    assert config_path_cmd.policy.supports_json is True

    assert config_init_cmd is not None
    assert config_init_cmd.policy.runtime_guard == "exempt"
    assert config_init_cmd.policy.mutates_state is True

    assert auth_config_print_cmd is not None
    assert auth_config_print_cmd.policy.runtime_guard == "exempt"
    assert auth_config_print_cmd.policy.supports_json is True

    assert auth_config_create_cmd is not None
    assert auth_config_create_cmd.policy.mutates_state is True

    assert setup_cmd is not None
    assert setup_cmd.policy.mutates_state is True


def test_root_json_is_global_for_version() -> None:
    result = runner.invoke(_app(), ["--json", "version"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["app"] == "Daycog CLI"
    assert payload["version"] == dist_version("daylily-auth-cognito")


def test_root_json_is_global_for_info(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    result = runner.invoke(_app(), ["--json", "info"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["Version"] == dist_version("daylily-auth-cognito")
    assert payload["CLI Core"] == dist_version("cli-core-yo")
    assert payload["Config Dir"] == str((tmp_path / "config" / "daycog").resolve())


def test_json_rejected_for_non_json_command(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    result = runner.invoke(_app(), ["--json", "config", "init"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "contract_violation"
    assert payload["error"]["details"]["command"] == "config/init"


def test_config_path_is_available_without_runtime(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    result = runner.invoke(_app(), ["--json", "config", "path"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["config_path"] == str((tmp_path / "config" / "daycog" / "config.yaml").resolve())
