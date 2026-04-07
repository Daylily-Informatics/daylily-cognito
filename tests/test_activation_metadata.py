from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback for CI
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_activate_uses_new_distribution_name_and_dev_extra_only() -> None:
    activate_script = (REPO_ROOT / "activate").read_text(encoding="utf-8")

    assert "daylily-auth-cognito" in activate_script
    assert "Editable project location" in activate_script
    assert "daylily-auth-cognito is not installed editable from" in activate_script
    assert 'python -m pip install --no-build-isolation -e "${_DAYCOG_ACTIVATE_DIR}[dev]"' in activate_script
    assert "[dev,auth]" not in activate_script
    assert "daylily" + "-cognito" not in activate_script
    assert "../cli-core-yo" not in activate_script
    assert "_DAYCOG_CLI_CORE_YO_DIR" not in activate_script
    assert "Using cli-core-yo from sibling checkout via PYTHONPATH" not in activate_script
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in activate_script
    assert "python -m pip install --upgrade pip setuptools wheel setuptools-scm build" in activate_script


def test_pyproject_uses_new_distribution_name_and_base_jose_dependency() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["name"] == "daylily-auth-cognito"
    assert "cli-core-yo==2.0.0" in pyproject["project"]["dependencies"]
    assert "python-jose[cryptography]>=3.3.0" in pyproject["project"]["dependencies"]
    assert "auth" not in pyproject["project"].get("optional-dependencies", {})
    assert pyproject["project"]["scripts"]["daycog"] == "daylily_auth_cognito.cli.main:main"


def test_activate_reads_cli_core_requirement_from_pyproject() -> None:
    activate_script = (REPO_ROOT / "activate").read_text(encoding="utf-8")
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    cli_core_requirement = next(
        dependency
        for dependency in pyproject["project"]["dependencies"]
        if dependency.startswith("cli-core-yo")
    )

    assert cli_core_requirement == "cli-core-yo==2.0.0"
    assert cli_core_requirement not in activate_script
    assert 'PYTHONPATH="" python - "$_DAYCOG_ACTIVATE_DIR/pyproject.toml"' in activate_script
    assert "tomllib.loads" in activate_script
    assert "Requirement(requirement_text)" in activate_script
    assert 'importlib.metadata.version("cli-core-yo")' in activate_script
