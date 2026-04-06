from __future__ import annotations

import re
from pathlib import Path


def test_activate_uses_metadata_only_editable_detection() -> None:
    activate_script = (Path(__file__).resolve().parents[1] / "activate").read_text(encoding="utf-8")

    assert "daylily-cognito" in activate_script
    assert "Editable project location" in activate_script
    assert "daylily-cognito is not installed editable from" in activate_script
    assert "_daycog_module_is_from_repo" not in activate_script
    assert 'python -m pip install --no-build-isolation -e "${_DAYCOG_ACTIVATE_DIR}[dev,auth]"' in activate_script


def test_activate_reads_cli_core_requirement_from_pyproject() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    activate_script = (repo_root / "activate").read_text(encoding="utf-8")
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^\s*"(?P<dependency>cli-core-yo[^"]+)",\s*$', pyproject_text, re.MULTILINE)

    assert match is not None
    cli_core_requirement = match.group("dependency")

    assert cli_core_requirement.startswith("cli-core-yo")
    assert cli_core_requirement not in activate_script
    assert 'PYTHONPATH="" python - "$_DAYCOG_ACTIVATE_DIR/pyproject.toml"' in activate_script
    assert "tomllib.loads" in activate_script
    assert "Requirement(requirement_text)" in activate_script
    assert 'importlib.metadata.version("cli-core-yo")' in activate_script
