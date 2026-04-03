from __future__ import annotations

from pathlib import Path


def test_activate_uses_metadata_only_editable_detection() -> None:
    activate_script = (Path(__file__).resolve().parents[1] / "activate").read_text(encoding="utf-8")

    assert "daylily-cognito" in activate_script
    assert "Editable project location" in activate_script
    assert "daylily-cognito is not installed editable from" in activate_script
    assert "_daycog_module_is_from_repo" not in activate_script
    assert 'python -m pip install --no-build-isolation -e "${_DAYCOG_ACTIVATE_DIR}[dev,auth]"' in activate_script
