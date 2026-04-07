"""Static boundary tests for the split package layout."""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "daylily_auth_cognito"


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None:
                modules.add(node.module)
    return modules


def test_runtime_has_no_boto3_imports() -> None:
    for path in sorted((PACKAGE_ROOT / "runtime").rglob("*.py")):
        imports = _imported_modules(path)
        assert all(module.split(".", 1)[0] != "boto3" for module in imports), path


def test_non_cli_modules_do_not_import_cli_frameworks() -> None:
    forbidden_roots = {"cli_core_yo", "typer", "rich"}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "/cli/" in path.as_posix():
            continue
        imports = _imported_modules(path)
        assert all(module.split(".", 1)[0] not in forbidden_roots for module in imports), path


def test_runtime_and_browser_do_not_import_cli_package() -> None:
    for boundary in ["runtime", "browser", "admin", "policy"]:
        for path in sorted((PACKAGE_ROOT / boundary).rglob("*.py")):
            imports = _imported_modules(path)
            assert all(not module.startswith("daylily_auth_cognito.cli") for module in imports), path
