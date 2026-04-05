import importlib
import importlib.metadata as metadata
import sys


def test_public_api_exports_expected_symbols() -> None:
    import daylily_cognito as package

    assert package.__version__
    assert "CognitoConfig" in package.__all__
    assert "CognitoAuth" in package.__all__
    assert package.CognitoConfig.__name__ == "CognitoConfig"
    assert package.CognitoAuth.__name__ == "CognitoAuth"


def test_version_fallback_when_package_metadata_is_missing(monkeypatch) -> None:
    original_module = sys.modules.get("daylily_cognito")

    def raise_package_not_found(_: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", raise_package_not_found)
    sys.modules.pop("daylily_cognito", None)

    try:
        package = importlib.import_module("daylily_cognito")
        assert package.__version__ == "0.0.0"
    finally:
        sys.modules.pop("daylily_cognito", None)
        if original_module is not None:
            sys.modules["daylily_cognito"] = original_module
