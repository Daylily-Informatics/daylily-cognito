import importlib
import sys
from importlib import metadata

EXPECTED_ALL = [
    "CognitoWebSessionConfig",
    "SessionPrincipal",
    "configure_session_middleware",
    "start_cognito_login",
    "complete_cognito_callback",
    "load_session_principal",
    "store_session_principal",
    "clear_session_principal",
    "CognitoTokenVerifier",
    "create_auth_dependency",
    "JWKSCache",
    "verify_m2m_token_with_jwks",
    "__version__",
]


def test_public_api_exports_curated_symbols() -> None:
    import daylily_auth_cognito as package

    assert package.__all__ == EXPECTED_ALL
    assert package.__version__
    assert not hasattr(package, "CognitoAuth")
    assert not hasattr(package, "CognitoConfig")
    for name in EXPECTED_ALL:
        assert hasattr(package, name)


def test_version_fallback_when_package_metadata_is_missing(monkeypatch) -> None:
    original_package = sys.modules.pop("daylily_auth_cognito", None)
    original_version = sys.modules.pop("daylily_auth_cognito.version", None)

    def raise_package_not_found(_: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", raise_package_not_found)

    try:
        package = importlib.import_module("daylily_auth_cognito")
        assert package.__version__ == "0.0.0"
    finally:
        sys.modules.pop("daylily_auth_cognito", None)
        sys.modules.pop("daylily_auth_cognito.version", None)
        if original_version is not None:
            sys.modules["daylily_auth_cognito.version"] = original_version
        if original_package is not None:
            sys.modules["daylily_auth_cognito"] = original_package
