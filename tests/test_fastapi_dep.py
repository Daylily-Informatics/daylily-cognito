"""Tests for FastAPI bearer dependency creation."""

from __future__ import annotations

from unittest import mock

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from daylily_auth_cognito.runtime.fastapi import create_auth_dependency, security


def test_security_is_optional_http_bearer() -> None:
    assert security.auto_error is False


def test_create_auth_dependency_requires_credentials_by_default() -> None:
    verifier = mock.Mock()
    dependency = create_auth_dependency(verifier)

    with pytest.raises(HTTPException, match="Authentication required") as exc_info:
        dependency(None)

    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


def test_create_auth_dependency_can_be_optional() -> None:
    dependency = create_auth_dependency(mock.Mock(), optional=True)

    assert dependency(None) is None


def test_create_auth_dependency_delegates_to_verifier() -> None:
    verifier = mock.Mock()
    verifier.verify_token.return_value = {"sub": "user-123"}
    dependency = create_auth_dependency(verifier)

    result = dependency(HTTPAuthorizationCredentials(scheme="Bearer", credentials="token-123"))

    assert result == {"sub": "user-123"}
    verifier.verify_token.assert_called_once_with("token-123")
