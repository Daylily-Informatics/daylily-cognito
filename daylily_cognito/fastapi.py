"""FastAPI integration helpers for Cognito authentication.

Provides security scheme and dependency factory for FastAPI applications.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

if TYPE_CHECKING:
    from .auth import CognitoAuth

# Shared security scheme for Bearer token authentication
security = HTTPBearer(auto_error=False)


def create_auth_dependency(
    cognito_auth: "CognitoAuth",
    optional: bool = False,
) -> Callable[..., Optional[Dict[str, Any]]]:
    """Create FastAPI dependency for authentication.

    Args:
        cognito_auth: CognitoAuth instance
        optional: If True, returns None when no credentials provided instead of raising error

    Returns:
        Dependency function that can be used with FastAPI's Depends()

    Example:
        cognito = CognitoAuth(...)
        get_user = create_auth_dependency(cognito)
        get_optional_user = create_auth_dependency(cognito, optional=True)

        @app.get("/protected")
        def protected(user: dict = Depends(get_user)):
            return {"user": user}

        @app.get("/public")
        def public(user: dict | None = Depends(get_optional_user)):
            return {"user": user}
    """

    def get_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Optional[Dict[str, Any]]:
        if credentials is None:
            if optional:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return cognito_auth.get_current_user(credentials)

    return get_current_user
