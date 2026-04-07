"""FastAPI integration helpers for Cognito bearer verification."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .verifier import CognitoTokenVerifier

security = HTTPBearer(auto_error=False)


def create_auth_dependency(
    verifier: CognitoTokenVerifier,
    optional: bool = False,
) -> Callable[..., dict[str, Any] | None]:
    """Create a FastAPI dependency backed by ``CognitoTokenVerifier``."""

    def get_current_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> dict[str, Any] | None:
        if credentials is None:
            if optional:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return verifier.verify_token(credentials.credentials)

    return get_current_user
