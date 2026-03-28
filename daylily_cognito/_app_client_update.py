"""Helpers for safe Cognito app client updates."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

MUTABLE_USER_POOL_CLIENT_FIELDS = (
    "ClientName",
    "RefreshTokenValidity",
    "AccessTokenValidity",
    "IdTokenValidity",
    "TokenValidityUnits",
    "ReadAttributes",
    "WriteAttributes",
    "ExplicitAuthFlows",
    "SupportedIdentityProviders",
    "CallbackURLs",
    "LogoutURLs",
    "DefaultRedirectURI",
    "AllowedOAuthFlows",
    "AllowedOAuthScopes",
    "AllowedOAuthFlowsUserPoolClient",
    "AnalyticsConfiguration",
    "PreventUserExistenceErrors",
    "EnableTokenRevocation",
    "EnablePropagateAdditionalUserContextData",
    "AuthSessionValidity",
    "RefreshTokenRotation",
)

REQUIRED_AUTH_FLOWS = (
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
)


def merge_unique_strings(existing: Iterable[str], additions: Iterable[str]) -> list[str]:
    """Return a stable union while preserving the first occurrence of each value."""
    merged: list[str] = []
    seen: set[str] = set()

    for item in [*existing, *additions]:
        if item and item not in seen:
            merged.append(item)
            seen.add(item)

    return merged


def build_user_pool_client_update_request(
    cognito: Any,
    *,
    user_pool_id: str,
    client_id: str,
    overrides: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a safe update request from the current client config and explicit overrides."""
    response = cognito.describe_user_pool_client(
        UserPoolId=user_pool_id,
        ClientId=client_id,
    )
    client_config = response["UserPoolClient"]

    update_kwargs: dict[str, Any] = {
        "UserPoolId": user_pool_id,
        "ClientId": client_id,
    }
    for field in MUTABLE_USER_POOL_CLIENT_FIELDS:
        if field in client_config:
            update_kwargs[field] = client_config[field]

    update_kwargs.update(overrides)
    return update_kwargs


def update_user_pool_client_safe(
    cognito: Any,
    *,
    user_pool_id: str,
    client_id: str,
    overrides: Mapping[str, Any],
) -> dict[str, Any]:
    """Describe, merge, and update a Cognito app client without dropping unrelated fields."""
    update_kwargs = build_user_pool_client_update_request(
        cognito,
        user_pool_id=user_pool_id,
        client_id=client_id,
        overrides=overrides,
    )
    return cognito.update_user_pool_client(**update_kwargs)
