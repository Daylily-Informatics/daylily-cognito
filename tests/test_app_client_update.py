"""Tests for safe Cognito app client update helpers."""

from __future__ import annotations

from unittest import mock

from daylily_cognito._app_client_update import (
    MUTABLE_USER_POOL_CLIENT_FIELDS,
    REQUIRED_AUTH_FLOWS,
    build_user_pool_client_update_request,
    merge_unique_strings,
    update_user_pool_client_safe,
)


def _full_client_config() -> dict[str, object]:
    return {
        "UserPoolId": "us-west-2_TestPool",
        "ClientId": "client-123",
        "ClientName": "web-app",
        "RefreshTokenValidity": 30,
        "AccessTokenValidity": 60,
        "IdTokenValidity": 60,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
        "ReadAttributes": ["email", "name"],
        "WriteAttributes": ["email"],
        "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
        "SupportedIdentityProviders": ["COGNITO"],
        "CallbackURLs": ["https://app.example.com/callback"],
        "LogoutURLs": ["https://app.example.com/logout"],
        "DefaultRedirectURI": "https://app.example.com/callback",
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": ["openid", "email", "profile"],
        "AllowedOAuthFlowsUserPoolClient": True,
        "AnalyticsConfiguration": {"ApplicationId": "abc"},
        "PreventUserExistenceErrors": "ENABLED",
        "EnableTokenRevocation": True,
        "EnablePropagateAdditionalUserContextData": True,
        "AuthSessionValidity": 3,
        "RefreshTokenRotation": {"Feature": "ENABLED", "RetryGracePeriodSeconds": 10},
        "ClientSecret": "secret",
        "CreationDate": "2024-01-01T00:00:00Z",
        "LastModifiedDate": "2024-01-02T00:00:00Z",
    }


def test_build_update_request_preserves_mutable_fields_and_applies_overrides() -> None:
    cognito = mock.MagicMock()
    cognito.describe_user_pool_client.return_value = {"UserPoolClient": _full_client_config()}

    update_kwargs = build_user_pool_client_update_request(
        cognito,
        user_pool_id="us-west-2_TestPool",
        client_id="client-123",
        overrides={
            "ClientName": "web-app-v2",
            "CallbackURLs": ["https://app.example.com/new-callback"],
        },
    )

    assert update_kwargs["UserPoolId"] == "us-west-2_TestPool"
    assert update_kwargs["ClientId"] == "client-123"
    assert update_kwargs["ClientName"] == "web-app-v2"
    assert update_kwargs["CallbackURLs"] == ["https://app.example.com/new-callback"]
    assert update_kwargs["LogoutURLs"] == ["https://app.example.com/logout"]
    assert update_kwargs["DefaultRedirectURI"] == "https://app.example.com/callback"
    assert update_kwargs["PreventUserExistenceErrors"] == "ENABLED"
    assert update_kwargs["EnableTokenRevocation"] is True
    assert "ClientSecret" not in update_kwargs
    assert "CreationDate" not in update_kwargs
    assert "LastModifiedDate" not in update_kwargs
    assert set(update_kwargs) == {"UserPoolId", "ClientId", *MUTABLE_USER_POOL_CLIENT_FIELDS}


def test_update_user_pool_client_safe_submits_merged_request() -> None:
    cognito = mock.MagicMock()
    cognito.describe_user_pool_client.return_value = {"UserPoolClient": _full_client_config()}

    update_user_pool_client_safe(
        cognito,
        user_pool_id="us-west-2_TestPool",
        client_id="client-123",
        overrides={"AllowedOAuthScopes": ["openid", "email"]},
    )

    cognito.update_user_pool_client.assert_called_once()
    kwargs = cognito.update_user_pool_client.call_args.kwargs
    assert kwargs["AllowedOAuthScopes"] == ["openid", "email"]
    assert kwargs["LogoutURLs"] == ["https://app.example.com/logout"]
    assert kwargs["AuthSessionValidity"] == 3


def test_merge_unique_strings_preserves_existing_order() -> None:
    merged = merge_unique_strings(
        ["ALLOW_USER_SRP_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        REQUIRED_AUTH_FLOWS,
    )

    assert merged == [
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
    ]
