"""Tests for explicit app-client admin helpers."""

from __future__ import annotations

from unittest import mock

from daylily_auth_cognito.admin.app_clients import (
    REQUIRED_AUTH_FLOWS,
    build_user_pool_client_update_request,
    create_m2m_app_client,
    update_app_client_auth_flows,
)
from daylily_auth_cognito.admin.client import CognitoAdminClient


def _admin(client: mock.Mock | None = None) -> CognitoAdminClient:
    return CognitoAdminClient(
        region="us-west-2",
        user_pool_id="pool-123",
        app_client_id="client-123",
        client=client or mock.Mock(),
    )


def test_build_user_pool_client_update_request_preserves_mutable_fields_only() -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "web-client",
            "RefreshTokenValidity": 30,
            "SupportedIdentityProviders": ["COGNITO"],
            "ClientSecret": "not-mutable",
        }
    }
    admin = _admin(cognito)

    request = build_user_pool_client_update_request(
        admin,
        user_pool_id="pool-123",
        client_id="client-123",
        overrides={"LogoutURLs": ["https://app.example.test/logout"]},
    )

    assert request == {
        "UserPoolId": "pool-123",
        "ClientId": "client-123",
        "ClientName": "web-client",
        "RefreshTokenValidity": 30,
        "SupportedIdentityProviders": ["COGNITO"],
        "LogoutURLs": ["https://app.example.test/logout"],
    }


def test_update_app_client_auth_flows_merges_required_flows() -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "web-client",
            "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
        }
    }
    admin = _admin(cognito)

    request = update_app_client_auth_flows(admin)

    assert request["ClientId"] == "client-123"
    assert set(REQUIRED_AUTH_FLOWS).issubset(set(request["ExplicitAuthFlows"]))
    cognito.update_user_pool_client.assert_called_once_with(**request)


def test_create_m2m_app_client_sets_admin_client_identity() -> None:
    cognito = mock.Mock()
    cognito.create_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "m2m-client-123",
            "ClientSecret": "secret-123",
            "ClientName": "worker-app",
        }
    }
    admin = _admin(cognito)

    created = create_m2m_app_client(admin, client_name="worker-app", scopes=["api/read"])

    assert created["ClientId"] == "m2m-client-123"
    assert admin.app_client_id == "m2m-client-123"
    assert admin.app_client_secret == "secret-123"
    cognito.create_user_pool_client.assert_called_once()
