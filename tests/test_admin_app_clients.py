"""Seam tests for Cognito app-client admin helpers."""

from __future__ import annotations

from unittest import mock

import pytest

from daylily_auth_cognito.admin.app_clients import (
    REQUIRED_AUTH_FLOWS,
    create_app_client,
    create_m2m_app_client,
    delete_app_client,
    describe_app_client,
    find_app_client,
    list_app_clients,
    merge_unique_strings,
    update_app_client,
    update_app_client_auth_flows,
)
from daylily_auth_cognito.admin.client import CognitoAdminClient


def _admin(client: mock.Mock | None = None, **overrides) -> CognitoAdminClient:
    defaults = {
        "region": "us-west-2",
        "user_pool_id": "pool-123",
        "app_client_id": "client-123",
        "client": client or mock.Mock(),
    }
    defaults.update(overrides)
    return CognitoAdminClient(**defaults)


def test_merge_unique_strings_preserves_order_and_uniqueness() -> None:
    assert merge_unique_strings(["a", "", "b"], ["b", "c", "a"]) == ["a", "b", "c"]


def test_list_find_and_describe_app_clients() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "client-a", "ClientName": "alpha"}]}
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "alpha",
            "CallbackURLs": ["https://app.example.test/callback"],
            "LogoutURLs": ["https://app.example.test/logout"],
        }
    }
    admin = _admin(cognito)

    assert list_app_clients(admin) == [{"ClientId": "client-a", "ClientName": "alpha"}]
    assert find_app_client(admin, client_name="alpha") == {"client_id": "client-a", "client_name": "alpha"}
    described = describe_app_client(admin, client_id="client-a")

    assert described["ClientId"] == "client-a"
    assert described["ClientName"] == "alpha"
    assert described["CallbackURLs"] == ["https://app.example.test/callback"]


def test_find_and_describe_raise_when_client_missing() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": []}
    admin = _admin(cognito)

    with pytest.raises(ValueError, match="App client not found"):
        find_app_client(admin, client_name="missing")
    with pytest.raises(ValueError, match="App client not found"):
        describe_app_client(admin, client_name="missing")


def test_create_app_client_covers_duplicate_and_reuse_paths() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "client-a", "ClientName": "alpha"}]}
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {"ClientName": "alpha", "CallbackURLs": ["https://app.example.test/callback"]}
    }
    admin = _admin(cognito)

    with pytest.raises(ValueError, match="already exists"):
        create_app_client(admin, client_name="alpha")

    reused = create_app_client(admin, client_name="alpha", reuse_if_exists=True)

    assert reused["ClientId"] == "client-a"
    assert admin.app_client_id == "client-a"


def test_create_app_client_sets_default_fields_and_secret_state() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": []}
    cognito.create_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientId": "client-new",
            "ClientSecret": "secret-new",
            "ClientName": "alpha",
        }
    }
    admin = _admin(cognito)

    created = create_app_client(
        admin,
        client_name="alpha",
        generate_secret=True,
        explicit_auth_flows=["ALLOW_USER_PASSWORD_AUTH"],
        allowed_oauth_flows=["code"],
        allowed_oauth_scopes=["openid"],
        callback_urls=["https://app.example.test/callback"],
        logout_urls=["https://app.example.test/logout"],
        supported_identity_providers=["COGNITO"],
    )

    assert created["ClientId"] == "client-new"
    assert admin.app_client_id == "client-new"
    assert admin.app_client_secret == "secret-new"
    kwargs = cognito.create_user_pool_client.call_args.kwargs
    assert kwargs["ClientName"] == "alpha"
    assert kwargs["ExplicitAuthFlows"] == ["ALLOW_USER_PASSWORD_AUTH"]
    assert kwargs["SupportedIdentityProviders"] == ["COGNITO"]
    assert kwargs["CallbackURLs"] == ["https://app.example.test/callback"]


def test_create_m2m_and_update_and_delete_app_client_cover_state_reset() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "client-a", "ClientName": "alpha"}]}
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {
            "ClientName": "alpha",
            "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH"],
            "RefreshTokenValidity": 30,
        }
    }
    cognito.create_user_pool_client.return_value = {
        "UserPoolClient": {"ClientId": "m2m-client", "ClientSecret": "m2m-secret", "ClientName": "worker"}
    }
    admin = _admin(cognito)

    created = create_m2m_app_client(admin, client_name="worker", scopes=["api/read"])
    assert created["ClientId"] == "m2m-client"
    assert admin.app_client_id == "m2m-client"
    assert admin.app_client_secret == "m2m-secret"

    updated = update_app_client(admin, client_name="alpha", overrides={"CallbackURLs": ["https://new/callback"]})
    assert updated["CallbackURLs"] == ["https://new/callback"]
    assert admin.app_client_id == "client-a"

    merged = update_app_client_auth_flows(admin, client_id="client-a")
    assert set(REQUIRED_AUTH_FLOWS).issubset(set(merged["ExplicitAuthFlows"]))

    admin.app_client_id = "client-a"
    assert delete_app_client(admin, client_id="client-a") is True
    assert admin.app_client_id is None


def test_delete_app_client_accepts_client_name_lookup_and_missing_id_uses_admin_default() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {"UserPoolClients": [{"ClientId": "client-a", "ClientName": "alpha"}]}
    admin = _admin(cognito)

    assert delete_app_client(admin, client_name="alpha") is True
    cognito.delete_user_pool_client.assert_called_once_with(UserPoolId="pool-123", ClientId="client-a")
