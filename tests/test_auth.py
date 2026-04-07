"""Tests for explicit Cognito admin boundaries."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone
from unittest import mock

import pytest
from fastapi import HTTPException

from daylily_auth_cognito.admin import federation, passwords, pools, users
from daylily_auth_cognito.admin.client import CognitoAdminClient
from daylily_auth_cognito.policy.email_domains import DomainValidator


def _admin(client: mock.Mock | None = None, **overrides) -> CognitoAdminClient:
    defaults = {
        "region": "us-west-2",
        "user_pool_id": "pool-123",
        "app_client_id": "client-123",
        "app_client_secret": "secret-123",
        "client": client or mock.Mock(),
    }
    defaults.update(overrides)
    return CognitoAdminClient(**defaults)


def test_admin_client_builds_boto_session_and_secret_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    boto_session = mock.Mock()
    boto_session.client.return_value = mock.sentinel.cognito
    session_cls = mock.Mock(return_value=boto_session)
    monkeypatch.setattr("daylily_auth_cognito.admin.client.boto3.Session", session_cls)

    admin = CognitoAdminClient(region="us-west-2", aws_profile="dev-profile")

    session_cls.assert_called_once_with(region_name="us-west-2", profile_name="dev-profile")
    assert admin.cognito is mock.sentinel.cognito

    admin.app_client_id = "client-123"
    admin.app_client_secret = "secret-123"
    expected = base64.b64encode(
        hmac.new(
            b"secret-123",
            msg=b"user@example.testclient-123",
            digestmod=hashlib.sha256,
        ).digest()
    ).decode()
    assert admin.compute_secret_hash("user@example.test") == expected


def test_admin_client_enforces_email_domain_policy() -> None:
    admin = _admin(email_domain_policy=DomainValidator(allowed_domains="example.test"))

    admin.validate_email_domain("user@example.test")
    with pytest.raises(HTTPException, match="allowed list"):
        admin.validate_email_domain("user@other.test")


def test_ensure_user_pool_creates_pool_and_sets_admin_state() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"UserPools": []}]
    cognito.get_paginator.return_value = paginator
    cognito.create_user_pool.return_value = {"UserPool": {"Id": "pool-999"}}
    cognito.describe_user_pool.return_value = {"UserPool": {"Name": "ursa-users"}}
    admin = _admin(cognito)

    created = pools.ensure_user_pool(admin, pool_name="ursa-users")

    assert created["pool_id"] == "pool-999"
    assert created["pool_name"] == "ursa-users"
    assert admin.user_pool_id == "pool-999"
    cognito.create_user_pool.assert_called_once()


def test_create_user_and_export_users_delegate_through_admin_client() -> None:
    cognito = mock.Mock()
    cognito.admin_create_user.return_value = {"User": {"Username": "user@example.test"}}
    admin = _admin(cognito)

    created = users.create_user(
        admin,
        email="user@example.test",
        customer_id="CUST-42",
        suppress_message=True,
        extra_attributes=[{"Name": "custom:role", "Value": "scientist"}],
    )

    assert created == {"Username": "user@example.test"}
    kwargs = cognito.admin_create_user.call_args.kwargs
    assert kwargs["MessageAction"] == "SUPPRESS"
    assert {"Name": "custom:customer_id", "Value": "CUST-42"} in kwargs["UserAttributes"]
    assert {"Name": "custom:role", "Value": "scientist"} in kwargs["UserAttributes"]

    with mock.patch(
        "daylily_auth_cognito.admin.users.list_users",
        return_value=[
            {
                "Username": "user@example.test",
                "UserStatus": "CONFIRMED",
                "Enabled": True,
                "UserCreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "UserLastModifiedDate": datetime(2024, 1, 2, tzinfo=timezone.utc),
                "Attributes": [{"Name": "email", "Value": "user@example.test"}],
            }
        ],
    ):
        exported = users.export_users(admin)

    assert exported["pool_id"] == "pool-123"
    assert exported["user_count"] == 1
    assert exported["users"][0]["attributes"]["email"] == "user@example.test"


def test_password_helpers_return_normalized_auth_payloads() -> None:
    cognito = mock.Mock()
    cognito.admin_initiate_auth.return_value = {
        "AuthenticationResult": {
            "AccessToken": "access-123",
            "IdToken": "id-123",
            "RefreshToken": "refresh-123",
            "ExpiresIn": 3600,
            "TokenType": "Bearer",
        }
    }
    cognito.admin_respond_to_auth_challenge.return_value = {
        "AuthenticationResult": {
            "AccessToken": "new-access-123",
            "IdToken": "new-id-123",
            "RefreshToken": "new-refresh-123",
            "ExpiresIn": 3600,
        }
    }
    admin = _admin(cognito)

    auth_result = passwords.authenticate(admin, email="user@example.test", password="Secret123")
    challenge_result = passwords.respond_to_new_password_challenge(
        admin,
        email="user@example.test",
        new_password="NewSecret123",
        session="session-123",
    )

    assert auth_result["access_token"] == "access-123"
    assert challenge_result["access_token"] == "new-access-123"
    auth_params = cognito.admin_initiate_auth.call_args.kwargs["AuthParameters"]
    assert auth_params["SECRET_HASH"]
    challenge_params = cognito.admin_respond_to_auth_challenge.call_args.kwargs["ChallengeResponses"]
    assert challenge_params["SECRET_HASH"]


def test_password_mutation_helpers_delegate_to_cognito() -> None:
    cognito = mock.Mock()
    admin = _admin(cognito)

    passwords.forgot_password(admin, email="user@example.test")
    passwords.confirm_forgot_password(
        admin,
        email="user@example.test",
        confirmation_code="123456",
        new_password="NewSecret123",
    )
    passwords.change_password(
        admin,
        access_token="access-123",
        old_password="OldSecret123",
        new_password="NewSecret123",
    )
    passwords.set_user_password(
        admin,
        email="user@example.test",
        password="Permanent123",
        permanent=True,
    )

    cognito.forgot_password.assert_called_once()
    cognito.confirm_forgot_password.assert_called_once()
    cognito.change_password.assert_called_once()
    cognito.admin_set_user_password.assert_called_once()


def test_ensure_google_federation_creates_provider_and_updates_app_client() -> None:
    cognito = mock.Mock()
    cognito.list_user_pool_clients.return_value = {
        "UserPoolClients": [{"ClientId": "client-123", "ClientName": "web-client"}]
    }
    cognito.describe_user_pool_client.return_value = {
        "UserPoolClient": {"SupportedIdentityProviders": ["COGNITO"], "ClientName": "web-client"}
    }
    cognito.describe_identity_provider.side_effect = RuntimeError("missing")
    admin = _admin(cognito)

    result = federation.ensure_google_federation(
        admin,
        google_client_id="google-client-123",
        google_client_secret="google-secret-123",
        app_name="web-client",
    )

    assert result["client_id"] == "client-123"
    cognito.create_identity_provider.assert_called_once()
    update_kwargs = cognito.update_user_pool_client.call_args.kwargs
    assert "Google" in update_kwargs["SupportedIdentityProviders"]
