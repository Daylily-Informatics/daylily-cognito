"""Seam tests for Cognito user and group admin helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest import mock

import pytest
from botocore.exceptions import ClientError

from daylily_auth_cognito.admin import users
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


def test_generate_temporary_password_has_required_character_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(users.secrets, "choice", lambda seq: seq[0])
    monkeypatch.setattr(users.secrets.SystemRandom, "shuffle", lambda self, items: items.reverse())

    password = users.generate_temporary_password()

    assert len(password) == 12
    assert any(ch.isupper() for ch in password)
    assert any(ch.islower() for ch in password)
    assert any(ch.isdigit() for ch in password)


def test_create_user_validates_domain_and_builds_user_payload() -> None:
    cognito = mock.Mock()
    cognito.admin_create_user.return_value = {"User": {"Username": "user@example.test"}}
    admin = _admin(cognito)
    admin.validate_email_domain = mock.Mock()

    created = users.create_user(
        admin,
        email="user@example.test",
        customer_id="cust-1",
        temporary_password="Temp123456",
        email_verified=False,
        suppress_message=False,
        extra_attributes=[{"Name": "custom:role", "Value": "scientist"}],
    )

    assert created == {"Username": "user@example.test"}
    admin.validate_email_domain.assert_called_once_with("user@example.test")
    call_kwargs = cognito.admin_create_user.call_args.kwargs
    assert call_kwargs["TemporaryPassword"] == "Temp123456"
    assert call_kwargs["DesiredDeliveryMediums"] == ["EMAIL"]
    assert {"Name": "custom:customer_id", "Value": "cust-1"} in call_kwargs["UserAttributes"]
    assert {"Name": "custom:role", "Value": "scientist"} in call_kwargs["UserAttributes"]
    assert all(attr["Name"] != "email_verified" for attr in call_kwargs["UserAttributes"])


def test_list_and_customer_users_apply_filters_and_limits() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"Users": [{"Username": "u1"}]}, {"Users": [{"Username": "u2"}]}]
    cognito.get_paginator.return_value = paginator
    admin = _admin(cognito)

    assert users.list_users(admin, limit=2, filter_expression='email = "user@example.test"') == [
        {"Username": "u1"},
        {"Username": "u2"},
    ]
    assert users.list_customer_users(admin, "cust-99") == [{"Username": "u1"}, {"Username": "u2"}]
    first_call = paginator.paginate.call_args_list[0].kwargs
    second_call = paginator.paginate.call_args_list[1].kwargs
    assert first_call["UserPoolId"] == "pool-123"
    assert first_call["Filter"] == 'email = "user@example.test"'
    assert first_call["PaginationConfig"] == {"MaxItems": 2}
    assert second_call["Filter"] == 'custom:customer_id = "cust-99"'


def test_ensure_group_handles_existing_and_new_groups() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"Groups": [{"GroupName": "scientists"}]}]
    cognito.get_paginator.return_value = paginator
    admin = _admin(cognito)

    assert users.ensure_group(admin, group_name="scientists") is False

    paginator.paginate.return_value = [{"Groups": []}]
    assert users.ensure_group(admin, group_name="engineers", description="  Core team  ") is True
    cognito.create_group.assert_called_once_with(UserPoolId="pool-123", GroupName="engineers", Description="Core team")


def test_set_attributes_and_add_user_to_group_delegate_to_cognito() -> None:
    cognito = mock.Mock()
    admin = _admin(cognito)

    users.set_user_attributes(admin, email="user@example.test", attributes=[{"Name": "given_name", "Value": "Ada"}])
    users.add_user_to_group(admin, email="user@example.test", group_name="scientists")

    cognito.admin_update_user_attributes.assert_called_once_with(
        UserPoolId="pool-123",
        Username="user@example.test",
        UserAttributes=[{"Name": "given_name", "Value": "Ada"}],
    )
    cognito.admin_add_user_to_group.assert_called_once_with(
        UserPoolId="pool-123",
        Username="user@example.test",
        GroupName="scientists",
    )


def test_delete_user_and_delete_all_users_cover_success_failure_and_skips() -> None:
    cognito = mock.Mock()
    cognito.admin_delete_user.side_effect = [
        None,
        ClientError({"Error": {"Code": "NotFound"}}, "AdminDeleteUser"),
    ]
    admin = _admin(cognito)

    assert users.delete_user(admin, email="user@example.test") is True
    assert users.delete_user(admin, email="missing@example.test") is False

    delete_all_cognito = mock.Mock()
    delete_all_admin = _admin(delete_all_cognito)
    with mock.patch(
        "daylily_auth_cognito.admin.users.list_users",
        return_value=[{"Username": "one"}, {"Username": ""}, {"Attributes": []}, {"Username": "two"}],
    ):
        deleted = users.delete_all_users(delete_all_admin)

    assert deleted == 2
    assert delete_all_cognito.admin_delete_user.call_args_list[-2].kwargs["Username"] == "one"
    assert delete_all_cognito.admin_delete_user.call_args_list[-1].kwargs["Username"] == "two"


def test_export_users_normalizes_records_and_timestamps() -> None:
    cognito = mock.Mock()
    admin = _admin(cognito)
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
    assert exported["region"] == "us-west-2"
    assert exported["user_count"] == 1
    assert exported["users"][0]["username"] == "user@example.test"
    assert exported["users"][0]["created"].startswith("2024-01-01")
    assert exported["users"][0]["attributes"]["email"] == "user@example.test"
