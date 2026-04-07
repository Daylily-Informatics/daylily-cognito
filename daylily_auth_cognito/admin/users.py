"""User and group admin helpers."""

from __future__ import annotations

import secrets
import string
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from .client import CognitoAdminClient


def generate_temporary_password() -> str:
    alphabet = string.ascii_letters + string.digits
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    password += [secrets.choice(alphabet) for _ in range(9)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def create_user(
    admin: CognitoAdminClient,
    *,
    email: str,
    customer_id: str | None = None,
    temporary_password: str | None = None,
    email_verified: bool = True,
    suppress_message: bool = False,
    extra_attributes: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    admin.validate_email_domain(email)
    attributes = [{"Name": "email", "Value": email}]
    if email_verified:
        attributes.append({"Name": "email_verified", "Value": "true"})
    if customer_id:
        attributes.append({"Name": "custom:customer_id", "Value": customer_id})
    if extra_attributes:
        attributes.extend(extra_attributes)

    params: dict[str, Any] = {
        "UserPoolId": admin.require_user_pool_id(),
        "Username": email,
        "UserAttributes": attributes,
    }
    if temporary_password:
        params["TemporaryPassword"] = temporary_password
    if not suppress_message:
        params["DesiredDeliveryMediums"] = ["EMAIL"]
    else:
        params["MessageAction"] = "SUPPRESS"

    response = admin.cognito.admin_create_user(**params)
    return dict(response["User"])


def list_users(
    admin: CognitoAdminClient,
    *,
    limit: int | None = None,
    filter_expression: str | None = None,
) -> list[dict[str, Any]]:
    paginator = admin.cognito.get_paginator("list_users")
    kwargs: dict[str, Any] = {"UserPoolId": admin.require_user_pool_id()}
    if filter_expression:
        kwargs["Filter"] = filter_expression
    if limit is not None:
        kwargs["PaginationConfig"] = {"MaxItems": limit}

    users: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        users.extend(page.get("Users", []))
    return users


def list_customer_users(admin: CognitoAdminClient, customer_id: str) -> list[dict[str, Any]]:
    return list_users(admin, filter_expression=f'custom:customer_id = "{customer_id}"')


def set_user_attributes(admin: CognitoAdminClient, *, email: str, attributes: list[dict[str, str]]) -> None:
    admin.cognito.admin_update_user_attributes(
        UserPoolId=admin.require_user_pool_id(),
        Username=email,
        UserAttributes=attributes,
    )


def ensure_group(admin: CognitoAdminClient, *, group_name: str, description: str = "") -> bool:
    paginator = admin.cognito.get_paginator("list_groups")
    for page in paginator.paginate(UserPoolId=admin.require_user_pool_id()):
        for group in page.get("Groups", []):
            if group.get("GroupName") == group_name:
                return False
    params: dict[str, Any] = {"UserPoolId": admin.require_user_pool_id(), "GroupName": group_name}
    if description.strip():
        params["Description"] = description.strip()
    admin.cognito.create_group(**params)
    return True


def add_user_to_group(admin: CognitoAdminClient, *, email: str, group_name: str) -> None:
    admin.cognito.admin_add_user_to_group(
        UserPoolId=admin.require_user_pool_id(),
        Username=email,
        GroupName=group_name,
    )


def delete_user(admin: CognitoAdminClient, *, email: str) -> bool:
    try:
        admin.cognito.admin_delete_user(UserPoolId=admin.require_user_pool_id(), Username=email)
        return True
    except ClientError:
        return False


def delete_all_users(admin: CognitoAdminClient) -> int:
    count = 0
    for user in list_users(admin):
        username = user.get("Username")
        if not username:
            continue
        admin.cognito.admin_delete_user(UserPoolId=admin.require_user_pool_id(), Username=username)
        count += 1
    return count


def export_users(admin: CognitoAdminClient) -> dict[str, Any]:
    users: list[dict[str, Any]] = []
    for user in list_users(admin):
        users.append(
            {
                "username": user.get("Username"),
                "status": user.get("UserStatus"),
                "enabled": user.get("Enabled"),
                "created": user.get("UserCreateDate").isoformat() if user.get("UserCreateDate") else None,
                "modified": user.get("UserLastModifiedDate").isoformat() if user.get("UserLastModifiedDate") else None,
                "attributes": {attr["Name"]: attr["Value"] for attr in user.get("Attributes", [])},
            }
        )

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "pool_id": admin.require_user_pool_id(),
        "region": admin.region,
        "user_count": len(users),
        "users": users,
    }
