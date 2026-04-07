"""User-pool admin helpers."""

from __future__ import annotations

import time
from typing import Any

from .client import CognitoAdminClient


def list_user_pools(admin: CognitoAdminClient, *, max_results: int = 60) -> list[dict[str, Any]]:
    paginator = admin.cognito.get_paginator("list_user_pools")
    pools: list[dict[str, Any]] = []
    for page in paginator.paginate(MaxResults=max_results):
        pools.extend(page.get("UserPools", []))
    return pools


def find_user_pool_id_by_name(admin: CognitoAdminClient, pool_name: str) -> str:
    for pool in list_user_pools(admin):
        if pool.get("Name") == pool_name:
            return str(pool["Id"])
    raise ValueError(f"Pool not found: {pool_name}")


def resolve_pool(
    admin: CognitoAdminClient,
    *,
    pool_name: str | None = None,
    pool_id: str | None = None,
) -> dict[str, Any]:
    if not pool_name and not pool_id:
        raise ValueError("pool_name or pool_id is required")

    resolved_pool_id = pool_id or find_user_pool_id_by_name(admin, pool_name or "")
    pool_info = admin.cognito.describe_user_pool(UserPoolId=resolved_pool_id)["UserPool"]
    if pool_name and pool_info.get("Name") != pool_name:
        raise ValueError(f"Pool name '{pool_name}' does not match resolved pool '{pool_info.get('Name')}'")
    return {
        "pool_id": resolved_pool_id,
        "pool_name": str(pool_info["Name"]),
        "pool_info": pool_info,
    }


def ensure_user_pool(
    admin: CognitoAdminClient,
    *,
    pool_name: str,
    password_min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_numbers: bool = True,
    require_symbols: bool = False,
    mfa_configuration: str = "OFF",
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    for pool in list_user_pools(admin):
        if pool.get("Name") == pool_name:
            resolved = resolve_pool(admin, pool_id=str(pool["Id"]))
            admin.user_pool_id = resolved["pool_id"]
            return resolved

    response = admin.cognito.create_user_pool(
        PoolName=pool_name,
        AutoVerifiedAttributes=["email"],
        UsernameAttributes=["email"],
        MfaConfiguration=mfa_configuration,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": password_min_length,
                "RequireUppercase": require_uppercase,
                "RequireLowercase": require_lowercase,
                "RequireNumbers": require_numbers,
                "RequireSymbols": require_symbols,
            }
        },
        UserPoolTags=tags or {},
        Schema=[
            {
                "Name": "email",
                "AttributeDataType": "String",
                "Required": True,
                "Mutable": True,
            },
            {
                "Name": "customer_id",
                "AttributeDataType": "String",
                "Mutable": True,
            },
        ],
    )
    pool_id = str(response["UserPool"]["Id"])
    admin.user_pool_id = pool_id
    return resolve_pool(admin, pool_id=pool_id)


def ensure_user_pool_domain(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    domain_prefix: str,
) -> str:
    pool_id = user_pool_id or admin.require_user_pool_id()
    pool = admin.cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    existing = pool.get("Domain")
    if existing:
        return f"{existing}.auth.{admin.region}.amazoncognito.com"

    admin.cognito.create_user_pool_domain(UserPoolId=pool_id, Domain=domain_prefix)
    return f"{domain_prefix}.auth.{admin.region}.amazoncognito.com"


def delete_user_pool(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    delete_domain_first: bool = False,
    wait_seconds: int = 12,
) -> None:
    pool_id = user_pool_id or admin.require_user_pool_id()
    if delete_domain_first:
        pool = admin.cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        domain_name = pool.get("Domain") or pool.get("CustomDomain")
        if domain_name:
            admin.cognito.delete_user_pool_domain(UserPoolId=pool_id, Domain=domain_name)
            for _ in range(wait_seconds):
                latest = admin.cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
                if not latest.get("Domain") and not latest.get("CustomDomain"):
                    break
                time.sleep(1)

    admin.cognito.delete_user_pool(UserPoolId=pool_id)
