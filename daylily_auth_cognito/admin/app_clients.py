"""App-client admin helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .client import CognitoAdminClient

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
    merged: list[str] = []
    seen: set[str] = set()
    for item in [*existing, *additions]:
        if item and item not in seen:
            merged.append(item)
            seen.add(item)
    return merged


def build_user_pool_client_update_request(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str,
    client_id: str,
    overrides: Mapping[str, Any],
) -> dict[str, Any]:
    response = admin.cognito.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)
    client_config = response["UserPoolClient"]
    update_kwargs: dict[str, Any] = {"UserPoolId": user_pool_id, "ClientId": client_id}
    for field in MUTABLE_USER_POOL_CLIENT_FIELDS:
        if field in client_config:
            update_kwargs[field] = client_config[field]
    update_kwargs.update(overrides)
    return update_kwargs


def list_app_clients(admin: CognitoAdminClient, *, user_pool_id: str | None = None) -> list[dict[str, str]]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    return admin.cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get("UserPoolClients", [])


def find_app_client(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    client_name: str | None = None,
    client_id: str | None = None,
) -> dict[str, str]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    clients = list_app_clients(admin, user_pool_id=pool_id)
    match = None
    if client_id:
        match = next((client for client in clients if client.get("ClientId") == client_id), None)
    elif client_name:
        match = next((client for client in clients if client.get("ClientName") == client_name), None)
    if not match:
        raise ValueError(f"App client not found: {client_id or client_name or '<unknown>'}")
    return {"client_id": str(match["ClientId"]), "client_name": str(match["ClientName"])}


def describe_app_client(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    client_name: str | None = None,
    client_id: str | None = None,
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    found = find_app_client(admin, user_pool_id=pool_id, client_name=client_name, client_id=client_id)
    response = admin.cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=found["client_id"])
    details = dict(response["UserPoolClient"])
    details["ClientId"] = found["client_id"]
    details["ClientName"] = found["client_name"]
    return details


def create_app_client(
    admin: CognitoAdminClient,
    *,
    client_name: str,
    user_pool_id: str | None = None,
    generate_secret: bool = False,
    explicit_auth_flows: list[str] | None = None,
    allowed_oauth_flows: list[str] | None = None,
    allowed_oauth_scopes: list[str] | None = None,
    allowed_oauth_flows_user_pool_client: bool = True,
    callback_urls: list[str] | None = None,
    logout_urls: list[str] | None = None,
    supported_identity_providers: list[str] | None = None,
    read_attributes: list[str] | None = None,
    write_attributes: list[str] | None = None,
    reuse_if_exists: bool = False,
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    existing = next(
        (client for client in list_app_clients(admin, user_pool_id=pool_id) if client.get("ClientName") == client_name),
        None,
    )
    if existing:
        if not reuse_if_exists:
            raise ValueError(f"App client already exists: {client_name}")
        admin.app_client_id = str(existing["ClientId"])
        return describe_app_client(admin, user_pool_id=pool_id, client_id=admin.app_client_id)

    response = admin.cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=generate_secret,
        ExplicitAuthFlows=explicit_auth_flows or list(REQUIRED_AUTH_FLOWS),
        AllowedOAuthFlows=allowed_oauth_flows or ["code"],
        AllowedOAuthScopes=allowed_oauth_scopes or ["openid", "email", "profile"],
        AllowedOAuthFlowsUserPoolClient=allowed_oauth_flows_user_pool_client,
        CallbackURLs=callback_urls or [],
        LogoutURLs=logout_urls or [],
        SupportedIdentityProviders=supported_identity_providers or ["COGNITO"],
        ReadAttributes=read_attributes or ["email", "custom:customer_id"],
        WriteAttributes=write_attributes or ["email"],
    )
    client = dict(response["UserPoolClient"])
    admin.app_client_id = str(client["ClientId"])
    if client.get("ClientSecret"):
        admin.app_client_secret = str(client["ClientSecret"])
    return client


def create_m2m_app_client(
    admin: CognitoAdminClient,
    *,
    client_name: str,
    scopes: list[str],
    user_pool_id: str | None = None,
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    response = admin.cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=client_name,
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=scopes,
        AllowedOAuthFlowsUserPoolClient=True,
    )
    client = dict(response["UserPoolClient"])
    admin.app_client_id = str(client["ClientId"])
    if client.get("ClientSecret"):
        admin.app_client_secret = str(client["ClientSecret"])
    return client


def update_app_client(
    admin: CognitoAdminClient,
    *,
    client_id: str | None = None,
    client_name: str | None = None,
    user_pool_id: str | None = None,
    overrides: Mapping[str, Any],
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    found = find_app_client(admin, user_pool_id=pool_id, client_name=client_name, client_id=client_id)
    update_kwargs = build_user_pool_client_update_request(
        admin,
        user_pool_id=pool_id,
        client_id=found["client_id"],
        overrides=overrides,
    )
    admin.cognito.update_user_pool_client(**update_kwargs)
    admin.app_client_id = found["client_id"]
    return update_kwargs


def update_app_client_auth_flows(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    client_id: str | None = None,
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    resolved_client_id = client_id or admin.require_app_client_id()
    update_kwargs = build_user_pool_client_update_request(
        admin,
        user_pool_id=pool_id,
        client_id=resolved_client_id,
        overrides={},
    )
    update_kwargs["ExplicitAuthFlows"] = merge_unique_strings(
        update_kwargs.get("ExplicitAuthFlows", []),
        REQUIRED_AUTH_FLOWS,
    )
    admin.cognito.update_user_pool_client(**update_kwargs)
    admin.app_client_id = resolved_client_id
    return update_kwargs


def delete_app_client(
    admin: CognitoAdminClient,
    *,
    user_pool_id: str | None = None,
    client_id: str | None = None,
    client_name: str | None = None,
) -> bool:
    pool_id = user_pool_id or admin.require_user_pool_id()
    resolved_client_id = client_id
    if not resolved_client_id and client_name:
        resolved_client_id = find_app_client(admin, user_pool_id=pool_id, client_name=client_name)["client_id"]
    if not resolved_client_id:
        resolved_client_id = admin.require_app_client_id()
    admin.cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=resolved_client_id)
    if resolved_client_id == admin.app_client_id:
        admin.app_client_id = None
    return True
