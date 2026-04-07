"""Identity-provider federation helpers."""

from __future__ import annotations

from typing import Any

from .app_clients import build_user_pool_client_update_request, find_app_client, merge_unique_strings
from .client import CognitoAdminClient


def ensure_google_federation(
    admin: CognitoAdminClient,
    *,
    google_client_id: str,
    google_client_secret: str,
    scopes: str = "openid email profile",
    user_pool_id: str | None = None,
    app_name: str | None = None,
    client_id: str | None = None,
) -> dict[str, Any]:
    pool_id = user_pool_id or admin.require_user_pool_id()
    app = find_app_client(admin, user_pool_id=pool_id, client_name=app_name, client_id=client_id)

    provider_details = {
        "client_id": google_client_id,
        "client_secret": google_client_secret,
        "authorize_scopes": scopes,
    }
    attribute_mapping = {"email": "email", "username": "sub"}

    idp_name = "Google"
    try:
        admin.cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=idp_name)
        admin.cognito.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName=idp_name,
            ProviderDetails=provider_details,
            AttributeMapping=attribute_mapping,
        )
    except Exception:
        admin.cognito.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=idp_name,
            ProviderType=idp_name,
            ProviderDetails=provider_details,
            AttributeMapping=attribute_mapping,
        )

    update_kwargs = build_user_pool_client_update_request(
        admin,
        user_pool_id=pool_id,
        client_id=app["client_id"],
        overrides={},
    )
    update_kwargs["SupportedIdentityProviders"] = merge_unique_strings(
        update_kwargs.get("SupportedIdentityProviders", []),
        ["Google"],
    )
    admin.cognito.update_user_pool_client(**update_kwargs)
    return {"provider_name": idp_name, "client_id": app["client_id"], "client_name": app["client_name"]}
