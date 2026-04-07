"""Password and auth-challenge helpers."""

from __future__ import annotations

from typing import Any

from .client import CognitoAdminClient


def set_user_password(
    admin: CognitoAdminClient,
    *,
    email: str,
    password: str,
    permanent: bool,
) -> None:
    admin.validate_email_domain(email)
    admin.cognito.admin_set_user_password(
        UserPoolId=admin.require_user_pool_id(),
        Username=email,
        Password=password,
        Permanent=bool(permanent),
    )


def authenticate(admin: CognitoAdminClient, *, email: str, password: str) -> dict[str, Any]:
    admin.validate_email_domain(email)
    auth_params = {"USERNAME": email, "PASSWORD": password}
    if admin.app_client_secret:
        auth_params["SECRET_HASH"] = admin.compute_secret_hash(email)

    response = admin.cognito.admin_initiate_auth(
        UserPoolId=admin.require_user_pool_id(),
        ClientId=admin.require_app_client_id(),
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters=auth_params,
    )

    if "ChallengeName" in response:
        return {
            "challenge": response["ChallengeName"],
            "session": response.get("Session"),
            "challenge_parameters": response.get("ChallengeParameters", {}),
        }

    auth_result = response.get("AuthenticationResult", {})
    return {
        "access_token": auth_result.get("AccessToken"),
        "id_token": auth_result.get("IdToken"),
        "refresh_token": auth_result.get("RefreshToken"),
        "expires_in": auth_result.get("ExpiresIn"),
        "token_type": auth_result.get("TokenType", "Bearer"),
    }


def respond_to_new_password_challenge(
    admin: CognitoAdminClient,
    *,
    email: str,
    new_password: str,
    session: str,
) -> dict[str, Any]:
    responses = {"USERNAME": email, "NEW_PASSWORD": new_password}
    if admin.app_client_secret:
        responses["SECRET_HASH"] = admin.compute_secret_hash(email)

    response = admin.cognito.admin_respond_to_auth_challenge(
        UserPoolId=admin.require_user_pool_id(),
        ClientId=admin.require_app_client_id(),
        ChallengeName="NEW_PASSWORD_REQUIRED",
        ChallengeResponses=responses,
        Session=session,
    )
    auth_result = response.get("AuthenticationResult", {})
    return {
        "access_token": auth_result.get("AccessToken"),
        "id_token": auth_result.get("IdToken"),
        "refresh_token": auth_result.get("RefreshToken"),
        "expires_in": auth_result.get("ExpiresIn"),
        "token_type": auth_result.get("TokenType", "Bearer"),
    }


def forgot_password(admin: CognitoAdminClient, *, email: str) -> None:
    admin.validate_email_domain(email)
    admin.cognito.forgot_password(ClientId=admin.require_app_client_id(), Username=email)


def confirm_forgot_password(
    admin: CognitoAdminClient,
    *,
    email: str,
    confirmation_code: str,
    new_password: str,
) -> None:
    admin.cognito.confirm_forgot_password(
        ClientId=admin.require_app_client_id(),
        Username=email,
        ConfirmationCode=confirmation_code,
        Password=new_password,
    )


def change_password(
    admin: CognitoAdminClient,
    *,
    access_token: str,
    old_password: str,
    new_password: str,
) -> None:
    admin.cognito.change_password(
        AccessToken=access_token,
        PreviousPassword=old_password,
        ProposedPassword=new_password,
    )
