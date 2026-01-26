"""OAuth2 URL builders and token exchange helpers for Cognito.

Provides pure functions for building authorization/logout URLs and
exchanging authorization codes for tokens.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any, Optional

from .config import CognitoConfig


def build_authorization_url(
    *,
    domain: str,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid email profile",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
) -> str:
    """Build Cognito authorization URL.

    Args:
        domain: Cognito domain (e.g., 'your-domain.auth.us-west-2.amazoncognito.com')
        client_id: App client ID
        redirect_uri: Callback URL after authorization
        response_type: OAuth response type (default: 'code')
        scope: OAuth scopes (default: 'openid email profile')
        state: Optional state parameter for CSRF protection
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE method (e.g., 'S256')

    Returns:
        Full authorization URL string

    Example:
        url = build_authorization_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            redirect_uri="http://localhost:8000/auth/callback",
        )
    """
    params = {
        "client_id": client_id,
        "response_type": response_type,
        "scope": scope,
        "redirect_uri": redirect_uri,
    }

    if state:
        params["state"] = state
    if code_challenge:
        params["code_challenge"] = code_challenge
    if code_challenge_method:
        params["code_challenge_method"] = code_challenge_method

    query = urllib.parse.urlencode(params)
    return f"https://{domain}/oauth2/authorize?{query}"


def build_logout_url(
    *,
    domain: str,
    client_id: str,
    logout_uri: str,
) -> str:
    """Build Cognito logout URL.

    Args:
        domain: Cognito domain (e.g., 'your-domain.auth.us-west-2.amazoncognito.com')
        client_id: App client ID
        logout_uri: URL to redirect to after logout

    Returns:
        Full logout URL string

    Example:
        url = build_logout_url(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            logout_uri="http://localhost:8000/",
        )
    """
    params = {
        "client_id": client_id,
        "logout_uri": logout_uri,
    }
    query = urllib.parse.urlencode(params)
    return f"https://{domain}/logout?{query}"


def exchange_authorization_code(
    *,
    domain: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    client_secret: Optional[str] = None,
    code_verifier: Optional[str] = None,
) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Makes a POST request to Cognito's /oauth2/token endpoint.

    Args:
        domain: Cognito domain
        client_id: App client ID
        code: Authorization code from callback
        redirect_uri: Must match the redirect_uri used in authorization
        client_secret: Optional client secret (if app client has one)
        code_verifier: Optional PKCE code verifier

    Returns:
        Dict containing tokens: access_token, id_token, refresh_token, etc.

    Raises:
        RuntimeError: If token exchange fails (non-2xx response)

    Example:
        tokens = exchange_authorization_code(
            domain="myapp.auth.us-west-2.amazoncognito.com",
            client_id="abc123",
            code="auth-code-from-callback",
            redirect_uri="http://localhost:8000/auth/callback",
        )
    """
    url = f"https://{domain}/oauth2/token"

    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    if client_secret:
        data["client_secret"] = client_secret
    if code_verifier:
        data["code_verifier"] = code_verifier

    encoded_data = urllib.parse.urlencode(data).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=encoded_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(
            f"Token exchange failed: HTTP {e.code} - {error_body}"
        ) from e


def refresh_with_refresh_token(
    config: CognitoConfig,
    refresh_token: str,
    *,
    profile: Optional[str] = None,
) -> dict[str, Any]:
    """Refresh tokens using a refresh token.

    Uses boto3 admin_initiate_auth with REFRESH_TOKEN_AUTH flow.

    Args:
        config: CognitoConfig instance
        refresh_token: Refresh token from previous authentication
        profile: Optional AWS profile (overrides config.aws_profile)

    Returns:
        Dict containing new tokens: access_token, id_token, expires_in, etc.

    Raises:
        botocore.exceptions.ClientError: If refresh fails

    Example:
        new_tokens = refresh_with_refresh_token(config, old_refresh_token)
    """
    import boto3

    session_kwargs = {"region_name": config.region}
    effective_profile = profile or config.aws_profile
    if effective_profile:
        session_kwargs["profile_name"] = effective_profile

    session = boto3.Session(**session_kwargs)
    cognito = session.client("cognito-idp")

    response = cognito.admin_initiate_auth(
        UserPoolId=config.user_pool_id,
        ClientId=config.app_client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )

    auth_result = response.get("AuthenticationResult", {})
    return {
        "access_token": auth_result.get("AccessToken"),
        "id_token": auth_result.get("IdToken"),
        "expires_in": auth_result.get("ExpiresIn"),
        "token_type": auth_result.get("TokenType", "Bearer"),
    }
