"""Google OAuth2 integration for hybrid Cognito authentication.

Standalone Google OAuth flow that auto-creates Cognito users.
Uses stdlib only (urllib) — no extra dependencies beyond boto3.

Google endpoints:
    Authorization: https://accounts.google.com/o/oauth2/v2/auth
    Token:         https://oauth2.googleapis.com/token
    Userinfo:      https://openidconnect.googleapis.com/v1/userinfo

Standard scopes (openid email profile) yield these claims:
    Always:   sub, iss, aud, exp, iat
    email:    email, email_verified
    profile:  name, given_name, family_name, picture, locale
    Optional: hd (hosted domain for Google Workspace users)
"""

from __future__ import annotations

import json
import logging
import secrets
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

LOGGER = logging.getLogger("daylily_cognito.google")

# Google OAuth2 endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

# Default scopes — captures all attributes without extra permissions
DEFAULT_SCOPES = "openid email profile"


def generate_state_token() -> str:
    """Generate a cryptographically secure state token for CSRF protection.

    Returns:
        URL-safe random string (32 bytes, hex-encoded).
    """
    return secrets.token_hex(32)


def build_google_authorization_url(
    *,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: str = DEFAULT_SCOPES,
    login_hint: Optional[str] = None,
    hd: Optional[str] = None,
    nonce: Optional[str] = None,
    access_type: str = "offline",
    prompt: Optional[str] = None,
) -> str:
    """Build Google OAuth2 authorization URL.

    Args:
        client_id: Google OAuth2 client ID
        redirect_uri: Callback URL after authorization
        state: CSRF state token (auto-generated if None)
        scope: OAuth scopes (default: 'openid email profile')
        login_hint: Pre-fill email in Google login
        hd: Restrict to a Google Workspace domain
        nonce: Replay protection nonce
        access_type: 'offline' for refresh tokens, 'online' otherwise
        prompt: 'consent' to force re-consent, 'select_account' for account picker

    Returns:
        Full Google authorization URL string.
    """
    params: Dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": access_type,
    }
    if state:
        params["state"] = state
    if login_hint:
        params["login_hint"] = login_hint
    if hd:
        params["hd"] = hd
    if nonce:
        params["nonce"] = nonce
    if prompt:
        params["prompt"] = prompt

    query = urllib.parse.urlencode(params)
    return f"{GOOGLE_AUTH_ENDPOINT}?{query}"


def exchange_google_code_for_tokens(
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    """Exchange Google authorization code for tokens.

    Args:
        client_id: Google OAuth2 client ID
        client_secret: Google OAuth2 client secret
        code: Authorization code from callback
        redirect_uri: Must match the redirect_uri used in authorization

    Returns:
        Dict containing: access_token, id_token, expires_in, token_type,
        and optionally refresh_token (first auth only).

    Raises:
        RuntimeError: If token exchange fails.
    """
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    encoded = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(
        GOOGLE_TOKEN_ENDPOINT,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"Google token exchange failed: HTTP {e.code} - {error_body}") from e


def fetch_google_userinfo(access_token: str) -> Dict[str, Any]:
    """Fetch user profile from Google userinfo endpoint.

    Requires an access_token obtained with 'openid email profile' scopes.

    Args:
        access_token: Google OAuth2 access token

    Returns:
        Dict with available claims:
            sub:            Google user ID (always present)
            email:          Email address
            email_verified: Whether email is verified
            name:           Full name
            given_name:     First name
            family_name:    Last name
            picture:        Profile photo URL
            locale:         User locale (BCP 47)
            hd:             Hosted domain (Google Workspace only, may be absent)

    Raises:
        RuntimeError: If userinfo request fails.
    """
    request = urllib.request.Request(
        GOOGLE_USERINFO_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"Google userinfo request failed: HTTP {e.code} - {error_body}") from e


def auto_create_cognito_user_from_google(
    auth: Any,
    google_userinfo: Dict[str, Any],
    *,
    customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Auto-create or retrieve a Cognito user from Google userinfo.

    If the user (identified by email) already exists in the Cognito pool,
    returns the existing user. Otherwise creates a new user with Google
    profile attributes stored as Cognito user attributes.

    Note: The Cognito user pool must have custom attributes configured:
        custom:customer_id, custom:google_sub, custom:google_hd (optional).
    Standard attributes name, given_name, family_name, picture, locale
    must also be enabled on the pool if you want them populated.

    Args:
        auth: CognitoAuth instance (typed as Any to avoid circular import)
        google_userinfo: Dict from fetch_google_userinfo()
        customer_id: Optional customer ID for the new user.
                     Defaults to the Google 'sub' (unique user ID).

    Returns:
        Dict with keys:
            user: Cognito user data dict
            created: True if user was newly created, False if existing
            google_sub: Google user ID
            email: User email

    Raises:
        ValueError: If google_userinfo is missing required fields.
        HTTPException: If email domain fails validation (403 Forbidden).
        RuntimeError: If Cognito operations fail unexpectedly.
    """
    email = google_userinfo.get("email")
    google_sub = google_userinfo.get("sub")

    if not email:
        raise ValueError("Google userinfo missing 'email' field")
    if not google_sub:
        raise ValueError("Google userinfo missing 'sub' field")

    # Validate email domain before any user lookup or creation.
    # If auth.settings is None, this is a no-op (backward compatible).
    # If domain is blocked, raises HTTPException(403).
    if hasattr(auth, "_validate_email_domain"):
        auth._validate_email_domain(email)

    effective_customer_id = customer_id or google_sub

    # Try to look up the user first
    try:
        existing = auth.cognito.admin_get_user(
            UserPoolId=auth.user_pool_id,
            Username=email,
        )
        LOGGER.info("Google user %s already exists in Cognito", email)
        return {
            "user": dict(existing),
            "created": False,
            "google_sub": google_sub,
            "email": email,
        }
    except auth.cognito.exceptions.UserNotFoundException:
        pass  # User doesn't exist — create below

    # Build user attributes from Google profile
    user_attributes = [
        {"Name": "email", "Value": email},
        {"Name": "email_verified", "Value": str(google_userinfo.get("email_verified", False)).lower()},
        {"Name": "custom:customer_id", "Value": effective_customer_id},
        {"Name": "custom:google_sub", "Value": google_sub},
    ]

    # Add optional profile attributes if present
    optional_attrs = {
        "name": google_userinfo.get("name"),
        "given_name": google_userinfo.get("given_name"),
        "family_name": google_userinfo.get("family_name"),
        "picture": google_userinfo.get("picture"),
        "locale": google_userinfo.get("locale"),
    }
    for attr_name, attr_value in optional_attrs.items():
        if attr_value:
            user_attributes.append({"Name": attr_name, "Value": attr_value})

    # Store hosted domain if present
    hd = google_userinfo.get("hd")
    if hd:
        user_attributes.append({"Name": "custom:google_hd", "Value": hd})

    try:
        response = auth.cognito.admin_create_user(
            UserPoolId=auth.user_pool_id,
            Username=email,
            UserAttributes=user_attributes,
            MessageAction="SUPPRESS",  # Don't send welcome email for Google users
            DesiredDeliveryMediums=["EMAIL"],
        )
        LOGGER.info("Created Cognito user %s from Google OAuth (sub=%s)", email, google_sub)

        # Set a random password so the user record is confirmed.
        # Google users authenticate via OAuth, not password.
        random_password = secrets.token_urlsafe(32) + "!A1a"
        auth.cognito.admin_set_user_password(
            UserPoolId=auth.user_pool_id,
            Username=email,
            Password=random_password,
            Permanent=True,
        )

        return {
            "user": dict(response["User"]),
            "created": True,
            "google_sub": google_sub,
            "email": email,
        }
    except Exception as e:
        LOGGER.error("Failed to create Cognito user from Google: %s", str(e))
        raise RuntimeError(f"Failed to create Cognito user for {email}: {e}") from e
