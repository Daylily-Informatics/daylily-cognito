"""Google OAuth HTTP helpers for Cognito browser flows."""

from __future__ import annotations

import json
import logging
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

LOGGER = logging.getLogger("daylily_auth_cognito.browser.google")

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
DEFAULT_SCOPES = "openid email profile"


def generate_state_token() -> str:
    return secrets.token_hex(32)


def build_google_authorization_url(
    *,
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
    scope: str = DEFAULT_SCOPES,
    login_hint: str | None = None,
    hd: str | None = None,
    nonce: str | None = None,
    access_type: str = "offline",
    prompt: str | None = None,
) -> str:
    params: dict[str, str] = {
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
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_google_code_for_tokens(
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    request = urllib.request.Request(
        GOOGLE_TOKEN_ENDPOINT,
        data=urllib.parse.urlencode(data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except socket.timeout as exc:
        raise RuntimeError("Google token exchange timed out") from exc
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8") if exc.fp else ""
        raise RuntimeError(f"Google token exchange failed: HTTP {exc.code} - {error_body}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, socket.timeout):
            raise RuntimeError("Google token exchange timed out") from exc
        raise RuntimeError(f"Google token exchange failed: {exc.reason}") from exc


def fetch_google_userinfo(access_token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        GOOGLE_USERINFO_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except socket.timeout as exc:
        raise RuntimeError("Google userinfo fetch timed out") from exc
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8") if exc.fp else ""
        raise RuntimeError(f"Google userinfo request failed: HTTP {exc.code} - {error_body}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, socket.timeout):
            raise RuntimeError("Google userinfo fetch timed out") from exc
        raise RuntimeError(f"Google userinfo request failed: {exc.reason}") from exc
