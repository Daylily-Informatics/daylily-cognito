"""Cognito Hosted UI URL builders and token exchange helpers."""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from typing import Any


def _normalize_domain(domain: str) -> str:
    value = domain.strip()
    if not value:
        raise ValueError("domain is required")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme or parsed.netloc:
        raise ValueError("domain must be a bare host without scheme")
    if "/" in value:
        raise ValueError("domain must be a bare host without path")
    if any(char.isspace() for char in value):
        raise ValueError("domain must not contain whitespace")
    return value


def build_authorization_url(
    *,
    domain: str,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid email profile",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> str:
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
    return f"https://{_normalize_domain(domain)}/oauth2/authorize?{query}"


def build_logout_url(*, domain: str, client_id: str, logout_uri: str) -> str:
    params = {"client_id": client_id, "logout_uri": logout_uri}
    query = urllib.parse.urlencode(params)
    return f"https://{_normalize_domain(domain)}/logout?{query}"


def exchange_authorization_code(
    *,
    domain: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    client_secret: str | None = None,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    url = f"https://{_normalize_domain(domain)}/oauth2/token"
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

    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8") if exc.fp else ""
        raise RuntimeError(f"Token exchange failed: HTTP {exc.code} - {error_body}") from exc


async def exchange_authorization_code_async(
    *,
    domain: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    client_secret: str | None = None,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        exchange_authorization_code,
        domain=domain,
        client_id=client_id,
        code=code,
        redirect_uri=redirect_uri,
        client_secret=client_secret,
        code_verifier=code_verifier,
    )
