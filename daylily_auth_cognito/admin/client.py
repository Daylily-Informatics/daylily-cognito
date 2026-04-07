"""Shared admin client boundary for Cognito mutations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Any

import boto3
from fastapi import HTTPException, status

from daylily_auth_cognito.policy.email_domains import EmailDomainPolicy

LOGGER = logging.getLogger("daylily_auth_cognito.admin.client")


@dataclass
class CognitoAdminClient:
    """Shared boto3-backed Cognito admin boundary."""

    region: str
    aws_profile: str | None = None
    user_pool_id: str | None = None
    app_client_id: str | None = None
    app_client_secret: str | None = None
    email_domain_policy: EmailDomainPolicy | None = None
    client: Any | None = None

    def __post_init__(self) -> None:
        if not self.region:
            raise ValueError("region is required")
        if self.client is None:
            session_kwargs: dict[str, str] = {"region_name": self.region}
            if self.aws_profile:
                session_kwargs["profile_name"] = self.aws_profile
            session = boto3.Session(**session_kwargs)
            self.client = session.client("cognito-idp")

    @property
    def cognito(self) -> Any:
        return self.client

    def require_user_pool_id(self) -> str:
        if not self.user_pool_id:
            raise ValueError("user_pool_id is required")
        return self.user_pool_id

    def require_app_client_id(self) -> str:
        if not self.app_client_id:
            raise ValueError("app_client_id is required")
        return self.app_client_id

    def compute_secret_hash(self, username: str) -> str:
        if not self.app_client_secret:
            raise ValueError("app_client_secret is required to compute SECRET_HASH")
        message = username + self.require_app_client_id()
        digest = hmac.new(
            self.app_client_secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode()

    def validate_email_domain(self, email: str) -> None:
        if self.email_domain_policy is None:
            return
        is_valid, error_msg = self.email_domain_policy.validate_email_domain(email)
        if not is_valid:
            LOGGER.warning("Domain validation failed for %s: %s", email, error_msg)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=error_msg)
