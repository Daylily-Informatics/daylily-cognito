"""Email-domain policy contracts and helpers."""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

LOGGER = logging.getLogger("daylily_auth_cognito.policy.email_domains")


@runtime_checkable
class EmailDomainPolicy(Protocol):
    """Contract for validating whether an email domain is permitted."""

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        """Return ``(allowed, reason)`` for the supplied email address."""


class DomainValidator:
    """Validate email domains against allow/block lists."""

    def __init__(self, allowed_domains: str = "", blocked_domains: str = "") -> None:
        self._allow_all = False
        self._block_all = False
        self._allowed: set[str] = set()
        self._blocked: set[str] = set()

        stripped_allow = allowed_domains.strip().lower()
        if stripped_allow in {"", "all"}:
            self._allow_all = True
        else:
            self._allowed = {item.strip().lower() for item in allowed_domains.split(",") if item.strip()}

        stripped_block = blocked_domains.strip().lower()
        if stripped_block == "all":
            self._block_all = True
        elif stripped_block:
            self._blocked = {item.strip().lower() for item in blocked_domains.split(",") if item.strip()}

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        if "@" not in email:
            return False, f"Invalid email address: {email}"

        domain = email.rsplit("@", 1)[1].strip().lower()
        if not domain:
            return False, f"Invalid email address: {email}"

        if self._block_all:
            return False, f"Domain '{domain}' is blocked (all domains blocked)"
        if domain in self._blocked:
            return False, f"Domain '{domain}' is blocked"
        if self._allow_all:
            return True, ""
        if domain in self._allowed:
            return True, ""
        return False, f"Domain '{domain}' is not in the allowed list"
