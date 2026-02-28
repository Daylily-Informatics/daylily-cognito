"""Domain validation for email addresses.

Provides a concrete DomainValidator class implementing SettingsProtocol
from auth.py, with CSV-string allowed_domains/blocked_domains semantics.
"""

from __future__ import annotations

import logging

LOGGER = logging.getLogger("daylily_cognito.domain_validator")


class DomainValidator:
    """Validates email domains against allowed/blocked lists.

    Implements SettingsProtocol so it can be passed as ``settings``
    to ``CognitoAuth``.

    Args:
        allowed_domains: CSV of permitted domains.
            ``""`` or ``"all"`` means allow every domain.
            ``"lsmc.com,dyly.bio"`` means only those domains are allowed.
        blocked_domains: CSV of denied domains.
            ``""`` means block nothing.
            ``"all"`` means block everything.
            ``"evil.com,spam.org"`` means block those specific domains.

    Evaluation order: blocked_domains is checked **first** (deny wins).
    All matching is case-insensitive; whitespace around domains is stripped.
    """

    def __init__(
        self,
        allowed_domains: str = "",
        blocked_domains: str = "",
    ) -> None:
        self._allow_all: bool = False
        self._block_all: bool = False
        self._allowed: set[str] = set()
        self._blocked: set[str] = set()

        # Parse allowed_domains
        stripped_allow = allowed_domains.strip().lower()
        if stripped_allow in ("", "all"):
            self._allow_all = True
        else:
            self._allowed = {
                d.strip().lower()
                for d in allowed_domains.split(",")
                if d.strip()
            }

        # Parse blocked_domains
        stripped_block = blocked_domains.strip().lower()
        if stripped_block == "all":
            self._block_all = True
        elif stripped_block:
            self._blocked = {
                d.strip().lower()
                for d in blocked_domains.split(",")
                if d.strip()
            }

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        """Validate an email address's domain against allow/block lists.

        Args:
            email: Email address to validate.

        Returns:
            ``(True, "")`` if the domain is permitted,
            ``(False, reason)`` if it is not.
        """
        if "@" not in email:
            return (False, f"Invalid email address: {email}")

        domain = email.rsplit("@", 1)[1].strip().lower()
        if not domain:
            return (False, f"Invalid email address: {email}")

        # --- Blocked check first (deny wins) ---
        if self._block_all:
            return (False, f"Domain '{domain}' is blocked (all domains blocked)")

        if domain in self._blocked:
            return (False, f"Domain '{domain}' is blocked")

        # --- Allowed check ---
        if self._allow_all:
            return (True, "")

        if domain in self._allowed:
            return (True, "")

        return (False, f"Domain '{domain}' is not in the allowed list")

