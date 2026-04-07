"""Tests for email-domain policy helpers."""

from __future__ import annotations

from daylily_auth_cognito.policy.email_domains import DomainValidator, EmailDomainPolicy


def test_domain_validator_is_runtime_checkable_policy() -> None:
    validator = DomainValidator(allowed_domains="example.test")

    assert isinstance(validator, EmailDomainPolicy)


def test_domain_validator_allows_expected_domains() -> None:
    validator = DomainValidator(allowed_domains="example.test,science.test")

    assert validator.validate_email_domain("user@example.test") == (True, "")
    assert validator.validate_email_domain("user@science.test") == (True, "")
    assert validator.validate_email_domain("user@other.test") == (
        False,
        "Domain 'other.test' is not in the allowed list",
    )


def test_domain_validator_respects_block_rules() -> None:
    validator = DomainValidator(allowed_domains="all", blocked_domains="evil.test")

    assert validator.validate_email_domain("user@good.test") == (True, "")
    assert validator.validate_email_domain("user@evil.test") == (False, "Domain 'evil.test' is blocked")

    block_all = DomainValidator(blocked_domains="all")
    assert block_all.validate_email_domain("user@example.test") == (
        False,
        "Domain 'example.test' is blocked (all domains blocked)",
    )


def test_domain_validator_rejects_invalid_email_shape() -> None:
    validator = DomainValidator()

    assert validator.validate_email_domain("not-an-email") == (False, "Invalid email address: not-an-email")
