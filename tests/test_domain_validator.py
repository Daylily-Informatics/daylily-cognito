"""Tests for DomainValidator class."""

from __future__ import annotations

from daylily_cognito.domain_validator import DomainValidator

# ── Allow-all defaults ───────────────────────────────────────────────


class TestAllowAll:
    """Empty string or 'all' for allowed_domains means allow everything."""

    def test_empty_string_allows_all(self):
        v = DomainValidator("")
        assert v.validate_email_domain("user@anything.com") == (True, "")

    def test_explicit_all_allows_all(self):
        v = DomainValidator("all")
        assert v.validate_email_domain("user@anything.com") == (True, "")

    def test_all_case_insensitive(self):
        v = DomainValidator("ALL")
        assert v.validate_email_domain("user@foo.org") == (True, "")

    def test_whitespace_only_allows_all(self):
        v = DomainValidator("  ")
        assert v.validate_email_domain("user@bar.net") == (True, "")


# ── Specific allowed domains ─────────────────────────────────────────


class TestSpecificAllowed:
    def test_allowed_domain_passes(self):
        v = DomainValidator("lsmc.com,dyly.bio")
        assert v.validate_email_domain("alice@lsmc.com") == (True, "")
        assert v.validate_email_domain("bob@dyly.bio") == (True, "")

    def test_unlisted_domain_rejected(self):
        v = DomainValidator("lsmc.com,dyly.bio")
        ok, msg = v.validate_email_domain("eve@evil.com")
        assert ok is False
        assert "evil.com" in msg

    def test_case_insensitive_matching(self):
        v = DomainValidator("LSMC.COM")
        assert v.validate_email_domain("user@lsmc.com") == (True, "")
        assert v.validate_email_domain("user@LSMC.COM") == (True, "")

    def test_whitespace_stripped(self):
        v = DomainValidator(" lsmc.com , dyly.bio ")
        assert v.validate_email_domain("user@lsmc.com") == (True, "")
        assert v.validate_email_domain("user@dyly.bio") == (True, "")


# ── Blocked domains ──────────────────────────────────────────────────


class TestBlocked:
    def test_empty_blocked_blocks_nothing(self):
        v = DomainValidator("", "")
        assert v.validate_email_domain("user@anything.com") == (True, "")

    def test_specific_blocked_domain(self):
        v = DomainValidator("", "evil.com")
        ok, msg = v.validate_email_domain("user@evil.com")
        assert ok is False
        assert "blocked" in msg.lower()

    def test_non_blocked_domain_passes(self):
        v = DomainValidator("", "evil.com")
        assert v.validate_email_domain("user@good.com") == (True, "")

    def test_block_all(self):
        v = DomainValidator("", "all")
        ok, msg = v.validate_email_domain("user@anything.com")
        assert ok is False
        assert "blocked" in msg.lower()

    def test_block_all_case_insensitive(self):
        v = DomainValidator("", "ALL")
        ok, _ = v.validate_email_domain("user@foo.org")
        assert ok is False

    def test_blocked_domain_case_insensitive(self):
        v = DomainValidator("", "EVIL.COM")
        ok, _ = v.validate_email_domain("user@evil.com")
        assert ok is False

    def test_blocked_whitespace_stripped(self):
        v = DomainValidator("", " evil.com , spam.org ")
        ok, _ = v.validate_email_domain("user@spam.org")
        assert ok is False


# ── Deny wins over allow ─────────────────────────────────────────────


class TestDenyWins:
    def test_blocked_overrides_allowed(self):
        v = DomainValidator("lsmc.com", "lsmc.com")
        ok, msg = v.validate_email_domain("user@lsmc.com")
        assert ok is False
        assert "blocked" in msg.lower()

    def test_block_all_overrides_allow_all(self):
        v = DomainValidator("all", "all")
        ok, _ = v.validate_email_domain("user@foo.com")
        assert ok is False


# ── Invalid emails ───────────────────────────────────────────────────


class TestInvalidEmail:
    def test_no_at_sign(self):
        v = DomainValidator("")
        ok, msg = v.validate_email_domain("noatsign")
        assert ok is False
        assert "Invalid" in msg

    def test_empty_domain(self):
        v = DomainValidator("")
        ok, msg = v.validate_email_domain("user@")
        assert ok is False
        assert "Invalid" in msg

    def test_multiple_at_uses_last(self):
        v = DomainValidator("lsmc.com")
        assert v.validate_email_domain("user@extra@lsmc.com") == (True, "")


# ── Protocol compatibility ───────────────────────────────────────────


class TestProtocol:
    def test_isinstance_settings_protocol(self):
        from daylily_cognito.auth import SettingsProtocol

        v = DomainValidator("")
        assert isinstance(v, SettingsProtocol)

    def test_importable_from_package(self):
        from daylily_cognito import DomainValidator as DV

        assert DV is DomainValidator

