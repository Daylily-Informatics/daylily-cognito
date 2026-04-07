"""Small shared policy contracts."""

from .email_domains import DomainValidator, EmailDomainPolicy

__all__ = ["EmailDomainPolicy", "DomainValidator"]
