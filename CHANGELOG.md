# Changelog

## 0.1.13

- Added `DomainValidator` class for CSV-string allowed/blocked domain validation
- Added domain validation to Google SSO auto-create path
- Implemented JWKS-based JWT signature verification (replaces `verify_signature=False`)
- Fail-closed security: raises error if JWKS cache unavailable
- Added timeouts (10s) to all HTTP calls (JWKS, Google OAuth)
- Fixed URLError-wrapped timeout handling for connection/DNS timeouts
- Added `httpx` to dev dependencies for FastAPI TestClient
- 175 tests passing across Python 3.9–3.13

## 0.1.11 and earlier

- See git history for previous changes

