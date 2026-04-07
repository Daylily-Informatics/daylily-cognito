# Changelog

## 2.0.0

- Published the standalone `daylily-auth-cognito` distribution and `daylily_auth_cognito` package.
- Split the codebase into `runtime/`, `browser/`, `admin/`, `cli/`, and `policy/`.
- Moved Hosted UI session storage to a token-free normalized-principal model.
- Made browser callback token exchange asynchronous in the web path.
- Separated CLI config handling from runtime modules and kept it under `daylily_auth_cognito.cli.config`.
- Curated the top-level export surface and removed the monolith-style package root API.
- Updated docs, tests, and consumer repos to the new boundary model.

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
