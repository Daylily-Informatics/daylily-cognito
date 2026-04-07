# 2.0.0 Changelog

## Breaking Changes

- Renamed the distribution to `daylily-auth-cognito`.
- Renamed the import package to `daylily_auth_cognito`.
- Deleted the legacy package root.
- Removed the monolithic auth object.
- Removed the broad config export and other wide top-level exports from the package root.
- Removed compatibility aliases and deprecated wrappers.
- Removed the refresh-token helper.
- Removed the Google auto-create helper.

## Added

- `runtime/` verification boundary with `CognitoTokenVerifier`
- `browser/` Hosted UI and Google OAuth helpers
- `admin/` explicit Cognito mutation modules
- `cli/` package-local `daycog` wiring
- `policy/` email-domain helpers
- async browser callback token exchange for web paths
- semantic boundary tests for runtime, browser, admin, CLI, and import hygiene

## Changed

- `python-jose[cryptography]` is now a base dependency.
- Hosted UI session persistence is token-free and stores only normalized principal data.
- CLI config is separated from runtime code.
- CLI config handling is isolated under `daylily_auth_cognito.cli.config`, including its internal config helper.
- JWT verifier code is verification-only and performs no AWS mutation.
