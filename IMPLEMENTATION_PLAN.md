# Implementation Plan

## Scope

This repo now ships the `2.0.0` greenfield split for Cognito auth as one standalone distribution:
- repo: `daylily-auth-cognito`
- distribution: `daylily-auth-cognito`
- import package: `daylily_auth_cognito`
- CLI executable: `daycog`

The refactor is intentionally breaking. No compatibility shims or deprecated aliases remain.

## Target Layout

```text
daylily_auth_cognito/
  __init__.py
  version.py
  runtime/
    __init__.py
    verifier.py
    fastapi.py
    jwks.py
    tokens.py
    m2m.py
  browser/
    __init__.py
    session.py
    oauth.py
    google.py
  admin/
    __init__.py
    client.py
    pools.py
    app_clients.py
    users.py
    federation.py
    passwords.py
  policy/
    __init__.py
    email_domains.py
  cli/
    __init__.py
    main.py
    spec.py
    config.py
    plugins/
      __init__.py
      status.py
      config.py
      pools.py
      apps.py
      users.py
      google.py
```

## Execution Summary

1. Renamed the package, distribution metadata, script entrypoint, and activation checks.
2. Split verification logic into `runtime/` and removed AWS mutation from verifier paths.
3. Split Hosted UI and Google browser helpers into `browser/` and kept session storage token-free.
4. Split AWS mutation helpers into explicit `admin/` modules.
5. Moved CLI config/spec/main and plugin wiring under `cli/`.
6. Replaced monolith-oriented tests with semantic tests for runtime, browser, admin, CLI, and boundary enforcement.
7. Deleted the legacy monolith source tree.

## File Moves

- legacy package files were re-homed into the `runtime/`, `browser/`, `admin/`, `cli/`, and `policy/` boundaries
- version metadata now lives in `daylily_auth_cognito/version.py`
- CLI config handling is now isolated under `daylily_auth_cognito/cli/config.py`
- the package root now exports only the curated public API
- the legacy monolith modules were deleted after cutover

## Public API Contract

The curated top-level API exports exactly:
- `CognitoWebSessionConfig`
- `SessionPrincipal`
- `configure_session_middleware`
- `start_cognito_login`
- `complete_cognito_callback`
- `load_session_principal`
- `store_session_principal`
- `clear_session_principal`
- `CognitoTokenVerifier`
- `create_auth_dependency`
- `JWKSCache`
- `verify_m2m_token_with_jwks`
- `__version__`

## Test Plan Implemented

Internal semantic coverage now proves:
- runtime bearer verification behavior
- unverified and verified JWT claim checks
- M2M scope enforcement
- FastAPI dependency wiring
- async browser callback token exchange
- token-free browser session persistence
- stale `server_instance_id` invalidation
- admin pool, app-client, user, password, and federation behavior
- CLI command wiring and flat-config handling
- static package boundaries

Current local result:
- `pytest -q` -> `83 passed`

## Operational Note

CLI config handling remains in `daylily_auth_cognito.cli.config` and is CLI-only. Runtime, browser, and admin code should import from their own boundaries or the curated root exports, not from `daylily_auth_cognito.cli`.
