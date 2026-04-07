# Migrating to 2.0.0

## Renames

The package and distribution are now `daylily-auth-cognito` / `daylily_auth_cognito`.

Install:

```bash
pip install daylily-auth-cognito==2.0.0
```

## Top-Level API

The package root is now intentionally small. Import admin and browser/runtime submodules explicitly when you need more than the curated surface.

## Runtime Verification

Old pattern:

```python
from daylily_cognito.auth import CognitoAuth

auth = CognitoAuth(region=..., user_pool_id=..., app_client_id=...)
claims = auth.verify_token(token)
```

New pattern:

```python
from daylily_auth_cognito.runtime.verifier import CognitoTokenVerifier

verifier = CognitoTokenVerifier(region=..., user_pool_id=..., app_client_id=...)
claims = verifier.verify_token(token)
```

FastAPI dependency:

```python
from daylily_auth_cognito.runtime.fastapi import create_auth_dependency

auth_dependency = create_auth_dependency(verifier)
```

## Browser Session Flow

Old browser helpers moved under `browser/`.

Use:
- `daylily_auth_cognito.browser.session`
- `daylily_auth_cognito.browser.oauth`
- `daylily_auth_cognito.browser.google`

The callback path now uses `exchange_authorization_code_async()` and stores normalized principal data only. Do not store raw OAuth tokens in session state.

## Admin Operations

The old auth god object is gone.

Use explicit admin modules instead:
- `daylily_auth_cognito.admin.client.CognitoAdminClient`
- `daylily_auth_cognito.admin.pools`
- `daylily_auth_cognito.admin.app_clients`
- `daylily_auth_cognito.admin.users`
- `daylily_auth_cognito.admin.passwords`
- `daylily_auth_cognito.admin.federation`

Example:

```python
from daylily_auth_cognito.admin.client import CognitoAdminClient
from daylily_auth_cognito.admin.users import create_user

admin = CognitoAdminClient(region=..., aws_profile=..., user_pool_id=...)
create_user(admin, email="user@example.test")
```

## CLI Config

CLI config remains at `~/.config/daycog/config.yaml`, but it is now isolated under `daylily_auth_cognito.cli.config` and must not be imported by service runtime code. The internal CLI config helper belongs to that module only.

## Removed Surface

Removed with no compatibility aliases:
- the legacy package root
- the old top-level auth god object
- the old broad top-level config export
- the monolithic auth module
- the refresh-token helper
- the Google auto-create helper
- the old plugin monolith

Do not keep imports from the deleted monolith modules or the legacy package root.

## Testing Expectations

Update tests to patch these seams:
- runtime bearer auth: `daylily_auth_cognito.runtime.*`
- async browser callback exchange: `daylily_auth_cognito.browser.session.exchange_authorization_code_async`
- CLI config: `daylily_auth_cognito.cli.config`
