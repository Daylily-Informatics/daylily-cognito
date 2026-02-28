# daylily-cognito

Shared AWS Cognito authentication library for FastAPI + Jinja2 web applications.

## Installation

```bash
# Basic installation
pip install -e .

# With JWT verification support (recommended)
pip install -e ".[auth]"

# With development dependencies
pip install -e ".[dev,auth]"
```

## Configuration

### Option 1: Explicit Constructor

```python
from daylily_cognito import CognitoConfig, CognitoAuth

config = CognitoConfig(
    name="myapp",
    region="us-west-2",
    user_pool_id="us-west-2_XXXXXXXXX",
    app_client_id="XXXXXXXXXXXXXXXXXXXXXXXXXX",
    aws_profile="my-profile",  # optional
)
config.validate()  # raises ValueError if invalid

auth = CognitoAuth(
    region=config.region,
    user_pool_id=config.user_pool_id,
    app_client_id=config.app_client_id,
    app_client_secret=config.app_client_secret,  # optional, for clients with secrets
    profile=config.aws_profile,
)
```

### App Client Secret Support

When a Cognito app client has a client secret enabled, all authentication API calls
require a `SECRET_HASH` parameter. The library automatically computes this when
`app_client_secret` is provided:

```python
# For app clients WITH a secret
auth = CognitoAuth(
    region="us-west-2",
    user_pool_id="us-west-2_pUqKyIM1N",
    app_client_id="your-client-id",
    app_client_secret="your-client-secret",  # Required for clients with secrets
)

# The SECRET_HASH is automatically computed as:
# base64(hmac_sha256(client_secret, username + client_id))
```

**Note:** If your Cognito app client was created with `GenerateSecret=True`, you MUST
provide the `app_client_secret` parameter, otherwise authentication will fail with
"Unable to verify secret hash for client".

### Option 2: Namespaced Environment Variables

For multi-tenant or multi-environment setups:

```bash
export DAYCOG_PROD_REGION=us-west-2
export DAYCOG_PROD_USER_POOL_ID=us-west-2_abc123
export DAYCOG_PROD_APP_CLIENT_ID=client123
export DAYCOG_PROD_AWS_PROFILE=prod-profile  # optional
```

```python
from daylily_cognito import CognitoConfig

config = CognitoConfig.from_env("PROD")
```

### Option 3: Legacy Environment Variables

For backward compatibility with existing deployments:

```bash
export COGNITO_REGION=us-west-2        # or AWS_REGION, defaults to us-west-2
export COGNITO_USER_POOL_ID=us-west-2_abc123
export COGNITO_APP_CLIENT_ID=client123  # or COGNITO_CLIENT_ID
export AWS_PROFILE=my-profile           # optional
```

```python
from daylily_cognito import CognitoConfig

config = CognitoConfig.from_legacy_env()
```

## CLI Usage

The `daycog` CLI is the operational interface for Cognito management in this repo.

### Shell Setup

Use the helper script so the venv/CLI are ready and shell env loading works:

```bash
source ./daycog_activate
```

This script:
- creates/activates `.venv`
- installs this repo editable
- installs shell completion
- defines a shell wrapper so `daycog setup` can export values into your current shell
- loads `~/.config/daycog/default.env` if present

### Core Commands

```bash
# Show CLI help
daycog --help

# Check current Cognito config/status
daycog status

# Create pool + app client
daycog setup --name my-pool --port 8001 --profile my-aws-profile --region us-east-1

# Advanced setup (client name, callback/logout URLs, OAuth, MFA, tags, autoprovision)
daycog setup \
  --name my-pool \
  --client-name my-app-client \
  --callback-url http://localhost:8001/auth/callback \
  --logout-url http://localhost:8001/ \
  --oauth-flows code \
  --scopes openid,email,profile \
  --idp COGNITO \
  --mfa optional \
  --tags env=dev,owner=platform \
  --autoprovision \
  --profile my-aws-profile \
  --region us-east-1

# List all pools in a region
daycog list-pools --profile my-aws-profile --region us-east-1

# List apps (app clients) in a pool
daycog list-apps --pool-name my-pool --profile my-aws-profile --region us-east-1

# Add/update/remove apps in a pool
daycog add-app --pool-name my-pool --app-name web-app \
  --callback-url http://localhost:8001/auth/callback \
  --profile my-aws-profile --region us-east-1
daycog edit-app --pool-name my-pool --app-name web-app \
  --new-app-name web-app-v2 \
  --callback-url http://localhost:9000/auth/callback \
  --profile my-aws-profile --region us-east-1
daycog remove-app --pool-name my-pool --app-name web-app-v2 \
  --profile my-aws-profile --region us-east-1 --force

# Configure Google IdP for a pool/app from downloaded Google OAuth JSON
daycog add-google-idp --pool-name my-pool --app-name web-app \
  --google-client-json ./client_secret.json \
  --profile my-aws-profile --region us-east-1

# All-in-one: create pool/app and configure Google IdP in one command
daycog setup-with-google \
  --name my-pool \
  --client-name web-app \
  --callback-url http://localhost:8000/auth/google/callback \
  --google-client-json ./client_secret.json \
  --profile my-aws-profile --region us-east-1

# Delete one pool by name or ID
daycog delete-pool --pool-name my-pool --profile my-aws-profile --region us-east-1 --force
daycog delete-pool --pool-id us-east-1_abc123 --profile my-aws-profile --region us-east-1 --force
# If the pool has a Cognito Hosted UI domain, delete it automatically first
daycog delete-pool --pool-name my-pool --profile my-aws-profile --region us-east-1 --delete-domain-first --force

# User management
daycog list-users
daycog add-user user@example.com --password Secure1234
daycog set-password --email user@example.com --password NewPass123
daycog delete-user --email user@example.com --force
daycog delete-all-users --force
```

### `setup` Behavior

`daycog setup` resolves AWS context in this order:
1. `--profile`, `--region`
2. `AWS_PROFILE`, `AWS_REGION`

If either value is missing, setup exits with an error.

On success, setup writes/updates:
- `~/.config/daycog/<pool-name>.<region>.env`
- `~/.config/daycog/<pool-name>.<region>.<app-name>.env`
- `~/.config/daycog/default.env`

with:
- `AWS_PROFILE`
- `AWS_REGION`
- `COGNITO_REGION`
- `COGNITO_USER_POOL_ID`
- `COGNITO_APP_CLIENT_ID`
- `COGNITO_CLIENT_NAME`
- `COGNITO_CALLBACK_URL`
- `COGNITO_LOGOUT_URL` (when set)

If you pass `--print-exports`, setup also prints shell `export ...` lines.

Additional setup options:
- `--client-name` (default: `<pool-name>-client`)
- `--callback-url` or `--callback-path` + `--port`
- `--logout-url`
- `--generate-secret`
- `--oauth-flows` (comma-separated)
- `--scopes` (comma-separated)
- `--idp` (comma-separated)
- `--password-min-length`
- `--require-uppercase/--no-require-uppercase`
- `--require-lowercase/--no-require-lowercase`
- `--require-numbers/--no-require-numbers`
- `--require-symbols/--no-require-symbols`
- `--mfa` (`off`, `optional`, `required`)
- `--tags` (`key=value,key2=value2`)
- `--autoprovision` (reuse existing app client by `--client-name` when found)

### Multi-App Env Files

For a single pool with multiple app clients, daycog now stores:
- Pool file: `~/.config/daycog/<pool>.<region>.env`
  - Last selected app context for that pool/region.
- App file: `~/.config/daycog/<pool>.<region>.<app>.env`
  - App-specific client settings (`COGNITO_APP_CLIENT_ID`, callback/logout, etc.).
- Global default: `~/.config/daycog/default.env`
  - Active/default context loaded by `daycog_activate`.

`daycog setup` always writes all three for the created/reused app.
`daycog add-app` / `daycog edit-app` always write the app file, and update pool/default when `--set-default` is passed.
`daycog remove-app` deletes the app in Cognito and, by default, removes the app file.

### Config File Commands

```bash
# Print default config file path and contents
daycog config print

# Print specific pool config path and contents
daycog config print --pool-name my-pool --region us-east-1

# Create per-pool config from AWS and update default config
daycog config create --pool-name my-pool --profile my-aws-profile --region us-east-1

# Update per-pool config from AWS and update default config
daycog config update --pool-name my-pool --profile my-aws-profile --region us-east-1
```

### Multi-Config CLI Usage

Use `--config NAME` to select a named configuration:

```bash
export DAYCOG_PROD_REGION=us-west-2
export DAYCOG_PROD_USER_POOL_ID=us-west-2_prod
export DAYCOG_PROD_APP_CLIENT_ID=client_prod

export DAYCOG_DEV_REGION=us-east-1
export DAYCOG_DEV_USER_POOL_ID=us-east-1_dev
export DAYCOG_DEV_APP_CLIENT_ID=client_dev

daycog --config PROD status
daycog --config DEV list-users
```

Note: `daycog config create/update` use AWS lookups with `--profile`/`--region` (or `AWS_*`) and are separate from `--config NAME`.
If a pool has multiple app clients, `config create/update` use the first client returned by AWS.
When using `config print --pool-name`, `--region` is required to resolve the region-scoped file name.

## FastAPI Integration

```python
from fastapi import Depends, FastAPI
from daylily_cognito import CognitoAuth, CognitoConfig, create_auth_dependency

app = FastAPI()

# Load config and create auth handler
config = CognitoConfig.from_legacy_env()
auth = CognitoAuth(
    region=config.region,
    user_pool_id=config.user_pool_id,
    app_client_id=config.app_client_id,
)

# Create dependencies
get_current_user = create_auth_dependency(auth)
get_optional_user = create_auth_dependency(auth, optional=True)

@app.get("/protected")
def protected_route(user: dict = Depends(get_current_user)):
    return {"user": user}

@app.get("/public")
def public_route(user: dict | None = Depends(get_optional_user)):
    return {"user": user}
```

## OAuth2 Helpers

```python
from daylily_cognito import (
    build_authorization_url,
    build_logout_url,
    exchange_authorization_code,
)

# Build authorization URL for login redirect
auth_url = build_authorization_url(
    domain="myapp.auth.us-west-2.amazoncognito.com",
    client_id="abc123",
    redirect_uri="http://localhost:8000/auth/callback",
    state="csrf-token",
)

# Exchange authorization code for tokens
tokens = exchange_authorization_code(
    domain="myapp.auth.us-west-2.amazoncognito.com",
    client_id="abc123",
    code="auth-code-from-callback",
    redirect_uri="http://localhost:8000/auth/callback",
)

# Build logout URL
logout_url = build_logout_url(
    domain="myapp.auth.us-west-2.amazoncognito.com",
    client_id="abc123",
    logout_uri="http://localhost:8000/",
)
```

## Google OAuth Integration

`daylily-cognito` supports standalone Google OAuth2 authentication that auto-creates
users in your Cognito user pool. This hybrid approach lets users sign in with Google
while keeping Cognito as the single user directory.

### Prerequisites

1. Create a Google Cloud project and enable the OAuth consent screen
2. Create OAuth 2.0 credentials in the Google Cloud Console
3. Register `http://localhost:8000/auth/google/callback` as an authorized redirect URI

### Environment Variables

**Namespaced:**

```bash
export DAYCOG_PROD_GOOGLE_CLIENT_ID="your-google-client-id"
export DAYCOG_PROD_GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

**Legacy:**

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

Or use the CLI helper:

```bash
daycog setup-google --client-id YOUR_ID --client-secret YOUR_SECRET
```

Or configure Cognito Google federation directly:

```bash
daycog add-google-idp --pool-name my-pool --app-name web-app \
  --google-client-json ./client_secret.json \
  --profile my-aws-profile --region us-east-1
```

Or run all-in-one setup + Google IdP:

```bash
daycog setup-with-google \
  --name my-pool \
  --client-name web-app \
  --callback-url http://localhost:8000/auth/google/callback \
  --google-client-json ./client_secret.json \
  --profile my-aws-profile --region us-east-1
```

`add-google-idp` resolves Google credentials in this order:
1. `--google-client-id` + `--google-client-secret`
2. `--google-client-json` (`web` or `installed` keys)
3. `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`
4. `DAYCOG_<NAME>_GOOGLE_CLIENT_ID` + `DAYCOG_<NAME>_GOOGLE_CLIENT_SECRET` (when `--config NAME` is used)

### Usage

```python
from daylily_cognito import (
    build_google_authorization_url,
    exchange_google_code_for_tokens,
    fetch_google_userinfo,
    auto_create_cognito_user_from_google,
    generate_state_token,
    CognitoAuth,
    CognitoConfig,
)

# 1. Build authorization URL and redirect the user
state = generate_state_token()
auth_url = build_google_authorization_url(
    client_id="your-google-client-id",
    redirect_uri="http://localhost:8000/auth/google/callback",
    state=state,
)

# 2. In your callback handler, exchange the code for tokens
tokens = exchange_google_code_for_tokens(
    client_id="your-google-client-id",
    client_secret="your-google-client-secret",
    code=request.query_params["code"],
    redirect_uri="http://localhost:8000/auth/google/callback",
)

# 3. Fetch the user's Google profile
userinfo = fetch_google_userinfo(tokens["access_token"])
# userinfo contains: sub, email, email_verified, name, given_name,
#                    family_name, picture, locale, hd (if Google Workspace)

# 4. Auto-create or retrieve the Cognito user
config = CognitoConfig.from_legacy_env()
auth = CognitoAuth(
    region=config.region,
    user_pool_id=config.user_pool_id,
    app_client_id=config.app_client_id,
)
result = auto_create_cognito_user_from_google(auth, userinfo)
# result = {"user": {...}, "created": True/False, "google_sub": "...", "email": "..."}
```

### Google Attributes Captured

All attributes available with standard scopes (`openid email profile`) — no extra
permissions required:

| Claim | Description |
|-------|-------------|
| `sub` | Unique Google user ID |
| `email` | Email address |
| `email_verified` | Whether email is verified by Google |
| `name` | Full display name |
| `given_name` | First name |
| `family_name` | Last name |
| `picture` | Profile photo URL |
| `locale` | User locale (BCP 47) |
| `hd` | Hosted domain (Google Workspace only, absent for personal accounts) |

### Cognito Custom Attributes

The user pool must have these custom attributes configured:

- `custom:customer_id` — defaults to Google `sub`
- `custom:google_sub` — Google unique user ID
- `custom:google_hd` — hosted domain (optional, populated when present)

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev,auth]"

# Run tests
pytest -q

# Run tests with coverage
pytest --cov=daylily_cognito

# Lint and format
ruff check daylily_cognito tests
ruff format daylily_cognito tests
```

## License

MIT
