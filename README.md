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
    profile=config.aws_profile,
)
```

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

The `daycog` CLI provides commands for managing Cognito resources:

```bash
# Check configuration status
daycog status

# Create user pool and app client
daycog setup --name my-pool --port 8001

# List users
daycog list-users

# Add a user
daycog add-user user@example.com

# Set user password
daycog set-password --email user@example.com --password NewPass123

# Delete a user
daycog delete-user --email user@example.com

# Delete all users (use with caution!)
daycog delete-all-users --force

# Delete the entire pool
daycog teardown --force
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

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev,auth]"

# Run tests
pytest -q

# Run tests with coverage
pytest --cov=daylily_cognito
```

## License

MIT
