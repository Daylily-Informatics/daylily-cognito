# AI Directive: daylily-auth-cognito

## Operational Policy

Use this repository through `daycog` for normal Cognito operations.

- Do not run direct AWS Cognito CLI/API commands (`aws cognito-idp ...`) when `daycog` is the intended operational path.
- Do not bypass the CLI with ad hoc boto3 scripts or direct config-file edits unless the user explicitly approves a workaround.

## Environment Bootstrap

From repo root, always start with:

```sh
source ./activate
```

This prepares `.venv`, installs the repo editable, exposes `daycog`, and uses the published CLI dependency pinned by `pyproject.toml`.

## Config Model

The current model is one flat YAML config file per environment.

- Canonical path: `daycog config path`
- Default path: `~/.config/daycog/config.yaml`
- One-invocation override: root `--config PATH`

Required file keys:

- `COGNITO_REGION`
- `COGNITO_USER_POOL_ID`
- `COGNITO_APP_CLIENT_ID`

Optional file keys:

- `COGNITO_CLIENT_NAME`
- `COGNITO_CALLBACK_URL`
- `COGNITO_LOGOUT_URL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `COGNITO_DOMAIN`
- `AWS_PROFILE`
- `AWS_REGION`

The CLI-only flat-file model is implemented in `daylily_auth_cognito.cli.config`; its internal config helper is not a runtime API.

Unsupported old model:

- no named config namespaces
- no legacy context selector field
- no namespaced env override model
- no removed multi-target auth-config sync command
- no per-pool/per-app `.env` file workflow

## Resolution Rules

For config-consuming commands:

- non-`AWS_*` values come from the selected config file only
- AWS profile precedence: `--profile`, then file `AWS_PROFILE`, then env `AWS_PROFILE`
- AWS region precedence: `--region`, then file `COGNITO_REGION`, then file `AWS_REGION`, then env `AWS_REGION`

For commands that are purely flag/env driven, use:

1. `--profile`, `--region`
2. `AWS_PROFILE`, `AWS_REGION`

If required AWS context is still missing, the command errors.

## Required CLI Usage

### Orientation and config

```sh
daycog --help
daycog status
daycog config path
daycog config init
daycog auth-config print --json
daycog --config ./override.yaml auth-config print --json
daycog auth-config create --pool-name <pool-name> --client-name <app-name> --profile <profile> --region <region>
daycog auth-config update --pool-name <pool-name> --client-name <app-name> --profile <profile> --region <region>
```

### Pool and app lifecycle

```sh
daycog list-pools --profile <profile> --region <region>
daycog setup --name <pool-name> --profile <profile> --region <region>
daycog list-apps --pool-name <pool-name> --profile <profile> --region <region>
daycog add-app --pool-name <pool-name> --app-name <app-name> --callback-url <url> --profile <profile> --region <region>
daycog edit-app --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region>
daycog remove-app --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region> --force
daycog fix-auth-flows
```

### Google federation

```sh
daycog add-google-idp --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region>
daycog setup-with-google --name <pool-name> --client-name <app-name> --profile <profile> --region <region>
daycog setup-google --client-id <id> --client-secret <secret>
```

Current Google behavior:

- `setup-with-google` writes Google credentials into the effective config file
- `setup-google` writes Google credentials into the effective config file and prints the redirect URI to register
- `add-google-idp` reads Google credentials from flags, JSON, or the effective config file

### User and group operations

```sh
daycog list-users
daycog add-user <email> --password <password>
daycog set-password --email <email> --password <password>
daycog ensure-group <group-name>
daycog add-user-to-group --email <email> --group <group-name>
daycog set-user-attributes --email <email> --attribute Name=Value
daycog export --output <path>
```

### Destructive operations

```sh
daycog delete-user --email <email> --force
daycog delete-all-users --force
daycog delete-pool --pool-name <pool-name> --profile <profile> --region <region> --force
daycog teardown --force
```

Prefer `delete-pool` over `teardown` when the pool is explicitly known.

## Guardrails for Agents

- Prefer `daycog` over ad hoc boto3 scripts for operational actions.
- Do not use `aws cognito-idp` directly when this repo is designated for operations.
- Treat destructive commands as high-risk and use `--force` only when the user explicitly intends the deletion.
- Keep docs, tests, and examples aligned with the current flat-file config model and current command names.
- Service runtime modules must not import `daylily_auth_cognito.cli` or `daylily_auth_cognito.cli.config`.
