# AI Directive: daylily-cognito

## Operational Policy
Use this repository through `daycog` for Cognito operations.
Do not run direct AWS Cognito CLI/API commands (`aws cognito-idp ...`) when this library is specified as the operational path.

If asked to perform Cognito pool/user/client lifecycle actions, use `daycog` commands.

## Environment Bootstrap
From repo root, always start with:

```sh
source ./daycog_activate
```

This prepares `.venv`, installs this repo editable, installs completion, and loads `~/.config/daycog/default.env` if present.
It also wraps `daycog setup` so exported values are applied to the current shell.

## AWS Context Rules
Many commands require AWS profile/region.

Resolution order for commands that accept flags:
1. `--profile`, `--region`
2. `AWS_PROFILE`, `AWS_REGION`

If still missing, the command errors.

## Required CLI Usage

### Pool lifecycle
```sh
daycog list-pools --profile <profile> --region <region>
daycog setup --name <pool-name> --port <port> --profile <profile> --region <region>
daycog list-apps --pool-name <pool-name> --profile <profile> --region <region>
daycog add-app --pool-name <pool-name> --app-name <app-name> --callback-url <url> --profile <profile> --region <region>
daycog edit-app --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region>
daycog remove-app --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region> --force
daycog add-google-idp --pool-name <pool-name> --app-name <app-name> --profile <profile> --region <region>
daycog delete-pool --pool-name <pool-name> --profile <profile> --region <region> --force
daycog delete-pool --pool-name <pool-name> --profile <profile> --region <region> --delete-domain-first --force
```

For setup customization, prefer `daycog setup` flags over direct AWS changes:
`--client-name`, `--callback-url`/`--callback-path`, `--logout-url`, `--generate-secret`,
`--oauth-flows`, `--scopes`, `--idp`, password policy flags, `--mfa`, `--tags`, `--autoprovision`.

### User lifecycle
```sh
daycog list-users
daycog add-user <email> --password <password>
daycog set-password --email <email> --password <password>
daycog delete-user --email <email> --force
daycog delete-all-users --force
```

### Auth/client maintenance
```sh
daycog status
daycog fix-auth-flows
daycog setup-google --client-id <id> --client-secret <secret>
```

## Config Files
`daycog setup` writes/updates:
- `~/.config/daycog/<pool-name>.<region>.env`
- `~/.config/daycog/<pool-name>.<region>.<app-name>.env`
- `~/.config/daycog/default.env`

These files contain:
- `AWS_PROFILE`
- `AWS_REGION`
- `COGNITO_REGION`
- `COGNITO_USER_POOL_ID`
- `COGNITO_APP_CLIENT_ID`
- `COGNITO_CLIENT_NAME`
- `COGNITO_CALLBACK_URL`
- `COGNITO_LOGOUT_URL` (if configured)

## `daycog config` commands
Use these for file inspection/sync:

```sh
daycog config print
daycog config print --pool-name <pool-name> --region <region>
daycog config create --pool-name <pool-name> --profile <profile> --region <region>
daycog config update --pool-name <pool-name> --profile <profile> --region <region>
```

`config create/update` query AWS for pool details and keep `default.env` aligned with the selected pool.
For pool-scoped print, region is required because filenames are region-scoped.
If multiple app clients exist in a pool, the CLI uses the first client returned by AWS.

Multi-app guidance:
- Keep one app file per app client (`<pool>.<region>.<app>.env`).
- Pool file (`<pool>.<region>.env`) stores the selected app context for that pool/region.
- `default.env` stores active global context.
- Use `--set-default` on `add-app`/`edit-app` when the new app should become active in pool/default env files.
- For Google federation, use `add-google-idp` with `--google-client-json` or credential flags/env vars.
- Do not assume Google client secret can be fetched from Google automatically; use provided JSON or env credentials.

## Guardrails for Agents
- Prefer `daycog` over ad-hoc boto3 scripts for operational actions.
- Do not use `aws cognito-idp` directly when this repo is designated for operations.
- Use `--force` only for destructive commands when explicitly intended.
