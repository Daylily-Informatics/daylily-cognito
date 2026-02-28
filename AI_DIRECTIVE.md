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
daycog delete-pool --pool-name <pool-name> --profile <profile> --region <region> --force
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
- `~/.config/daycog/<pool-name>.env`
- `~/.config/daycog/default.env`

These files contain:
- `AWS_PROFILE`
- `AWS_REGION`
- `COGNITO_REGION`
- `COGNITO_USER_POOL_ID`
- `COGNITO_APP_CLIENT_ID`
- `COGNITO_CALLBACK_URL`

## `daycog config` commands
Use these for file inspection/sync:

```sh
daycog config print
daycog config print --pool-name <pool-name>
daycog config create --pool-name <pool-name> --profile <profile> --region <region>
daycog config update --pool-name <pool-name> --profile <profile> --region <region>
```

`config create/update` query AWS for pool details and keep `default.env` aligned with the selected pool.
If multiple app clients exist in a pool, the CLI uses the first client returned by AWS.

## Guardrails for Agents
- Prefer `daycog` over ad-hoc boto3 scripts for operational actions.
- Do not use `aws cognito-idp` directly when this repo is designated for operations.
- Use `--force` only for destructive commands when explicitly intended.
