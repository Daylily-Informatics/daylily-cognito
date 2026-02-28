# AI Directive: daylily-cognito

## Primary interface
Use this repository through the `daycog` CLI.
Do not treat this repo as a standalone app server; it is a Cognito/auth library plus operational CLI.

## Environment setup
1. From repo root, source:
   ```sh
   source ./daycog_activate
   ```
2. This creates/activates `.venv`, installs the repo editable, and makes `daycog` available.

## CLI command
- Executable: `daycog`
- Help: `daycog --help`

## Required AWS context
Most commands require:
- `AWS_PROFILE`
- Region context (usually `AWS_REGION`)

### `daycog setup` region/profile rules
`setup` uses this order:
1. `--profile` and `--region` flags
2. `AWS_PROFILE` and `AWS_REGION` environment variables

If either profile or region is still missing, `setup` exits with an error.
If flags are provided, `setup` sets `AWS_PROFILE` and `AWS_REGION` in the CLI process.

## Recommended usage flow
1. Check status:
   ```sh
   daycog status
   ```
2. Create pool + client:
   ```sh
   daycog setup --name my-pool --port 8001 --profile my-aws-profile --region us-west-2
   ```
3. List users:
   ```sh
   daycog list-users
   ```
4. Add a user:
   ```sh
   daycog add-user user@example.com --password 'Secure1234'
   ```

## High-impact commands (use intentionally)
- `daycog delete-user --email ...`
- `daycog delete-all-users --force`
- `daycog teardown --force`

## Multi-config mode
You can also pass `--config NAME` and use `DAYCOG_<NAME>_*` vars for app settings. This is separate from AWS profile/region used by `setup`.
