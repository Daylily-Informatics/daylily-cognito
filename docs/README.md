# daylily-auth-cognito Docs

Primary documents:
- `../IMPLEMENTATION_PLAN.md`
- `../MIGRATING_TO_2_0_0.md`
- `../CHANGELOG_2_0_0.md`

Package boundaries:
- `runtime/`: bearer verification, JWKS, M2M helpers, FastAPI dependency
- `browser/`: Hosted UI login/callback/session helpers and Google OAuth HTTP helpers
- `admin/`: Cognito mutation APIs
- `cli/`: daycog command wiring and config handling
- `policy/`: email-domain validation

CLI config handling is isolated in `daylily_auth_cognito.cli.config` and is not imported by runtime/browser/admin code.
