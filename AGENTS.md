# Daycog CLI Policy

## Session Setup

Always start by activating the repo environment:

```bash
source ./activate
```

## Command Ownership

- Use `daycog ...` as the primary interface for normal Cognito and shared auth work.
- Do not bypass `daycog` with raw AWS CLI mutations, ad hoc `python -m ...`, or direct config-file edits just because something is missing or broken.

## No Circumvention Policy

- If the intended CLI path is broken or incomplete, stop, diagnose, and ask for permission before circumventing it.
- Prefer patience and repair of the intended CLI workflow over inventing a shortcut.

## Daycog Examples

- Start with `source ./activate`
- Use `daycog status`
- Use `daycog config path`
- Use `daycog --json config print`
- Use `daycog ...` directly for Cognito pool, app, and user lifecycle
