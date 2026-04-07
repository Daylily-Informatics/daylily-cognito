"""Google federation commands for daycog."""

from __future__ import annotations

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CliSpec

from daylily_auth_cognito.admin.federation import ensure_google_federation
from daylily_auth_cognito.admin.pools import find_user_pool_id_by_name
from daylily_auth_cognito.cli.config import ConfigError, active_config_path, load_config_file

from .config import (
    MUTATE_POLICY,
    _get_admin_client,
    _resolve_google_client_details,
    _write_effective_config,
)
from .pools import setup


def add_google_idp(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str | None = typer.Option(None, "--app-name", help="App client name in this pool"),
    client_id: str | None = typer.Option(None, "--client-id", help="App client ID in this pool"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    google_client_id: str | None = typer.Option(None, "--google-client-id", help="Google OAuth client ID"),
    google_client_secret: str | None = typer.Option(None, "--google-client-secret", help="Google OAuth client secret"),
    google_client_json: str | None = typer.Option(
        None, "--google-client-json", help="Path to Google OAuth client JSON"
    ),
    scopes: str = typer.Option("openid email profile", "--scopes", help="Google authorize scopes"),
) -> None:
    if not app_name and not client_id:
        ccyo_out.info("[red]x[/red] Provide one of: --app-name or --client-id")
        raise typer.Exit(1)
    admin, _runtime = _get_admin_client(
        profile=profile, region=region, require_config=True, require_required_keys=True, require_profile=True
    )
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    resolved_google_id, resolved_google_secret = _resolve_google_client_details(
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_client_json=google_client_json,
    )
    result = ensure_google_federation(
        admin,
        user_pool_id=pool_id,
        app_name=app_name,
        client_id=client_id,
        google_client_id=resolved_google_id,
        google_client_secret=resolved_google_secret,
        scopes=scopes,
    )
    ccyo_out.info(f"Enabled Google provider on app client: {result['client_name']} ({result['client_id']})")


def setup_with_google(
    pool_name: str = typer.Option("ursa-users", "--name", "-n", help="User pool name"),
    client_name: str | None = typer.Option(None, "--client-name", help="App client name (default: <pool-name>-client)"),
    domain_prefix: str | None = typer.Option(
        None, "--domain-prefix", help="Hosted UI domain prefix (default: pool name)"
    ),
    attach_domain: bool = typer.Option(
        True, "--attach-domain/--no-attach-domain", help="Attach/ensure Cognito Hosted UI domain"
    ),
    port: int = typer.Option(8001, "--port", "-p", help="Server port for callback URL"),
    callback_path: str = typer.Option(
        "/auth/callback", "--callback-path", help="Callback path used with --port when --callback-url is not set"
    ),
    callback_url: str | None = typer.Option(None, "--callback-url", help="Full callback URL override"),
    logout_url: str | None = typer.Option(None, "--logout-url", help="Optional logout URL for app client"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    print_exports: bool = typer.Option(False, "--print-exports", help="Print export commands for the caller shell"),
    autoprovision: bool = typer.Option(False, "--autoprovision", help="Reuse existing app client when present"),
    generate_secret: bool = typer.Option(False, "--generate-secret", help="Create app client with secret"),
    oauth_flows: str = typer.Option("code", "--oauth-flows", help="Comma-separated OAuth flows"),
    scopes: str = typer.Option("openid,email,profile", "--scopes", help="Comma-separated OAuth scopes"),
    idps: str = typer.Option("COGNITO", "--idp", help="Comma-separated identity providers"),
    password_min_length: int = typer.Option(8, "--password-min-length", help="Minimum password length"),
    require_uppercase: bool = typer.Option(
        True, "--require-uppercase/--no-require-uppercase", help="Require uppercase"
    ),
    require_lowercase: bool = typer.Option(
        True, "--require-lowercase/--no-require-lowercase", help="Require lowercase"
    ),
    require_numbers: bool = typer.Option(True, "--require-numbers/--no-require-numbers", help="Require numbers"),
    require_symbols: bool = typer.Option(False, "--require-symbols/--no-require-symbols", help="Require symbols"),
    mfa: str = typer.Option("off", "--mfa", help="MFA mode: off, optional, required"),
    tags: str | None = typer.Option(None, "--tags", help="Comma-separated tags in key=value format"),
    google_client_id: str | None = typer.Option(None, "--google-client-id", help="Google OAuth client ID"),
    google_client_secret: str | None = typer.Option(None, "--google-client-secret", help="Google OAuth client secret"),
    google_client_json: str | None = typer.Option(
        None, "--google-client-json", help="Path to Google OAuth client JSON"
    ),
    google_scopes: str = typer.Option("openid email profile", "--google-scopes", help="Google authorize scopes"),
) -> None:
    resolved_client_name = client_name or f"{pool_name}-client"
    setup(
        pool_name=pool_name,
        client_name=resolved_client_name,
        domain_prefix=domain_prefix,
        attach_domain=attach_domain,
        port=port,
        callback_path=callback_path,
        callback_url=callback_url,
        logout_url=logout_url,
        profile=profile,
        region=region,
        print_exports=print_exports,
        autoprovision=autoprovision,
        generate_secret=generate_secret,
        oauth_flows=oauth_flows,
        scopes=scopes,
        idps=idps,
        password_min_length=password_min_length,
        require_uppercase=require_uppercase,
        require_lowercase=require_lowercase,
        require_numbers=require_numbers,
        require_symbols=require_symbols,
        mfa=mfa,
        tags=tags,
    )
    resolved_google_id, resolved_google_secret = _resolve_google_client_details(
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_client_json=google_client_json,
    )
    add_google_idp(
        pool_name=pool_name,
        app_name=resolved_client_name,
        client_id=None,
        profile=profile,
        region=region,
        google_client_id=resolved_google_id,
        google_client_secret=resolved_google_secret,
        google_client_json=None,
        scopes=google_scopes,
    )
    current_values = load_config_file(active_config_path(), require_required_keys=True)
    current_values["GOOGLE_CLIENT_ID"] = resolved_google_id
    current_values["GOOGLE_CLIENT_SECRET"] = resolved_google_secret
    config_path = _write_effective_config(current_values)
    ccyo_out.info(f"Setup with Google IdP complete: {config_path}")


def setup_google(
    google_client_id: str = typer.Option(..., "--client-id", help="Google OAuth2 client ID"),
    google_client_secret: str = typer.Option(..., "--client-secret", help="Google OAuth2 client secret"),
    redirect_port: int = typer.Option(8000, "--port", "-p", help="Local server port for redirect URI"),
) -> None:
    try:
        values = load_config_file(active_config_path(), require_required_keys=True)
    except ConfigError as exc:
        ccyo_out.info(f"[red]x[/red] {exc}")
        raise typer.Exit(1) from exc
    values["GOOGLE_CLIENT_ID"] = google_client_id
    values["GOOGLE_CLIENT_SECRET"] = google_client_secret
    config_path = _write_effective_config(values)
    redirect_uri = f"http://localhost:{redirect_port}/auth/google/callback"
    ccyo_out.info(f"Wrote Google OAuth credentials to {config_path}")
    ccyo_out.info(f"Redirect URI: {redirect_uri}")


def register(registry: CommandRegistry, spec: CliSpec | None = None) -> None:
    del spec
    registry.add_command(
        None,
        "add-google-idp",
        add_google_idp,
        help_text="Configure Google IdP on a pool and enable it on an app client.",
        policy=MUTATE_POLICY,
    )
    registry.add_command(
        None,
        "setup-with-google",
        setup_with_google,
        help_text="Provision Cognito and configure Google IdP.",
        policy=MUTATE_POLICY,
    )
    registry.add_command(
        None,
        "setup-google",
        setup_google,
        help_text="Write Google OAuth credentials into the active config file.",
        policy=MUTATE_POLICY,
    )
