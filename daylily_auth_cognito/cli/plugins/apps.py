"""App-client daycog commands."""

from __future__ import annotations

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.runtime import get_context
from cli_core_yo.spec import CliSpec

from daylily_auth_cognito.admin.app_clients import (
    create_app_client,
    create_m2m_app_client,
    delete_app_client,
    find_app_client,
    list_app_clients,
    update_app_client,
)
from daylily_auth_cognito.admin.pools import find_user_pool_id_by_name

from .config import MUTATE_POLICY, READ_JSON_POLICY, READ_POLICY, _get_admin_client, _parse_csv


def list_apps(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    admin, runtime = _get_admin_client(
        profile=profile, region=region, require_config=False, require_required_keys=False, require_profile=True
    )
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    clients = list_app_clients(admin, user_pool_id=pool_id)
    ccyo_out.info(f"Cognito App Clients ({pool_name} / {runtime.aws_region})")
    for client in clients:
        ccyo_out.info(f"- {client.get('ClientName', '')} ({client.get('ClientId', '')})")
    ccyo_out.info(f"Total: {len(clients)} app clients")


def add_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str = typer.Option(..., "--app-name", help="App client name"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    callback_url: str = typer.Option(..., "--callback-url", help="OAuth callback URL"),
    logout_url: str | None = typer.Option(None, "--logout-url", help="Optional logout URL"),
    generate_secret: bool = typer.Option(False, "--generate-secret", help="Create app client with secret"),
    oauth_flows: str = typer.Option("code", "--oauth-flows", help="Comma-separated OAuth flows"),
    scopes: str = typer.Option("openid,email,profile", "--scopes", help="Comma-separated OAuth scopes"),
    idps: str = typer.Option("COGNITO", "--idp", help="Comma-separated identity providers"),
    set_default: bool = typer.Option(
        False, "--set-default", help="Print a reminder to refresh the auth config file to this app"
    ),
) -> None:
    admin, _runtime = _get_admin_client(
        profile=profile, region=region, require_config=False, require_required_keys=False, require_profile=True
    )
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    try:
        client = create_app_client(
            admin,
            client_name=app_name,
            user_pool_id=pool_id,
            generate_secret=generate_secret,
            allowed_oauth_flows=_parse_csv(oauth_flows),
            allowed_oauth_scopes=_parse_csv(scopes),
            callback_urls=[callback_url],
            logout_urls=[logout_url] if logout_url else [],
            supported_identity_providers=_parse_csv(idps),
            reuse_if_exists=False,
        )
    except ValueError as exc:
        ccyo_out.info(f"[red]x[/red] {exc}")
        raise typer.Exit(1) from exc
    ccyo_out.info(f"Created app client: {app_name} ({client['ClientId']})")
    if set_default:
        ccyo_out.info("Run daycog auth-config update if you want the config file to point at this app.")


def add_m2m_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str = typer.Option(..., "--app-name", help="External app client name"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    scopes: str = typer.Option(..., "--scopes", help="Comma-separated OAuth scopes for client_credentials"),
    emit_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
) -> None:
    admin, _runtime = _get_admin_client(
        profile=profile, region=region, require_config=False, require_required_keys=False, require_profile=True
    )
    resolved_scopes = _parse_csv(scopes)
    if not resolved_scopes:
        ccyo_out.info("[red]x[/red] Provide at least one scope with --scopes")
        raise typer.Exit(1)
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    created = create_m2m_app_client(admin, client_name=app_name, scopes=resolved_scopes, user_pool_id=pool_id)
    payload = {
        "pool_id": pool_id,
        "client_name": app_name,
        "client_id": str(created["ClientId"]),
        "client_secret": str(created.get("ClientSecret", "")),
        "scopes": resolved_scopes,
    }
    if emit_json or get_context().json_mode:
        ccyo_out.emit_json(payload)
        return
    ccyo_out.info(f"Created M2M app client: {app_name} ({payload['client_id']})")
    ccyo_out.info(f"Allowed scopes: {', '.join(resolved_scopes)}")
    ccyo_out.info(f"Client secret: {payload['client_secret']}")


def edit_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str | None = typer.Option(None, "--app-name", help="Existing app client name"),
    client_id: str | None = typer.Option(None, "--client-id", help="Existing app client ID"),
    new_app_name: str | None = typer.Option(None, "--new-app-name", help="Rename app client"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    callback_url: str | None = typer.Option(None, "--callback-url", help="Override callback URL"),
    logout_url: str | None = typer.Option(None, "--logout-url", help="Override logout URL"),
    oauth_flows: str | None = typer.Option(None, "--oauth-flows", help="Comma-separated OAuth flows"),
    scopes: str | None = typer.Option(None, "--scopes", help="Comma-separated OAuth scopes"),
    idps: str | None = typer.Option(None, "--idp", help="Comma-separated identity providers"),
    set_default: bool = typer.Option(
        False, "--set-default", help="Print a reminder to refresh the auth config file to this app"
    ),
) -> None:
    if not app_name and not client_id:
        ccyo_out.info("[red]x[/red] Provide one of: --app-name or --client-id")
        raise typer.Exit(1)
    admin, _runtime = _get_admin_client(
        profile=profile, region=region, require_config=False, require_required_keys=False, require_profile=True
    )
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    try:
        found = find_app_client(admin, user_pool_id=pool_id, client_name=app_name, client_id=client_id)
        overrides: dict[str, object] = {"ClientName": new_app_name or found["client_name"]}
        if callback_url:
            overrides["CallbackURLs"] = [callback_url]
        if logout_url:
            overrides["LogoutURLs"] = [logout_url]
        if oauth_flows:
            overrides["AllowedOAuthFlows"] = _parse_csv(oauth_flows)
        if scopes:
            overrides["AllowedOAuthScopes"] = _parse_csv(scopes)
        if idps:
            overrides["SupportedIdentityProviders"] = _parse_csv(idps)
        update_app_client(admin, client_id=found["client_id"], user_pool_id=pool_id, overrides=overrides)
    except ValueError as exc:
        ccyo_out.info(f"[red]x[/red] {exc}")
        raise typer.Exit(1) from exc
    ccyo_out.info(f"Updated app client: {new_app_name or found['client_name']} ({found['client_id']})")
    if set_default:
        ccyo_out.info("Run daycog auth-config update if you want the config file to point at this app.")


def remove_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str | None = typer.Option(None, "--app-name", help="App client name"),
    client_id: str | None = typer.Option(None, "--client-id", help="App client ID"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    delete_config: bool = typer.Option(True, "--delete-config/--keep-config", help="No-op compatibility flag"),
) -> None:
    del delete_config
    if not app_name and not client_id:
        ccyo_out.info("[red]x[/red] Provide one of: --app-name or --client-id")
        raise typer.Exit(1)
    admin, _runtime = _get_admin_client(
        profile=profile, region=region, require_config=False, require_required_keys=False, require_profile=True
    )
    pool_id = find_user_pool_id_by_name(admin, pool_name)
    try:
        found = find_app_client(admin, user_pool_id=pool_id, client_name=app_name, client_id=client_id)
    except ValueError as exc:
        ccyo_out.info(f"[red]x[/red] {exc}")
        raise typer.Exit(1) from exc
    if not force and not typer.confirm(f"Delete app client {found['client_name']} ({found['client_id']})?"):
        ccyo_out.info("Cancelled")
        return
    delete_app_client(admin, user_pool_id=pool_id, client_id=found["client_id"])
    ccyo_out.info(f"Deleted app client: {found['client_name']} ({found['client_id']})")


def register(registry: CommandRegistry, spec: CliSpec | None = None) -> None:
    del spec
    registry.add_command(None, "list-apps", list_apps, help_text="List app clients for a pool.", policy=READ_POLICY)
    registry.add_command(
        None, "add-app", add_app, help_text="Add a new app client to an existing pool.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None, "add-m2m-app", add_m2m_app, help_text="Create a client_credentials app client.", policy=READ_JSON_POLICY
    )
    registry.add_command(
        None, "edit-app", edit_app, help_text="Edit an existing app client in a pool.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None, "remove-app", remove_app, help_text="Remove an app client from a pool.", policy=MUTATE_POLICY
    )
