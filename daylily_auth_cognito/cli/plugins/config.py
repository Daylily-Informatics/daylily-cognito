"""CLI config helpers and auth-config commands."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.runtime import get_context
from cli_core_yo.spec import CliSpec, CommandPolicy
from rich.console import Console

from ...admin import app_clients as app_client_admin
from ...admin import pools as pool_admin
from ...admin.client import CognitoAdminClient
from ..config import (
    ConfigError,
    RuntimeConfig,
    active_config_path,
    load_config_file,
    load_config_file_if_present,
    resolve_runtime_config,
    write_config_file,
)

READ_ONLY_POLICY = CommandPolicy(supports_json=True, runtime_guard="exempt")
MUTATING_POLICY = CommandPolicy(mutates_state=True, runtime_guard="exempt")
INTERACTIVE_MUTATING_POLICY = CommandPolicy(mutates_state=True, interactive=True, runtime_guard="exempt")
READ_POLICY = READ_ONLY_POLICY
READ_JSON_POLICY = CommandPolicy(mutates_state=True, supports_json=True)
MUTATE_POLICY = MUTATING_POLICY


def _print_rich(renderable: Any) -> None:
    Console(
        file=sys.stdout,
        highlight=False,
        no_color="NO_COLOR" in os.environ,
        stderr=False,
    ).print(renderable)


def _parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_tags(value: str | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not value:
        return parsed
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        if "=" not in item:
            ccyo_out.info(f"[red]✗[/red]  Invalid tag format: {item}. Use key=value")
            raise typer.Exit(1)
        key, tag_value = item.split("=", 1)
        key = key.strip()
        tag_value = tag_value.strip()
        if not key:
            ccyo_out.info(f"[red]✗[/red]  Invalid empty tag key in: {item}")
            raise typer.Exit(1)
        parsed[key] = tag_value
    return parsed


def _parse_attributes(values: list[str]) -> list[dict[str, str]]:
    attributes: list[dict[str, str]] = []
    for raw in values:
        item = str(raw or "").strip()
        if not item:
            continue
        if "=" not in item:
            ccyo_out.info(f"[red]✗[/red]  Invalid attribute format: {item}. Use Name=Value")
            raise typer.Exit(1)
        name, value = item.split("=", 1)
        name = name.strip()
        if not name:
            ccyo_out.info(f"[red]✗[/red]  Invalid empty attribute name in: {item}")
            raise typer.Exit(1)
        attributes.append({"Name": name, "Value": value})
    return attributes


def _resolve_callback_url(callback_url: str | None, port: int, callback_path: str) -> str:
    if callback_url:
        return callback_url
    path = callback_path if callback_path.startswith("/") else f"/{callback_path}"
    return f"http://localhost:{port}{path}"


def _resolve_mfa_configuration(mfa: str) -> str:
    normalized = mfa.strip().lower()
    mapping = {"off": "OFF", "optional": "OPTIONAL", "required": "ON"}
    if normalized not in mapping:
        ccyo_out.info("[red]✗[/red]  Invalid --mfa value. Use one of: off, optional, required")
        raise typer.Exit(1)
    return mapping[normalized]


def _resolve_google_client_details(
    *,
    google_client_id: str | None,
    google_client_secret: str | None,
    google_client_json: str | None,
) -> tuple[str, str]:
    resolved_id = google_client_id
    resolved_secret = google_client_secret

    if google_client_json and (not resolved_id or not resolved_secret):
        try:
            payload = json.loads(Path(google_client_json).read_text(encoding="utf-8"))
            node = payload.get("web") or payload.get("installed") or {}
            resolved_id = resolved_id or node.get("client_id")
            resolved_secret = resolved_secret or node.get("client_secret")
        except Exception as exc:
            ccyo_out.info(f"[red]✗[/red]  Failed to read Google client JSON: {exc}")
            raise typer.Exit(1)

    if not resolved_id or not resolved_secret:
        try:
            values = load_config_file(active_config_path(), require_required_keys=True)
            resolved_id = resolved_id or values.get("GOOGLE_CLIENT_ID")
            resolved_secret = resolved_secret or values.get("GOOGLE_CLIENT_SECRET")
        except ConfigError:
            pass

    if not resolved_id or not resolved_secret:
        ccyo_out.info("[red]✗[/red]  Google OAuth client details missing")
        ccyo_out.info(
            "   Provide --google-client-id/--google-client-secret, or --google-client-json, "
            "or store GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the active config file"
        )
        raise typer.Exit(1)

    return resolved_id, resolved_secret


def _resolve_cognito_domain(pool_info: dict[str, Any], region: str) -> str:
    domain_prefix = pool_info.get("Domain")
    if domain_prefix:
        return f"{domain_prefix}.auth.{region}.amazoncognito.com"

    custom_domain = pool_info.get("CustomDomain")
    if isinstance(custom_domain, str):
        return custom_domain
    if isinstance(custom_domain, dict):
        custom_domain_name = custom_domain.get("DomainName")
        if custom_domain_name:
            return str(custom_domain_name)
    return ""


def _build_pool_details(
    pool: dict[str, Any],
    region: str,
    client_details: dict[str, str] | None = None,
) -> dict[str, str]:
    details = {
        "pool_id": pool["pool_id"],
        "pool_name": pool["pool_name"],
    }
    cognito_domain = _resolve_cognito_domain(pool["pool_info"], region)
    if cognito_domain:
        details["cognito_domain"] = cognito_domain
    if client_details:
        details.update(client_details)
    return details


def _build_config_values(
    profile: str,
    region: str,
    pool_details: dict[str, str],
    *,
    existing: dict[str, str] | None = None,
) -> dict[str, str]:
    config_values = dict(existing or {})
    for managed_key in [
        "AWS_PROFILE",
        "AWS_REGION",
        "COGNITO_REGION",
        "COGNITO_USER_POOL_ID",
        "COGNITO_APP_CLIENT_ID",
        "COGNITO_CLIENT_NAME",
        "COGNITO_CALLBACK_URL",
        "COGNITO_LOGOUT_URL",
        "COGNITO_DOMAIN",
    ]:
        config_values.pop(managed_key, None)
    config_values.update(
        {
            "AWS_PROFILE": profile,
            "AWS_REGION": region,
            "COGNITO_REGION": region,
            "COGNITO_USER_POOL_ID": pool_details["pool_id"],
        }
    )

    optional_keys = {
        "client_id": "COGNITO_APP_CLIENT_ID",
        "client_name": "COGNITO_CLIENT_NAME",
        "callback_url": "COGNITO_CALLBACK_URL",
        "logout_url": "COGNITO_LOGOUT_URL",
        "cognito_domain": "COGNITO_DOMAIN",
    }
    for source_key, target_key in optional_keys.items():
        value = pool_details.get(source_key)
        if value:
            config_values[target_key] = value

    return config_values


def _config_payload(path: Path, values: dict[str, str]) -> dict[str, Any]:
    return {"config_path": str(path), "values": values}


def _print_config(path: Path, values: dict[str, str], *, as_json: bool | None = None) -> None:
    payload = _config_payload(path, values)
    json_mode = as_json if as_json is not None else get_context().json_mode
    if json_mode:
        ccyo_out.emit_json(payload)
        return

    ccyo_out.info(f"{payload['config_path']}")
    for key in [
        "AWS_PROFILE",
        "AWS_REGION",
        "COGNITO_REGION",
        "COGNITO_USER_POOL_ID",
        "COGNITO_APP_CLIENT_ID",
        "COGNITO_CLIENT_NAME",
        "COGNITO_CALLBACK_URL",
        "COGNITO_LOGOUT_URL",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "COGNITO_DOMAIN",
    ]:
        value = payload["values"].get(key)
        if value:
            ccyo_out.info(f"{key}={value}")


def _handle_config_error(exc: Exception) -> None:
    path = active_config_path()
    ccyo_out.info(f"[red]✗[/red]  {exc}")
    ccyo_out.info(f"   Config path: [cyan]{path}[/cyan]")
    ccyo_out.info("   Use [cyan]daycog config init[/cyan] to create the file.")
    ccyo_out.info("   Override for one invocation with [cyan]daycog --config /path/to/config.yaml ...[/cyan]")
    raise SystemExit(1)


def _get_existing_config_values(*, require_required_keys: bool = False) -> dict[str, str]:
    try:
        return load_config_file_if_present(active_config_path(), require_required_keys=require_required_keys)
    except ConfigError as exc:
        _handle_config_error(exc)
    raise AssertionError("unreachable")


def _get_runtime_config(
    *,
    profile: str | None = None,
    region: str | None = None,
    require_config: bool = True,
    require_required_keys: bool = True,
    require_profile: bool = False,
) -> RuntimeConfig:
    try:
        runtime = resolve_runtime_config(
            profile=profile,
            region=region,
            require_config=require_config,
            require_required_keys=require_required_keys,
        )
    except ConfigError as exc:
        _handle_config_error(exc)
    if require_profile:
        try:
            runtime.require_aws_profile()
        except ConfigError as exc:
            _handle_config_error(exc)
    return runtime


def _get_admin_client(
    *,
    profile: str | None = None,
    region: str | None = None,
    require_config: bool = True,
    require_required_keys: bool = True,
    require_profile: bool = False,
) -> tuple[CognitoAdminClient, RuntimeConfig]:
    runtime = _get_runtime_config(
        profile=profile,
        region=region,
        require_config=require_config,
        require_required_keys=require_required_keys,
        require_profile=require_profile,
    )
    admin = CognitoAdminClient(
        region=runtime.aws_region,
        aws_profile=runtime.aws_profile,
    )
    return admin, runtime


def _get_pool_id() -> str:
    runtime = _get_runtime_config(require_profile=False)
    value = runtime.values.get("COGNITO_USER_POOL_ID", "").strip()
    if value:
        return value
    _handle_config_error(ConfigError("Missing required config value: COGNITO_USER_POOL_ID"))
    raise AssertionError("unreachable")


def _get_client_id() -> str:
    runtime = _get_runtime_config(require_profile=False)
    value = runtime.values.get("COGNITO_APP_CLIENT_ID", "").strip()
    if value:
        return value
    _handle_config_error(ConfigError("Missing required config value: COGNITO_APP_CLIENT_ID"))
    raise AssertionError("unreachable")


def _write_effective_config(values: dict[str, str]) -> Path:
    return write_config_file(active_config_path(), values)


def _describe_client(
    admin: CognitoAdminClient,
    pool_id: str,
    *,
    client_name: str | None = None,
    client_id: str | None = None,
) -> dict[str, str]:
    details = app_client_admin.describe_app_client(
        admin,
        user_pool_id=pool_id,
        client_name=client_name,
        client_id=client_id,
    )
    callback_urls = list(details.get("CallbackURLs", []))
    logout_urls = list(details.get("LogoutURLs", []))
    normalized = {
        "client_id": str(details["ClientId"]),
        "client_name": str(details["ClientName"]),
    }
    if callback_urls:
        normalized["callback_url"] = str(callback_urls[0])
    if logout_urls:
        normalized["logout_url"] = str(logout_urls[0])
    return normalized


def _select_config_client(
    admin: CognitoAdminClient,
    pool_id: str,
    *,
    client_name: str | None = None,
    client_id: str | None = None,
) -> dict[str, str] | None:
    if client_name and client_id:
        ccyo_out.info("[red]✗[/red]  Provide only one of: --client-name or --client-id")
        raise typer.Exit(1)

    clients = app_client_admin.list_app_clients(admin, user_pool_id=pool_id)
    if client_name or client_id:
        return _describe_client(admin, pool_id, client_name=client_name, client_id=client_id)
    if not clients:
        return None
    if len(clients) == 1:
        return _describe_client(admin, pool_id, client_id=str(clients[0]["ClientId"]))

    ccyo_out.info("[red]✗[/red]  Pool has multiple app clients; pass --client-name or --client-id")
    for client in clients:
        ccyo_out.info(f"   {client.get('ClientName', '')} ({client.get('ClientId', '')})")
    raise typer.Exit(1)


def _resolve_config_values_from_aws(
    *,
    pool_name: str | None,
    pool_id: str | None,
    client_name: str | None,
    client_id: str | None,
    callback_url: str | None,
    logout_url: str | None,
    profile: str | None,
    region: str | None,
    existing: dict[str, str] | None = None,
) -> tuple[Path, dict[str, str]]:
    admin, runtime = _get_admin_client(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )

    try:
        pool = pool_admin.resolve_pool(admin, pool_name=pool_name, pool_id=pool_id)
        selected_client = _select_config_client(
            admin,
            pool["pool_id"],
            client_name=client_name,
            client_id=client_id,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        ccyo_out.info(f"[red]✗[/red]  Error: {exc}")
        raise typer.Exit(1)

    if not selected_client:
        ccyo_out.info("[red]✗[/red]  Pool has no app clients; a flat config file requires an app client")
        raise typer.Exit(1)

    pool_details = _build_pool_details(pool, runtime.aws_region, selected_client)
    if callback_url is not None:
        pool_details["callback_url"] = callback_url
    if logout_url is not None:
        pool_details["logout_url"] = logout_url

    config_values = _build_config_values(
        runtime.require_aws_profile(),
        runtime.aws_region,
        pool_details,
        existing=existing or runtime.values,
    )
    return active_config_path(), config_values


def config_print() -> None:
    """Print the effective auth config file. Use global --json for machine-readable output."""
    try:
        path = active_config_path()
        values = load_config_file(path, require_required_keys=True)
    except ConfigError as exc:
        _handle_config_error(exc)
    _print_config(path, values)


def config_create(
    pool_name: str | None = typer.Option(None, "--pool-name", help="Pool name to resolve and write config for"),
    pool_id: str | None = typer.Option(None, "--pool-id", help="Pool ID to resolve and write config for"),
    client_name: str | None = typer.Option(None, "--client-name", help="App client name to write config for"),
    client_id: str | None = typer.Option(None, "--client-id", help="App client ID to write config for"),
    callback_url: str | None = typer.Option(None, "--callback-url", help="Override callback URL in written config"),
    logout_url: str | None = typer.Option(None, "--logout-url", help="Override logout URL in written config"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """Create the effective auth config file from live AWS state."""
    path = active_config_path()
    if path.exists():
        ccyo_out.info(f"[red]✗[/red]  Config file already exists: {path}")
        ccyo_out.info("   Use [cyan]daycog auth-config update[/cyan] to refresh it.")
        raise typer.Exit(1)

    _, config_values = _resolve_config_values_from_aws(
        pool_name=pool_name,
        pool_id=pool_id,
        client_name=client_name,
        client_id=client_id,
        callback_url=callback_url,
        logout_url=logout_url,
        profile=profile,
        region=region,
        existing={},
    )
    _write_effective_config(config_values)
    _print_config(path, config_values)


def config_update(
    pool_name: str | None = typer.Option(None, "--pool-name", help="Pool name to resolve and write config for"),
    pool_id: str | None = typer.Option(None, "--pool-id", help="Pool ID to resolve and write config for"),
    client_name: str | None = typer.Option(None, "--client-name", help="App client name to write config for"),
    client_id: str | None = typer.Option(None, "--client-id", help="App client ID to write config for"),
    callback_url: str | None = typer.Option(None, "--callback-url", help="Override callback URL in written config"),
    logout_url: str | None = typer.Option(None, "--logout-url", help="Override logout URL in written config"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """Update the effective auth config file from live AWS state."""
    path = active_config_path()
    try:
        existing = load_config_file(path, require_required_keys=True)
    except ConfigError as exc:
        _handle_config_error(exc)

    _, config_values = _resolve_config_values_from_aws(
        pool_name=pool_name,
        pool_id=pool_id,
        client_name=client_name,
        client_id=client_id,
        callback_url=callback_url,
        logout_url=logout_url,
        profile=profile,
        region=region,
        existing=existing,
    )
    _write_effective_config(config_values)
    _print_config(path, config_values)


def register(registry: CommandRegistry, spec: CliSpec) -> None:
    del spec
    registry.add_group("auth-config", help_text="Manage the effective daycog auth config file")
    registry.add_command(
        "auth-config",
        "print",
        config_print,
        help_text="Print the effective auth config file.",
        policy=READ_ONLY_POLICY,
    )
    registry.add_command(
        "auth-config",
        "create",
        config_create,
        help_text="Create the effective auth config file from live AWS state.",
        policy=MUTATING_POLICY,
    )
    registry.add_command(
        "auth-config",
        "update",
        config_update,
        help_text="Update the effective auth config file from live AWS state.",
        policy=MUTATING_POLICY,
    )
