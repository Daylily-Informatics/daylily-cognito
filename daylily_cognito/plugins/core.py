"""Cognito authentication management CLI.

Provides commands for managing AWS Cognito user pools, app clients, and users.
Can be used standalone via `daycog` or integrated into other CLIs.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from cli_core_yo import ccyo_out
from rich.console import Console
from rich.table import Table

from .._app_client_update import (
    REQUIRED_AUTH_FLOWS,
    build_user_pool_client_update_request,
    merge_unique_strings,
)
from ..config import (
    ConfigError,
    active_config_path,
    load_config_file,
    load_config_file_if_present,
    resolve_runtime_config,
    write_config_file,
)

cognito_app = typer.Typer(help="Cognito authentication management commands")
config_app = typer.Typer(help="Manage the effective daycog auth config file")
cognito_app.add_typer(config_app, name="config")


def _print_rich(renderable: Any) -> None:
    """Render a Rich object to the current stdout."""
    Console(
        file=sys.stdout,
        highlight=False,
        no_color="NO_COLOR" in os.environ,
        stderr=False,
    ).print(renderable)


def _resolve_profile_region(profile: Optional[str], region: Optional[str]) -> tuple[str, str]:
    """Resolve profile/region from flags or environment, erroring if missing."""
    resolved_profile = profile or os.environ.get("AWS_PROFILE")
    resolved_region = region or os.environ.get("AWS_REGION")

    if not resolved_profile:
        ccyo_out.info("[red]✗[/red]  AWS profile not set")
        ccyo_out.info("   Pass [cyan]--profile[/cyan] or set [cyan]export AWS_PROFILE=your-profile[/cyan]")
        raise typer.Exit(1)

    if not resolved_region:
        ccyo_out.info("[red]✗[/red]  AWS region not set")
        ccyo_out.info("   Pass [cyan]--region[/cyan] or set [cyan]export AWS_REGION=us-west-2[/cyan]")
        raise typer.Exit(1)

    return resolved_profile, resolved_region


def _parse_csv(value: str) -> List[str]:
    """Parse comma-separated values into a normalized list."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_tags(value: Optional[str]) -> Dict[str, str]:
    """Parse tag input 'k=v,k2=v2' into a dictionary."""
    parsed: Dict[str, str] = {}
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


def _resolve_callback_url(callback_url: Optional[str], port: int, callback_path: str) -> str:
    """Resolve callback URL from explicit URL or localhost template."""
    if callback_url:
        return callback_url
    path = callback_path if callback_path.startswith("/") else f"/{callback_path}"
    return f"http://localhost:{port}{path}"


def _resolve_mfa_configuration(mfa: str) -> str:
    """Map CLI MFA value to Cognito API value."""
    normalized = mfa.strip().lower()
    mapping = {"off": "OFF", "optional": "OPTIONAL", "required": "ON"}
    if normalized not in mapping:
        ccyo_out.info("[red]✗[/red]  Invalid --mfa value. Use one of: off, optional, required")
        raise typer.Exit(1)
    return mapping[normalized]


def _resolve_google_client_details(
    *,
    google_client_id: Optional[str],
    google_client_secret: Optional[str],
    google_client_json: Optional[str],
) -> tuple[str, str]:
    """Resolve Google OAuth client credentials from flags/json/config file."""
    resolved_id = google_client_id
    resolved_secret = google_client_secret

    if google_client_json and (not resolved_id or not resolved_secret):
        try:
            payload = json.loads(Path(google_client_json).read_text(encoding="utf-8"))
            node = payload.get("web") or payload.get("installed") or {}
            resolved_id = resolved_id or node.get("client_id")
            resolved_secret = resolved_secret or node.get("client_secret")
        except Exception as e:
            ccyo_out.info(f"[red]✗[/red]  Failed to read Google client JSON: {e}")
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


def _resolve_cognito_domain(pool_info: Dict[str, Any], region: str) -> str:
    """Resolve a hosted UI domain hostname from pool details."""
    domain_prefix = pool_info.get("Domain")
    if domain_prefix:
        return f"{domain_prefix}.auth.{region}.amazoncognito.com"

    custom_domain = pool_info.get("CustomDomain")
    if isinstance(custom_domain, str):
        return custom_domain

    if isinstance(custom_domain, dict):
        custom_domain_name = custom_domain.get("DomainName")
        if custom_domain_name:
            return custom_domain_name

    return ""


def _resolve_pool(cognito: Any, pool_name: Optional[str] = None, pool_id: Optional[str] = None) -> Dict[str, Any]:
    """Resolve a pool by name or ID and return both identifiers plus pool info."""
    if not pool_name and not pool_id:
        ccyo_out.info("[red]✗[/red]  Provide one of: --pool-name or --pool-id")
        raise typer.Exit(1)

    if pool_id:
        pool_info = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        resolved_pool_name = pool_info["Name"]
        if pool_name and pool_name != resolved_pool_name:
            ccyo_out.info(f"[red]✗[/red]  Pool name '{pool_name}' does not match resolved pool '{resolved_pool_name}'")
            raise typer.Exit(1)
        return {"pool_id": pool_id, "pool_name": resolved_pool_name, "pool_info": pool_info}

    resolved_pool_id = _find_pool_id_by_name(cognito, pool_name or "")
    pool_info = cognito.describe_user_pool(UserPoolId=resolved_pool_id)["UserPool"]
    return {"pool_id": resolved_pool_id, "pool_name": pool_info["Name"], "pool_info": pool_info}


def _find_pool_id_by_name(cognito: Any, pool_name: str) -> str:
    """Find a user pool ID by pool name using list pagination."""
    paginator = cognito.get_paginator("list_user_pools")
    matched_pool: Optional[Dict[str, str]] = None
    for page in paginator.paginate(MaxResults=60):
        for pool in page.get("UserPools", []):
            if pool.get("Name") == pool_name:
                matched_pool = pool
                break
        if matched_pool:
            break

    if not matched_pool:
        ccyo_out.info(f"[red]✗[/red]  Pool not found: {pool_name}")
        raise typer.Exit(1)

    return matched_pool["Id"]


def _list_pool_clients(cognito: Any, pool_id: str) -> List[Dict[str, str]]:
    """List app clients in a pool."""
    return cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get("UserPoolClients", [])


def _find_client(
    cognito: Any, pool_id: str, client_name: Optional[str] = None, client_id: Optional[str] = None
) -> Dict[str, str]:
    """Find an app client by name or id in a pool."""
    clients = _list_pool_clients(cognito, pool_id)
    match = None
    if client_id:
        match = next((c for c in clients if c.get("ClientId") == client_id), None)
    elif client_name:
        match = next((c for c in clients if c.get("ClientName") == client_name), None)

    if not match:
        label = client_id or client_name or "<unknown>"
        ccyo_out.info(f"[red]✗[/red]  App client not found: {label}")
        raise typer.Exit(1)

    return {"client_id": match["ClientId"], "client_name": match["ClientName"]}


def _describe_client(
    cognito: Any,
    pool_id: str,
    *,
    client_name: Optional[str] = None,
    client_id: Optional[str] = None,
) -> Dict[str, str]:
    """Describe an app client and normalize values needed for flat config files."""
    found = _find_client(cognito, pool_id, client_name=client_name, client_id=client_id)
    client_cfg = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=found["client_id"])["UserPoolClient"]
    callback_urls = client_cfg.get("CallbackURLs", [])
    logout_urls = client_cfg.get("LogoutURLs", [])

    details = {
        "client_id": found["client_id"],
        "client_name": found["client_name"],
    }
    if callback_urls:
        details["callback_url"] = callback_urls[0]
    if logout_urls:
        details["logout_url"] = logout_urls[0]
    return details


def _select_config_client(
    cognito: Any,
    pool_id: str,
    *,
    client_name: Optional[str] = None,
    client_id: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    """Select a client for config commands, requiring explicit choice when multiple exist."""
    if client_name and client_id:
        ccyo_out.info("[red]✗[/red]  Provide only one of: --client-name or --client-id")
        raise typer.Exit(1)

    clients = _list_pool_clients(cognito, pool_id)
    if client_name or client_id:
        return _describe_client(cognito, pool_id, client_name=client_name, client_id=client_id)

    if not clients:
        return None

    if len(clients) == 1:
        return _describe_client(cognito, pool_id, client_id=clients[0]["ClientId"])

    ccyo_out.info("[red]✗[/red]  Pool has multiple app clients; pass --client-name or --client-id")
    for client in clients:
        ccyo_out.info(f"   {client.get('ClientName', '')} ({client.get('ClientId', '')})")
    raise typer.Exit(1)


def _render_env_lines(values: Dict[str, str]) -> List[str]:
    """Render key/value config settings as stable KEY=VALUE lines."""
    keys = [
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
    ]
    lines: List[str] = []
    for key in keys:
        value = values.get(key)
        if value:
            lines.append(f"{key}={value}")
    return lines


def _build_config_values(
    profile: str,
    region: str,
    pool_details: Dict[str, str],
    *,
    existing: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build flat-file config values from AWS-resolved pool and app details."""
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


def _build_pool_details(
    pool: Dict[str, Any],
    region: str,
    client_details: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build normalized pool/client details for persisted config values."""
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


def _config_payload(path: Path, values: Dict[str, str]) -> Dict[str, Any]:
    """Return a machine-readable representation of the effective flat config file."""
    return {"config_path": str(path), "values": values}


def _print_config(path: Path, values: Dict[str, str], *, as_json: bool | None = None) -> None:
    """Print the effective flat config file."""
    from cli_core_yo.runtime import get_context

    payload = _config_payload(path, values)
    json_mode = as_json if as_json is not None else get_context().json_mode
    if json_mode:
        ccyo_out.emit_json(payload)
        return

    ccyo_out.info(f"{payload['config_path']}")
    lines = _render_env_lines(payload["values"])
    if lines:
        ccyo_out.info("\n".join(lines))


def _handle_config_error(exc: Exception) -> None:
    """Emit a consistent config-file error with remediation."""
    path = active_config_path()
    ccyo_out.info(f"[red]✗[/red]  {exc}")
    ccyo_out.info(f"   Config path: [cyan]{path}[/cyan]")
    ccyo_out.info("   Use [cyan]daycog config init[/cyan] to create the file.")
    ccyo_out.info("   Override for one invocation with [cyan]daycog --config /path/to/config.yaml ...[/cyan]")
    raise SystemExit(1)


def _get_existing_config_values(*, require_required_keys: bool = False) -> Dict[str, str]:
    """Load the effective config file if it exists."""
    try:
        return load_config_file_if_present(active_config_path(), require_required_keys=require_required_keys)
    except ConfigError as exc:
        _handle_config_error(exc)
    raise AssertionError("unreachable")


def _get_runtime_config(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    require_config: bool = True,
    require_required_keys: bool = True,
    require_profile: bool = False,
) -> Any:
    """Resolve the effective config file plus AWS precedence."""
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


def _get_cognito_client(
    *,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    require_config: bool = True,
) -> Any:
    """Return a Cognito IDP client using effective config-path semantics."""
    import boto3

    runtime = _get_runtime_config(
        profile=profile,
        region=region,
        require_config=require_config,
        require_required_keys=require_config,
        require_profile=True,
    )
    session = boto3.Session(profile_name=runtime.require_aws_profile(), region_name=runtime.aws_region)
    return session.client("cognito-idp")


def _get_pool_id() -> str:
    """Return the configured Cognito User Pool ID."""
    runtime = _get_runtime_config(require_profile=False)
    value = runtime.values.get("COGNITO_USER_POOL_ID", "").strip()
    if value:
        return value
    _handle_config_error(ConfigError("Missing required config value: COGNITO_USER_POOL_ID"))
    raise AssertionError("unreachable")


def _get_client_id() -> str:
    """Return the configured Cognito App Client ID."""
    runtime = _get_runtime_config(require_profile=False)
    value = runtime.values.get("COGNITO_APP_CLIENT_ID", "").strip()
    if value:
        return value
    _handle_config_error(ConfigError("Missing required config value: COGNITO_APP_CLIENT_ID"))
    raise AssertionError("unreachable")


def _write_effective_config(values: Dict[str, str]) -> Path:
    """Write the effective config file for this invocation."""
    return write_config_file(active_config_path(), values)


def _parse_attributes(values: List[str]) -> List[Dict[str, str]]:
    """Parse repeated Name=Value attribute assignments."""
    attributes: List[Dict[str, str]] = []
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


@cognito_app.command("status")
def status() -> None:
    """Check Cognito configuration status."""
    ccyo_out.info("[cyan]Checking Cognito configuration...[/cyan]\n")

    try:
        import boto3

        runtime = _get_runtime_config(require_profile=True)
        session = boto3.Session(profile_name=runtime.require_aws_profile(), region_name=runtime.aws_region)
        cognito = session.client("cognito-idp")

        table = Table(title="Cognito Configuration")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_column("Source", style="dim")

        source = str(runtime.path)
        pool_id = runtime.values.get("COGNITO_USER_POOL_ID", "")
        client_id = runtime.values.get("COGNITO_APP_CLIENT_ID", "")

        table.add_row("Region", runtime.aws_region, source)

        if pool_id:
            try:
                pool = cognito.describe_user_pool(UserPoolId=pool_id)
                table.add_row("User Pool ID", pool_id, source)
                table.add_row("User Pool Name", pool["UserPool"]["Name"], "")
                table.add_row("Status", "[green]Active[/green]", "")
            except Exception as e:
                table.add_row("User Pool ID", pool_id, source)
                table.add_row("Status", f"[red]Error: {e}[/red]", "")
        else:
            table.add_row("User Pool ID", "[dim]Not configured[/dim]", "")

        if client_id:
            table.add_row("App Client ID", client_id, source)
        else:
            table.add_row("App Client ID", "[dim]Not configured[/dim]", "")

        status_data = {
            "region": runtime.aws_region,
            "user_pool_id": pool_id or None,
            "app_client_id": client_id or None,
            "config_source": source,
        }
        ccyo_out.emit_json(status_data)

        _print_rich(table)

        if not pool_id or not client_id:
            ccyo_out.info("\n[yellow]⚠[/yellow]  Cognito not fully configured")
            ccyo_out.info(
                "   Populate the active config file via [cyan]daycog setup[/cyan] or [cyan]daycog auth-config create[/cyan]"
            )

    except Exception as e:
        if isinstance(e, typer.Exit):
            raise
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("setup")
def setup(
    pool_name: str = typer.Option("ursa-users", "--name", "-n", help="User pool name"),
    client_name: Optional[str] = typer.Option(
        None, "--client-name", help="App client name (default: <pool-name>-client)"
    ),
    domain_prefix: Optional[str] = typer.Option(
        None, "--domain-prefix", help="Hosted UI domain prefix (default: pool name)"
    ),
    attach_domain: bool = typer.Option(
        True, "--attach-domain/--no-attach-domain", help="Attach/ensure Cognito Hosted UI domain"
    ),
    port: int = typer.Option(8001, "--port", "-p", help="Server port for callback URL"),
    callback_path: str = typer.Option(
        "/auth/callback", "--callback-path", help="Callback path used with --port when --callback-url is not set"
    ),
    callback_url: Optional[str] = typer.Option(None, "--callback-url", help="Full callback URL override"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Optional logout URL for app client"),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="AWS profile to use (defaults to AWS_PROFILE env var)",
    ),
    region: Optional[str] = typer.Option(
        None,
        "--region",
        help="AWS region to use (defaults to AWS_REGION env var)",
    ),
    print_exports: bool = typer.Option(
        False,
        "--print-exports",
        help="Print export commands so callers can eval them in the parent shell",
    ),
    autoprovision: bool = typer.Option(
        False,
        "--autoprovision",
        help="If set, reuse existing app client by --client-name when present",
    ),
    generate_secret: bool = typer.Option(
        False,
        "--generate-secret",
        help="Create app client with a secret (sets GenerateSecret=True)",
    ),
    oauth_flows: str = typer.Option("code", "--oauth-flows", help="Comma-separated OAuth flows (e.g. code,implicit)"),
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
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags in key=value format"),
):
    """Create Cognito User Pool and App Client."""
    runtime = _get_runtime_config(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )
    resolved_profile = runtime.require_aws_profile()
    resolved_region = runtime.aws_region

    ccyo_out.info("[cyan]Creating Cognito resources...[/cyan]")

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        resolved_client_name = client_name or f"{pool_name}-client"
        resolved_domain_prefix = domain_prefix or pool_name
        resolved_callback_url = _resolve_callback_url(callback_url, port, callback_path)
        resolved_oauth_flows = _parse_csv(oauth_flows)
        resolved_scopes = _parse_csv(scopes)
        resolved_idps = _parse_csv(idps)
        resolved_tags = _parse_tags(tags)
        resolved_mfa = _resolve_mfa_configuration(mfa)
        resolved_logout_urls = [logout_url] if logout_url else []

        ccyo_out.info(f"[dim]Profile: {resolved_profile}[/dim]")
        ccyo_out.info(f"[dim]Region: {resolved_region}[/dim]")
        cognito = session.client("cognito-idp")

        # Check if pool already exists
        pools = cognito.list_user_pools(MaxResults=60)
        existing = [p for p in pools["UserPools"] if p["Name"] == pool_name]

        if existing:
            ccyo_out.info(f"[yellow]⚠[/yellow]  User pool '{pool_name}' already exists")
            pool_id = existing[0]["Id"]
        else:
            # Create user pool
            pool = cognito.create_user_pool(
                PoolName=pool_name,
                AutoVerifiedAttributes=["email"],
                UsernameAttributes=["email"],
                MfaConfiguration=resolved_mfa,
                Policies={
                    "PasswordPolicy": {
                        "MinimumLength": password_min_length,
                        "RequireUppercase": require_uppercase,
                        "RequireLowercase": require_lowercase,
                        "RequireNumbers": require_numbers,
                        "RequireSymbols": require_symbols,
                    }
                },
                UserPoolTags=resolved_tags,
            )
            pool_id = pool["UserPool"]["Id"]
            ccyo_out.info(f"[green]✓[/green]  Created user pool: {pool_name}")

        resolved_cognito_domain: Optional[str] = None
        if attach_domain:
            pool_info = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
            current_domain = pool_info.get("Domain")
            if current_domain:
                if current_domain != resolved_domain_prefix:
                    ccyo_out.info(
                        f"[yellow]⚠[/yellow]  Pool already has domain '{current_domain}' "
                        f"(requested '{resolved_domain_prefix}'). Keeping existing domain."
                    )
                resolved_cognito_domain = f"{current_domain}.auth.{resolved_region}.amazoncognito.com"
            else:
                ccyo_out.info(f"[cyan]Attaching hosted UI domain: {resolved_domain_prefix}[/cyan]")
                cognito.create_user_pool_domain(UserPoolId=pool_id, Domain=resolved_domain_prefix)
                resolved_cognito_domain = f"{resolved_domain_prefix}.auth.{resolved_region}.amazoncognito.com"

        # Create or reuse app client
        client_id = ""
        if autoprovision:
            existing_clients = cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get(
                "UserPoolClients", []
            )
            existing_match = next((c for c in existing_clients if c.get("ClientName") == resolved_client_name), None)
            if existing_match:
                client_id = existing_match["ClientId"]
                ccyo_out.info(f"[yellow]⚠[/yellow]  Reusing app client '{resolved_client_name}': {client_id}")

        if not client_id:
            client = cognito.create_user_pool_client(
                UserPoolId=pool_id,
                ClientName=resolved_client_name,
                GenerateSecret=generate_secret,
                ExplicitAuthFlows=[
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_ADMIN_USER_PASSWORD_AUTH",  # Required for admin_initiate_auth
                    "ALLOW_REFRESH_TOKEN_AUTH",
                ],
                AllowedOAuthFlows=resolved_oauth_flows,
                AllowedOAuthScopes=resolved_scopes,
                AllowedOAuthFlowsUserPoolClient=True,
                CallbackURLs=[resolved_callback_url],
                LogoutURLs=resolved_logout_urls,
                SupportedIdentityProviders=resolved_idps,
            )
            client_id = client["UserPoolClient"]["ClientId"]
            ccyo_out.info(f"[green]✓[/green]  Created app client: {client_id}")

        setup_values = _build_config_values(
            resolved_profile,
            resolved_region,
            {
                "pool_id": pool_id,
                "client_id": client_id,
                "client_name": resolved_client_name,
                "callback_url": resolved_callback_url,
                "logout_url": logout_url or "",
                "cognito_domain": resolved_cognito_domain or "",
            },
            existing=runtime.values,
        )
        config_path = _write_effective_config(setup_values)

        ccyo_out.info("\n[green]✓[/green]  Cognito setup complete")
        ccyo_out.info(f"\nWrote config file: [cyan]{config_path}[/cyan]")
        ccyo_out.info("\nValues written to the effective config file:")
        ccyo_out.info(f"   [cyan]COGNITO_USER_POOL_ID={pool_id}[/cyan]")
        ccyo_out.info(f"   [cyan]COGNITO_APP_CLIENT_ID={client_id}[/cyan]")
        ccyo_out.info(f"   [cyan]COGNITO_CALLBACK_URL={resolved_callback_url}[/cyan]")
        if logout_url:
            ccyo_out.info(f"   [cyan]COGNITO_LOGOUT_URL={logout_url}[/cyan]")
        if resolved_cognito_domain:
            ccyo_out.info(f"   [cyan]COGNITO_DOMAIN={resolved_cognito_domain}[/cyan]")
        if print_exports:
            # Only AWS SDK env vars are exported; Cognito settings live in the config file.
            ccyo_out.info("\n[bold]Shell exports (boto3 SDK only):[/bold]")
            ccyo_out.info(f'export AWS_PROFILE="{resolved_profile}"')
            ccyo_out.info(f'export AWS_REGION="{resolved_region}"')

    except Exception as e:
        if isinstance(e, typer.Exit):
            raise
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


def _resolve_config_values_from_aws(
    *,
    pool_name: Optional[str],
    pool_id: Optional[str],
    client_name: Optional[str],
    client_id: Optional[str],
    callback_url: Optional[str],
    logout_url: Optional[str],
    profile: Optional[str],
    region: Optional[str],
    existing: Optional[Dict[str, str]] = None,
) -> tuple[Path, Dict[str, str]]:
    """Resolve a flat config payload from live AWS state."""
    if client_name and client_id:
        ccyo_out.info("[red]✗[/red]  Provide only one of: --client-name or --client-id")
        raise typer.Exit(1)

    runtime = _get_runtime_config(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )

    try:
        import boto3

        session = boto3.Session(profile_name=runtime.require_aws_profile(), region_name=runtime.aws_region)
        cognito = session.client("cognito-idp")
        pool = _resolve_pool(cognito, pool_name=pool_name, pool_id=pool_id)
        selected_client = _select_config_client(
            cognito,
            pool["pool_id"],
            client_name=client_name,
            client_id=client_id,
        )
    except typer.Exit:
        raise
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
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


@config_app.command("print")
def config_print() -> None:
    """Print the effective auth config file. Use global --json for machine-readable output."""
    try:
        path = active_config_path()
        values = load_config_file(path, require_required_keys=True)
    except ConfigError as exc:
        _handle_config_error(exc)
    _print_config(path, values)


@config_app.command("create")
def config_create(
    pool_name: Optional[str] = typer.Option(None, "--pool-name", help="Pool name to resolve and write config for"),
    pool_id: Optional[str] = typer.Option(None, "--pool-id", help="Pool ID to resolve and write config for"),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="App client name to write config for"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="App client ID to write config for"),
    callback_url: Optional[str] = typer.Option(None, "--callback-url", help="Override callback URL in written config"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Override logout URL in written config"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
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


@config_app.command("update")
def config_update(
    pool_name: Optional[str] = typer.Option(None, "--pool-name", help="Pool name to resolve and write config for"),
    pool_id: Optional[str] = typer.Option(None, "--pool-id", help="Pool ID to resolve and write config for"),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="App client name to write config for"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="App client ID to write config for"),
    callback_url: Optional[str] = typer.Option(None, "--callback-url", help="Override callback URL in written config"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Override logout URL in written config"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
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


@cognito_app.command("list-pools")
def list_pools(
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """List Cognito user pools in a region."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")

        table = Table(title=f"Cognito User Pools ({resolved_region})")
        table.add_column("Pool Name", style="cyan")
        table.add_column("Pool ID")

        paginator = cognito.get_paginator("list_user_pools")
        pools = []
        for page in paginator.paginate(MaxResults=60):
            for pool in page.get("UserPools", []):
                name = pool.get("Name", "")
                pool_id = pool.get("Id", "")
                pools.append({"name": name, "id": pool_id})
                table.add_row(name, pool_id)

        ccyo_out.emit_json({"pools": pools, "total": len(pools), "region": resolved_region})

        _print_rich(table)
        ccyo_out.info(f"\n[dim]Total: {len(pools)} pools[/dim]")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("list-apps")
def list_apps(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """List app clients for a pool."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        pool_id = _find_pool_id_by_name(cognito, pool_name)

        table = Table(title=f"Cognito App Clients ({pool_name} / {resolved_region})")
        table.add_column("Client Name", style="cyan")
        table.add_column("Client ID")

        clients_raw = cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get("UserPoolClients", [])
        clients = [{"name": c.get("ClientName", ""), "id": c.get("ClientId", "")} for c in clients_raw]
        for c in clients:
            table.add_row(c["name"], c["id"])

        ccyo_out.emit_json({"clients": clients, "total": len(clients), "pool_name": pool_name})

        _print_rich(table)
        ccyo_out.info(f"\n[dim]Total: {len(clients)} app clients[/dim]")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("add-app")
def add_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str = typer.Option(..., "--app-name", help="App client name"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    callback_url: str = typer.Option(..., "--callback-url", help="OAuth callback URL"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Optional logout URL"),
    generate_secret: bool = typer.Option(False, "--generate-secret", help="Create app client with secret"),
    oauth_flows: str = typer.Option("code", "--oauth-flows", help="Comma-separated OAuth flows"),
    scopes: str = typer.Option("openid,email,profile", "--scopes", help="Comma-separated OAuth scopes"),
    idps: str = typer.Option("COGNITO", "--idp", help="Comma-separated identity providers"),
    set_default: bool = typer.Option(
        False, "--set-default", help="Print a reminder to refresh the auth config file to this app"
    ),
) -> None:
    """Add a new app client to an existing pool."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    resolved_oauth_flows = _parse_csv(oauth_flows)
    resolved_scopes = _parse_csv(scopes)
    resolved_idps = _parse_csv(idps)
    resolved_logout_urls = [logout_url] if logout_url else []

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        pool_id = _find_pool_id_by_name(cognito, pool_name)

        existing = cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get("UserPoolClients", [])
        if any(c.get("ClientName") == app_name for c in existing):
            ccyo_out.info(f"[red]✗[/red]  App client already exists: {app_name}")
            raise typer.Exit(1)

        client = cognito.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=app_name,
            GenerateSecret=generate_secret,
            ExplicitAuthFlows=[
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
            ],
            AllowedOAuthFlows=resolved_oauth_flows,
            AllowedOAuthScopes=resolved_scopes,
            AllowedOAuthFlowsUserPoolClient=True,
            CallbackURLs=[callback_url],
            LogoutURLs=resolved_logout_urls,
            SupportedIdentityProviders=resolved_idps,
        )
        client_id = client["UserPoolClient"]["ClientId"]

        ccyo_out.info(f"[green]✓[/green]  Created app client: {app_name} ({client_id})")
        if set_default:
            ccyo_out.info("[dim]Run daycog auth-config update if you want the config file to point at this app.[/dim]")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("add-m2m-app")
def add_m2m_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: str = typer.Option(..., "--app-name", help="External app client name"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    scopes: str = typer.Option(..., "--scopes", help="Comma-separated OAuth scopes for client_credentials"),
    emit_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
) -> None:
    """Create a client_credentials app client for an external service."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    resolved_scopes = _parse_csv(scopes)
    if not resolved_scopes:
        ccyo_out.info("[red]✗[/red]  Provide at least one scope with --scopes")
        raise typer.Exit(1)

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        pool_id = _find_pool_id_by_name(cognito, pool_name)

        existing_clients = _list_pool_clients(cognito, pool_id)
        if any(client.get("ClientName") == app_name for client in existing_clients):
            ccyo_out.info(f"[red]✗[/red]  App client already exists: {app_name}")
            raise typer.Exit(1)

        client = cognito.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=app_name,
            GenerateSecret=True,
            AllowedOAuthFlows=["client_credentials"],
            AllowedOAuthScopes=resolved_scopes,
            AllowedOAuthFlowsUserPoolClient=True,
        )
        created = client["UserPoolClient"]
        client_id = str(created["ClientId"])
        client_secret = str(created.get("ClientSecret", ""))

        if emit_json:
            payload = {
                "pool_id": pool_id,
                "client_name": app_name,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": resolved_scopes,
            }
            sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
            return

        ccyo_out.info(f"[green]✓[/green]  Created M2M app client: {app_name} ({client_id})")
        ccyo_out.info(f"   Pool ID: {pool_id}")
        ccyo_out.info(f"   Allowed scopes: {', '.join(resolved_scopes)}")
        ccyo_out.info(f"   Client secret: {client_secret}")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("edit-app")
def edit_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: Optional[str] = typer.Option(None, "--app-name", help="Existing app client name"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="Existing app client ID"),
    new_app_name: Optional[str] = typer.Option(None, "--new-app-name", help="Rename app client"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    callback_url: Optional[str] = typer.Option(None, "--callback-url", help="Override callback URL"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Override logout URL"),
    oauth_flows: Optional[str] = typer.Option(None, "--oauth-flows", help="Comma-separated OAuth flows"),
    scopes: Optional[str] = typer.Option(None, "--scopes", help="Comma-separated OAuth scopes"),
    idps: Optional[str] = typer.Option(None, "--idp", help="Comma-separated identity providers"),
    set_default: bool = typer.Option(
        False, "--set-default", help="Print a reminder to refresh the auth config file to this app"
    ),
) -> None:
    """Edit an existing app client in a pool."""
    if not app_name and not client_id:
        ccyo_out.info("[red]✗[/red]  Provide one of: --app-name or --client-id")
        raise typer.Exit(1)

    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        pool_id = _find_pool_id_by_name(cognito, pool_name)
        found = _find_client(cognito, pool_id, client_name=app_name, client_id=client_id)

        overrides = {
            "ClientName": new_app_name or found["client_name"],
        }
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

        update_kwargs = build_user_pool_client_update_request(
            cognito,
            user_pool_id=pool_id,
            client_id=found["client_id"],
            overrides=overrides,
        )
        cognito.update_user_pool_client(**update_kwargs)

        final_name = str(update_kwargs["ClientName"])
        final_callback_urls = list(update_kwargs.get("CallbackURLs", []))
        final_logout_urls = list(update_kwargs.get("LogoutURLs", []))

        ccyo_out.info(f"[green]✓[/green]  Updated app client: {final_name} ({found['client_id']})")
        if final_callback_urls:
            ccyo_out.info(f"[dim]Callback URL: {final_callback_urls[0]}[/dim]")
        if final_logout_urls:
            ccyo_out.info(f"[dim]Logout URL: {final_logout_urls[0]}[/dim]")
        if set_default:
            ccyo_out.info("[dim]Run daycog auth-config update if you want the config file to point at this app.[/dim]")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("remove-app")
def remove_app(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: Optional[str] = typer.Option(None, "--app-name", help="App client name"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="App client ID"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    delete_config: bool = typer.Option(
        True, "--delete-config/--keep-config", help="No-op compatibility flag; config files are not edited here"
    ),
) -> None:
    """Remove an app client from a pool."""
    if not app_name and not client_id:
        ccyo_out.info("[red]✗[/red]  Provide one of: --app-name or --client-id")
        raise typer.Exit(1)

    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        pool_id = _find_pool_id_by_name(cognito, pool_name)
        found = _find_client(cognito, pool_id, client_name=app_name, client_id=client_id)

        if not force:
            ccyo_out.info("[red]⚠  WARNING: This will delete app client:[/red]")
            ccyo_out.info(f"   Pool: {pool_name} ({pool_id})")
            ccyo_out.info(f"   App: {found['client_name']} ({found['client_id']})")
            confirm = typer.confirm("Are you absolutely sure?")
            if not confirm:
                ccyo_out.info("[dim]Cancelled[/dim]")
                return

        cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=found["client_id"])
        ccyo_out.info(f"[green]✓[/green]  Deleted app client: {found['client_name']} ({found['client_id']})")

        if delete_config:
            ccyo_out.info(
                "[dim]Config files are no longer updated by remove-app; run daycog auth-config update if needed.[/dim]"
            )
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("add-google-idp")
def add_google_idp(
    pool_name: str = typer.Option(..., "--pool-name", help="Cognito pool name"),
    app_name: Optional[str] = typer.Option(None, "--app-name", help="App client name in this pool"),
    client_id: Optional[str] = typer.Option(None, "--client-id", help="App client ID in this pool"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    google_client_id: Optional[str] = typer.Option(None, "--google-client-id", help="Google OAuth client ID"),
    google_client_secret: Optional[str] = typer.Option(
        None, "--google-client-secret", help="Google OAuth client secret"
    ),
    google_client_json: Optional[str] = typer.Option(
        None, "--google-client-json", help="Path to Google OAuth client JSON (web/installed)"
    ),
    scopes: str = typer.Option("openid email profile", "--scopes", help="Google authorize scopes"),
) -> None:
    """Configure Google IdP on a pool and enable it on an app client."""
    if not app_name and not client_id:
        ccyo_out.info("[red]✗[/red]  Provide one of: --app-name or --client-id")
        raise typer.Exit(1)

    runtime = _get_runtime_config(
        profile=profile,
        region=region,
        require_config=True,
        require_required_keys=True,
        require_profile=True,
    )
    resolved_profile = runtime.require_aws_profile()
    resolved_region = runtime.aws_region
    resolved_google_id, resolved_google_secret = _resolve_google_client_details(
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_client_json=google_client_json,
    )

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")

        pool_id = _find_pool_id_by_name(cognito, pool_name)
        app = _find_client(cognito, pool_id, client_name=app_name, client_id=client_id)

        idp_name = "Google"
        provider_details = {
            "client_id": resolved_google_id,
            "client_secret": resolved_google_secret,
            "authorize_scopes": scopes,
        }
        attribute_mapping = {"email": "email", "username": "sub"}

        # Upsert identity provider
        idp_exists = False
        try:
            cognito.describe_identity_provider(UserPoolId=pool_id, ProviderName=idp_name)
            idp_exists = True
        except Exception:
            idp_exists = False

        if idp_exists:
            cognito.update_identity_provider(
                UserPoolId=pool_id,
                ProviderName=idp_name,
                ProviderDetails=provider_details,
                AttributeMapping=attribute_mapping,
            )
            ccyo_out.info("[green]✓[/green]  Updated Google identity provider")
        else:
            cognito.create_identity_provider(
                UserPoolId=pool_id,
                ProviderName=idp_name,
                ProviderType=idp_name,
                ProviderDetails=provider_details,
                AttributeMapping=attribute_mapping,
            )
            ccyo_out.info("[green]✓[/green]  Created Google identity provider")

        # Ensure app client allows Google provider
        update_kwargs = build_user_pool_client_update_request(
            cognito,
            user_pool_id=pool_id,
            client_id=app["client_id"],
            overrides={},
        )
        supported = merge_unique_strings(
            update_kwargs.get("SupportedIdentityProviders", []),
            ["Google"],
        )
        update_kwargs["SupportedIdentityProviders"] = supported
        cognito.update_user_pool_client(**update_kwargs)
        ccyo_out.info(
            f"[green]✓[/green]  Enabled Google provider on app client: {app['client_name']} ({app['client_id']})"
        )

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("setup-with-google")
def setup_with_google(
    pool_name: str = typer.Option("ursa-users", "--name", "-n", help="User pool name"),
    client_name: Optional[str] = typer.Option(
        None, "--client-name", help="App client name (default: <pool-name>-client)"
    ),
    domain_prefix: Optional[str] = typer.Option(
        None, "--domain-prefix", help="Hosted UI domain prefix (default: pool name)"
    ),
    attach_domain: bool = typer.Option(
        True, "--attach-domain/--no-attach-domain", help="Attach/ensure Cognito Hosted UI domain"
    ),
    port: int = typer.Option(8001, "--port", "-p", help="Server port for callback URL"),
    callback_path: str = typer.Option(
        "/auth/callback", "--callback-path", help="Callback path used with --port when --callback-url is not set"
    ),
    callback_url: Optional[str] = typer.Option(None, "--callback-url", help="Full callback URL override"),
    logout_url: Optional[str] = typer.Option(None, "--logout-url", help="Optional logout URL for app client"),
    profile: Optional[str] = typer.Option(
        None, "--profile", help="AWS profile to use (defaults to AWS_PROFILE env var)"
    ),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use (defaults to AWS_REGION env var)"),
    print_exports: bool = typer.Option(
        False, "--print-exports", help="Print export commands so callers can eval them in the parent shell"
    ),
    autoprovision: bool = typer.Option(
        False, "--autoprovision", help="If set, reuse existing app client by --client-name when present"
    ),
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
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags in key=value format"),
    google_client_id: Optional[str] = typer.Option(None, "--google-client-id", help="Google OAuth client ID"),
    google_client_secret: Optional[str] = typer.Option(
        None, "--google-client-secret", help="Google OAuth client secret"
    ),
    google_client_json: Optional[str] = typer.Option(
        None, "--google-client-json", help="Path to Google OAuth client JSON (web/installed)"
    ),
    google_scopes: str = typer.Option("openid email profile", "--google-scopes", help="Google authorize scopes"),
) -> None:
    """All-in-one setup: provision pool/app client and configure Google IdP."""
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

    ccyo_out.info(f"[green]✓[/green]  Setup with Google IdP complete: {config_path}")


@cognito_app.command("delete-pool")
def delete_pool(
    pool_name: Optional[str] = typer.Option(None, "--pool-name", help="Cognito pool name to delete"),
    pool_id: Optional[str] = typer.Option(None, "--pool-id", help="Cognito pool ID to delete"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    delete_domain_first: bool = typer.Option(
        False, "--delete-domain-first", help="Delete configured Cognito domain before deleting pool"
    ),
) -> None:
    """Delete a Cognito user pool by name or ID."""
    if not pool_name and not pool_id:
        ccyo_out.info("[red]✗[/red]  Provide one of: [cyan]--pool-name[/cyan] or [cyan]--pool-id[/cyan]")
        raise typer.Exit(1)

    resolved_profile, resolved_region = _resolve_profile_region(profile, region)

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")
        resolved_pool = _resolve_pool(cognito, pool_name=pool_name, pool_id=pool_id)
        resolved_pool_id = resolved_pool["pool_id"]
        resolved_pool_name = resolved_pool["pool_name"]
        pool_info = resolved_pool["pool_info"]
        domain = pool_info.get("Domain")
        custom_domain = pool_info.get("CustomDomain")
        domain_name = domain or custom_domain

        if not force:
            ccyo_out.info("[red]⚠  WARNING: This will delete the Cognito pool:[/red]")
            ccyo_out.info(f"   Pool Name: {resolved_pool_name}")
            ccyo_out.info(f"   Pool ID: {resolved_pool_id}")
            if domain_name:
                ccyo_out.info(f"   Domain: {domain_name}")
            ccyo_out.info("   [red]All users will be permanently deleted![/red]")
            confirm = typer.confirm("Are you absolutely sure?")
            if not confirm:
                ccyo_out.info("[dim]Cancelled[/dim]")
                return

        if delete_domain_first and domain_name:
            ccyo_out.info(f"[cyan]Deleting pool domain {domain_name}...[/cyan]")
            cognito.delete_user_pool_domain(UserPoolId=resolved_pool_id, Domain=domain_name)
            # AWS can take a few seconds to detach domain before pool deletion is accepted.
            for _ in range(12):
                latest_pool = cognito.describe_user_pool(UserPoolId=resolved_pool_id)["UserPool"]
                if not latest_pool.get("Domain") and not latest_pool.get("CustomDomain"):
                    break
                time.sleep(1)

        cognito.delete_user_pool(UserPoolId=resolved_pool_id)
        ccyo_out.info(f"[green]✓[/green]  Deleted Cognito pool: {resolved_pool_name} ({resolved_pool_id})")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("fix-auth-flows")
def fix_auth_flows():
    """Enable required auth flows on the app client.

    Fixes 'Auth flow not enabled for this client' error by enabling
    ALLOW_ADMIN_USER_PASSWORD_AUTH on the existing app client.
    """
    pool_id = _get_pool_id()
    client_id = _get_client_id()

    try:
        cognito = _get_cognito_client()

        ccyo_out.info(f"[cyan]Updating app client {client_id}...[/cyan]")

        update_kwargs = build_user_pool_client_update_request(
            cognito,
            user_pool_id=pool_id,
            client_id=client_id,
            overrides={},
        )
        required_flows = merge_unique_strings(
            update_kwargs.get("ExplicitAuthFlows", []),
            REQUIRED_AUTH_FLOWS,
        )
        update_kwargs["ExplicitAuthFlows"] = required_flows
        cognito.update_user_pool_client(**update_kwargs)

        ccyo_out.info("[green]✓[/green]  Enabled auth flows:")
        ccyo_out.info("     - ALLOW_USER_PASSWORD_AUTH")
        ccyo_out.info("     - ALLOW_ADMIN_USER_PASSWORD_AUTH")
        ccyo_out.info("     - ALLOW_REFRESH_TOKEN_AUTH")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("set-password")
def set_password(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email address"),
    password: str = typer.Option(..., "--password", "-p", prompt="New password", hide_input=True, help="New password"),
):
    """Set password for a Cognito user."""
    pool_id = _get_pool_id()

    try:
        cognito = _get_cognito_client()
        cognito.admin_set_user_password(
            UserPoolId=pool_id,
            Username=email,
            Password=password,
            Permanent=True,
        )

        ccyo_out.info(f"[green]✓[/green]  Password set for: {email}")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("ensure-group")
def ensure_group(
    group_name: str = typer.Argument(..., help="Group name"),
    description: str = typer.Option("", "--description", help="Optional group description"),
):
    """Ensure a Cognito group exists in the configured pool."""
    pool_id = _get_pool_id()

    try:
        cognito = _get_cognito_client()
        paginator = cognito.get_paginator("list_groups")
        for page in paginator.paginate(UserPoolId=pool_id):
            for group in page.get("Groups", []):
                if group.get("GroupName") == group_name:
                    ccyo_out.info(f"[green]✓[/green]  Group already exists: {group_name}")
                    return

        params: Dict[str, Any] = {"UserPoolId": pool_id, "GroupName": group_name}
        if description.strip():
            params["Description"] = description.strip()
        cognito.create_group(**params)
        ccyo_out.info(f"[green]✓[/green]  Created group: {group_name}")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("add-user-to-group")
def add_user_to_group(
    email: str = typer.Option(..., "--email", help="User email address"),
    group_name: str = typer.Option(..., "--group", help="Target Cognito group"),
):
    """Add a user to a Cognito group."""
    pool_id = _get_pool_id()

    try:
        cognito = _get_cognito_client()
        cognito.admin_add_user_to_group(
            UserPoolId=pool_id,
            Username=email,
            GroupName=group_name,
        )
        ccyo_out.info(f"[green]✓[/green]  Added {email} to group: {group_name}")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("set-user-attributes")
def set_user_attributes(
    email: str = typer.Option(..., "--email", help="User email address"),
    attribute: List[str] = typer.Option(
        [],
        "--attribute",
        "-a",
        help="Attribute assignment in Name=Value form. Repeat for multiple attributes.",
    ),
):
    """Update Cognito user attributes such as custom:tenant_id or custom:roles."""
    pool_id = _get_pool_id()
    attributes = _parse_attributes(attribute)
    if not attributes:
        ccyo_out.info("[red]✗[/red]  Provide at least one --attribute Name=Value pair")
        raise typer.Exit(1)

    try:
        cognito = _get_cognito_client()
        cognito.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=email,
            UserAttributes=attributes,
        )
        ccyo_out.info(f"[green]✓[/green]  Updated attributes for: {email}")
        for entry in attributes:
            ccyo_out.info(f"   {entry['Name']}={entry['Value']}")
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


def _generate_temp_password() -> str:
    """Generate a secure temporary password."""
    import secrets
    import string

    # 12 chars: upper, lower, digits (no symbols per policy)
    alphabet = string.ascii_letters + string.digits
    # Ensure at least one of each required type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    # Fill remaining with random chars
    password += [secrets.choice(alphabet) for _ in range(9)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


@cognito_app.command("add-user")
def add_user(
    email: str = typer.Argument(..., help="User email address"),
    password: str = typer.Option(None, "--password", "-p", help="Password (generated if not provided)"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip email verification (auto-confirm)"),
):
    """Add a new user to the Cognito pool.

    Creates a user with the given email. If no password is provided, a temporary
    password is generated and the user will be prompted to change it on first login.

    Examples:
        ursa cognito add-user user@example.com
        ursa cognito add-user user@example.com --password MySecure123
        ursa cognito add-user user@example.com --no-verify
    """
    pool_id = _get_pool_id()

    try:
        cognito = _get_cognito_client()

        # Generate password if not provided
        temp_password = password or _generate_temp_password()
        is_temp = password is None

        # Create user
        user_attributes: List[Dict[str, str]] = [
            {"Name": "email", "Value": email},
        ]
        create_params: Dict[str, Any] = {
            "UserPoolId": pool_id,
            "Username": email,
            "TemporaryPassword": temp_password,
            "UserAttributes": user_attributes,
            "MessageAction": "SUPPRESS",  # Don't send welcome email (we'll show password)
        }

        if no_verify:
            user_attributes.append({"Name": "email_verified", "Value": "true"})

        cognito.admin_create_user(**create_params)
        ccyo_out.info(f"[green]✓[/green]  Created user: {email}")

        # If --no-verify, set permanent password immediately
        if no_verify and password:
            cognito.admin_set_user_password(
                UserPoolId=pool_id,
                Username=email,
                Password=password,
                Permanent=True,
            )
            ccyo_out.info("[green]✓[/green]  Password set (permanent)")
        elif is_temp:
            ccyo_out.info(f"\n[yellow]Temporary password:[/yellow] {temp_password}")
            ccyo_out.info("[dim]User must change password on first login[/dim]")
        else:
            ccyo_out.info("[green]✓[/green]  Password set (temporary - must change on first login)")

    except cognito.exceptions.UsernameExistsException:
        ccyo_out.info(f"[red]✗[/red]  User already exists: {email}")
        raise typer.Exit(1)
    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("list-users")
def list_users(
    limit: int = typer.Option(50, "--limit", "-l", help="Max users to list"),
):
    """List all Cognito users."""
    pool_id = _get_pool_id()

    try:
        cognito = _get_cognito_client()

        table = Table(title=f"Cognito Users ({pool_id})")
        table.add_column("Email", style="cyan")
        table.add_column("Customer ID")
        table.add_column("Status")
        table.add_column("Created")
        table.add_column("Enabled")

        paginator = cognito.get_paginator("list_users")
        user_count = 0

        for page in paginator.paginate(UserPoolId=pool_id, PaginationConfig={"MaxItems": limit}):
            for user in page.get("Users", []):
                email = ""
                customer_id = ""
                for attr in user.get("Attributes", []):
                    if attr["Name"] == "email":
                        email = attr["Value"]
                    elif attr["Name"] == "custom:customer_id":
                        customer_id = attr["Value"]

                status = user.get("UserStatus", "UNKNOWN")
                created = user.get("UserCreateDate", "")
                if created:
                    created = created.strftime("%Y-%m-%d %H:%M")
                enabled = "[green]Yes[/green]" if user.get("Enabled", False) else "[red]No[/red]"

                status_color = {
                    "CONFIRMED": "[green]CONFIRMED[/green]",
                    "UNCONFIRMED": "[yellow]UNCONFIRMED[/yellow]",
                    "FORCE_CHANGE_PASSWORD": "[yellow]FORCE_CHANGE_PASSWORD[/yellow]",
                    "COMPROMISED": "[red]COMPROMISED[/red]",
                }.get(status, status)

                table.add_row(email, customer_id, status_color, str(created), enabled)
                user_count += 1

        _print_rich(table)
        ccyo_out.info(f"\n[dim]Total: {user_count} users[/dim]")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("export")
def export_users(
    output: str = typer.Option("cognito_users.log", "--output", "-o", help="Output file path"),
):
    """Export all Cognito users to a log file."""
    pool_id = _get_pool_id()

    try:
        import json
        from datetime import datetime, timezone

        runtime = _get_runtime_config(require_profile=True)
        region = runtime.aws_region
        cognito = _get_cognito_client()

        ccyo_out.info(f"[cyan]Exporting users from pool {pool_id}...[/cyan]")

        users = []
        paginator = cognito.get_paginator("list_users")

        for page in paginator.paginate(UserPoolId=pool_id):
            for user in page.get("Users", []):
                user_record = {
                    "username": user.get("Username"),
                    "status": user.get("UserStatus"),
                    "enabled": user.get("Enabled"),
                    "created": user.get("UserCreateDate").isoformat() if user.get("UserCreateDate") else None,
                    "modified": user.get("UserLastModifiedDate").isoformat()
                    if user.get("UserLastModifiedDate")
                    else None,
                    "attributes": {attr["Name"]: attr["Value"] for attr in user.get("Attributes", [])},
                }
                users.append(user_record)

        # Write to file
        export_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "pool_id": pool_id,
            "region": region,
            "user_count": len(users),
            "users": users,
        }

        with open(output, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        ccyo_out.info(f"[green]✓[/green]  Exported {len(users)} users to: {output}")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("delete-user")
def delete_user(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a single Cognito user."""
    pool_id = _get_pool_id()

    if not force:
        ccyo_out.info(f"[yellow]⚠[/yellow]  This will delete user: {email}")
        confirm = typer.confirm("Are you sure?")
        if not confirm:
            ccyo_out.info("[dim]Cancelled[/dim]")
            return

    try:
        cognito = _get_cognito_client()

        cognito.admin_delete_user(UserPoolId=pool_id, Username=email)
        ccyo_out.info(f"[green]✓[/green]  Deleted user: {email}")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("delete-all-users")
def delete_all_users(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete ALL users from the Cognito pool. Use with caution!"""
    pool_id = _get_pool_id()

    if not force:
        ccyo_out.info(f"[red]⚠  WARNING: This will delete ALL users from pool {pool_id}![/red]")
        confirm = typer.confirm("Are you absolutely sure?")
        if not confirm:
            ccyo_out.info("[dim]Cancelled[/dim]")
            return

    try:
        cognito = _get_cognito_client()

        ccyo_out.info(f"[cyan]Deleting all users from pool {pool_id}...[/cyan]")

        deleted_count = 0
        paginator = cognito.get_paginator("list_users")

        for page in paginator.paginate(UserPoolId=pool_id):
            for user in page.get("Users", []):
                username = user.get("Username")
                try:
                    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
                    ccyo_out.info(f"[dim]  Deleted: {username}[/dim]")
                    deleted_count += 1
                except Exception as e:
                    ccyo_out.info(f"[yellow]  Failed to delete {username}: {e}[/yellow]")

        ccyo_out.info(f"\n[green]✓[/green]  Deleted {deleted_count} users")

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("teardown")
def teardown(
    pool_name: str = typer.Option(None, "--name", "-n", help="Pool name to delete (if not using env var)"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete the Cognito User Pool and all its users."""
    try:
        import boto3

        runtime = _get_runtime_config(require_profile=True)
        session = boto3.Session(profile_name=runtime.require_aws_profile(), region_name=runtime.aws_region)
        cognito = session.client("cognito-idp")
        pool_id: Optional[str] = runtime.values.get("COGNITO_USER_POOL_ID")

        if not pool_id and pool_name:
            pools = cognito.list_user_pools(MaxResults=60)
            for p in pools["UserPools"]:
                if p["Name"] == pool_name:
                    pool_id = p["Id"]
                    break

        if not pool_id:
            ccyo_out.info("[red]✗[/red]  No pool ID found")
            ccyo_out.info(
                "   Populate the active config file via [cyan]daycog setup[/cyan] or [cyan]daycog auth-config create[/cyan]"
            )
            ccyo_out.info("   Or use --name to search by pool name")
            raise typer.Exit(1)

        # Get pool info for confirmation
        pool_info = cognito.describe_user_pool(UserPoolId=pool_id)
        pool_name_actual = pool_info["UserPool"]["Name"]

        if not force:
            ccyo_out.info("[red]⚠  WARNING: This will delete the Cognito pool:[/red]")
            ccyo_out.info(f"   Pool ID: {pool_id}")
            ccyo_out.info(f"   Pool Name: {pool_name_actual}")
            ccyo_out.info("   [red]All users will be permanently deleted![/red]")
            confirm = typer.confirm("Are you absolutely sure?")
            if not confirm:
                ccyo_out.info("[dim]Cancelled[/dim]")
                return

        ccyo_out.info(f"[cyan]Deleting pool {pool_id}...[/cyan]")
        cognito.delete_user_pool(UserPoolId=pool_id)
        ccyo_out.info(f"[green]✓[/green]  Deleted Cognito pool: {pool_name_actual} ({pool_id})")
        ccyo_out.info(
            "\n[yellow]Remember to refresh or remove the config file if it still points at this pool.[/yellow]"
        )

    except Exception as e:
        ccyo_out.info(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("setup-google")
def setup_google(
    google_client_id: str = typer.Option(..., "--client-id", help="Google OAuth2 client ID"),
    google_client_secret: str = typer.Option(..., "--client-secret", help="Google OAuth2 client secret"),
    redirect_port: int = typer.Option(8000, "--port", "-p", help="Local server port for redirect URI"),
) -> None:
    """Write Google OAuth credentials into the effective config file."""
    try:
        values = load_config_file(active_config_path(), require_required_keys=True)
    except ConfigError as exc:
        _handle_config_error(exc)

    values["GOOGLE_CLIENT_ID"] = google_client_id
    values["GOOGLE_CLIENT_SECRET"] = google_client_secret
    config_path = _write_effective_config(values)
    redirect_uri = f"http://localhost:{redirect_port}/auth/google/callback"

    ccyo_out.info("\n[bold cyan]Google OAuth Configuration[/bold cyan]\n")
    ccyo_out.info(f"Wrote Google OAuth credentials to [cyan]{config_path}[/cyan]\n")

    ccyo_out.info("\n[dim]Redirect URI (register in Google Cloud Console):[/dim]")
    ccyo_out.info(f"  {redirect_uri}\n")

    # Show a quick integration snippet
    ccyo_out.info("[bold]Quick integration example:[/bold]\n")
    ccyo_out.info("[dim]from daylily_cognito import ([/dim]")
    ccyo_out.info("[dim]    build_google_authorization_url,[/dim]")
    ccyo_out.info("[dim]    exchange_google_code_for_tokens,[/dim]")
    ccyo_out.info("[dim]    fetch_google_userinfo,[/dim]")
    ccyo_out.info("[dim]    auto_create_cognito_user_from_google,[/dim]")
    ccyo_out.info("[dim])[/dim]\n")

    ccyo_out.info("[green]✓[/green] Google OAuth credentials stored in the active config file.\n")


from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CliSpec


def register(registry: CommandRegistry, spec: CliSpec) -> None:
    """Register commands for the daycog CLI."""
    # Use the name 'cognito' or map individual commands?
    # The instructions say "Migrate existing subcommands into the plugin system"
    # Given the original entrypoint ran `cognito_app()` directly, we can loop over its commands.
    # But adding it as a typer app might be cleaner. Let's just add it as a sub-app "cognito".
    # Wait, daycog is only for cognito. Adding them directly to root is better.
    for cmd in cognito_app.registered_commands:
        registry.add_command(
            group_path=None,
            name=cmd.name or cmd.callback.__name__.replace("_", "-"),
            callback=cmd.callback,
            help_text=cmd.help or "",
        )
    for group in cognito_app.registered_groups:
        registry.add_typer_app(
            group_path=None,
            typer_app=group.typer_instance,
            name="auth-config" if group.name == "config" else (group.name or group.typer_instance.info.name),
            help_text=group.help or group.typer_instance.info.help or "",
        )
