"""Cognito authentication management CLI.

Provides commands for managing AWS Cognito user pools, app clients, and users.
Can be used standalone via `daycog` or integrated into other CLIs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import CognitoConfig

cognito_app = typer.Typer(help="Cognito authentication management commands")
config_app = typer.Typer(help="Manage persisted daycog CLI configuration")
console = Console()

# Global state for --config option (set by callback)
_config_name: Optional[str] = None


def _app_callback(
    config: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Named config to use (reads DAYCOG_<NAME>_* env vars)",
        envvar="DAYCOG_CONFIG",
    ),
) -> None:
    """Process global options before commands."""
    global _config_name
    _config_name = config


cognito_app.callback()(_app_callback)
cognito_app.add_typer(config_app, name="config")


def _default_config_path() -> Path:
    """Return the default daycog config file path."""
    return Path.home() / ".config" / "daycog" / "default.env"


def _pool_config_path(pool_name: str) -> Path:
    """Return the per-pool config file path."""
    return Path.home() / ".config" / "daycog" / f"{pool_name}.env"


def _resolve_profile_region(profile: Optional[str], region: Optional[str]) -> tuple[str, str]:
    """Resolve profile/region from flags or environment, erroring if missing."""
    resolved_profile = profile or os.environ.get("AWS_PROFILE")
    resolved_region = region or os.environ.get("AWS_REGION")

    if not resolved_profile:
        console.print("[red]✗[/red]  AWS profile not set")
        console.print("   Pass [cyan]--profile[/cyan] or set [cyan]export AWS_PROFILE=your-profile[/cyan]")
        raise typer.Exit(1)

    if not resolved_region:
        console.print("[red]✗[/red]  AWS region not set")
        console.print("   Pass [cyan]--region[/cyan] or set [cyan]export AWS_REGION=us-west-2[/cyan]")
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
            console.print(f"[red]✗[/red]  Invalid tag format: {item}. Use key=value")
            raise typer.Exit(1)
        key, tag_value = item.split("=", 1)
        key = key.strip()
        tag_value = tag_value.strip()
        if not key:
            console.print(f"[red]✗[/red]  Invalid empty tag key in: {item}")
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
        console.print("[red]✗[/red]  Invalid --mfa value. Use one of: off, optional, required")
        raise typer.Exit(1)
    return mapping[normalized]


def _get_pool_details_by_name(pool_name: str, profile: str, region: str) -> Dict[str, str]:
    """Look up pool and a client ID by pool name."""
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    cognito = session.client("cognito-idp")

    pool_id = _find_pool_id_by_name(cognito, pool_name)
    clients_resp = cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)
    clients = clients_resp.get("UserPoolClients", [])
    client_id = clients[0]["ClientId"] if clients else ""

    if len(clients) > 1:
        console.print(
            f"[yellow]⚠[/yellow]  Pool has {len(clients)} app clients; using first: {client_id}"
        )

    return {"pool_id": pool_id, "client_id": client_id}


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
        console.print(f"[red]✗[/red]  Pool not found: {pool_name}")
        raise typer.Exit(1)

    return matched_pool["Id"]


def _read_env_file(path: Path) -> Dict[str, str]:
    """Read simple KEY=VALUE lines from a config file."""
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            values[key] = value
    return values


def _write_env_file(path: Path, values: Dict[str, str]) -> None:
    """Write env config values to disk in stable key order."""
    lines = _render_env_lines(values)
    contents = "\n".join(lines) + ("\n" if lines else "")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _render_env_lines(values: Dict[str, str]) -> List[str]:
    """Render key/value env settings as stable KEY=VALUE lines."""
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


def _collect_known_cli_values() -> Dict[str, str]:
    """Collect values currently known to the CLI from config/env context."""
    values: Dict[str, str] = {}

    if _config_name:
        try:
            cfg = CognitoConfig.from_env(_config_name)
            values["COGNITO_REGION"] = cfg.region
            values["COGNITO_USER_POOL_ID"] = cfg.user_pool_id
            values["COGNITO_APP_CLIENT_ID"] = cfg.app_client_id
            if cfg.aws_profile:
                values["AWS_PROFILE"] = cfg.aws_profile
            if cfg.google_client_id:
                values["GOOGLE_CLIENT_ID"] = cfg.google_client_id
            if cfg.google_client_secret:
                values["GOOGLE_CLIENT_SECRET"] = cfg.google_client_secret
            if cfg.cognito_domain:
                values["COGNITO_DOMAIN"] = cfg.cognito_domain
        except ValueError:
            pass

    env = os.environ
    if env.get("AWS_PROFILE"):
        values["AWS_PROFILE"] = env["AWS_PROFILE"]
    if env.get("AWS_REGION"):
        values["AWS_REGION"] = env["AWS_REGION"]
    if env.get("COGNITO_REGION"):
        values["COGNITO_REGION"] = env["COGNITO_REGION"]
    if env.get("COGNITO_USER_POOL_ID"):
        values["COGNITO_USER_POOL_ID"] = env["COGNITO_USER_POOL_ID"]
    if env.get("COGNITO_CLIENT_NAME"):
        values["COGNITO_CLIENT_NAME"] = env["COGNITO_CLIENT_NAME"]
    if env.get("COGNITO_CALLBACK_URL"):
        values["COGNITO_CALLBACK_URL"] = env["COGNITO_CALLBACK_URL"]
    if env.get("COGNITO_LOGOUT_URL"):
        values["COGNITO_LOGOUT_URL"] = env["COGNITO_LOGOUT_URL"]

    app_client_id = env.get("COGNITO_APP_CLIENT_ID") or env.get("COGNITO_CLIENT_ID")
    if app_client_id:
        values["COGNITO_APP_CLIENT_ID"] = app_client_id

    if env.get("GOOGLE_CLIENT_ID"):
        values["GOOGLE_CLIENT_ID"] = env["GOOGLE_CLIENT_ID"]
    if env.get("GOOGLE_CLIENT_SECRET"):
        values["GOOGLE_CLIENT_SECRET"] = env["GOOGLE_CLIENT_SECRET"]
    if env.get("COGNITO_DOMAIN"):
        values["COGNITO_DOMAIN"] = env["COGNITO_DOMAIN"]

    return values


def _check_aws_profile() -> None:
    """Check if AWS_PROFILE is set."""
    if not os.environ.get("AWS_PROFILE"):
        console.print("[red]✗[/red]  AWS_PROFILE not set")
        console.print("   Set it with: [cyan]export AWS_PROFILE=your-profile[/cyan]")
        raise typer.Exit(1)


def _get_cognito_region() -> str:
    """Get the AWS region for Cognito operations.

    Priority order:
    1. Named config (if --config provided)
    2. COGNITO_REGION environment variable
    3. AWS_REGION environment variable
    4. Fallback to 'us-west-2'

    Returns:
        AWS region string (e.g., 'us-west-2')
    """
    if _config_name:
        try:
            config = CognitoConfig.from_env(_config_name)
            return config.region
        except ValueError:
            pass  # Fall through to legacy

    # Legacy: COGNITO_REGION > AWS_REGION > us-west-2
    return os.environ.get("COGNITO_REGION") or os.environ.get("AWS_REGION") or "us-west-2"


@cognito_app.command("status")
def status() -> None:
    """Check Cognito configuration status."""
    _check_aws_profile()

    console.print("[cyan]Checking Cognito configuration...[/cyan]\n")

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        table = Table(title="Cognito Configuration")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_column("Source", style="dim")

        # Determine source based on --config or env vars
        if _config_name:
            source = f"config:{_config_name}"
            try:
                config = CognitoConfig.from_env(_config_name)
                pool_id = config.user_pool_id
                client_id = config.app_client_id
            except ValueError:
                pool_id = ""
                client_id = ""
        else:
            # Legacy env var lookup
            pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
            client_id = os.environ.get("COGNITO_APP_CLIENT_ID") or os.environ.get("COGNITO_CLIENT_ID", "")
            source = "env"

        table.add_row("Region", region, source if _config_name else "")

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

        console.print(table)

        if not pool_id or not client_id:
            console.print("\n[yellow]⚠[/yellow]  Cognito not fully configured")
            console.print("   Run: [cyan]daycog setup[/cyan]")
            console.print("   Or set env vars: COGNITO_USER_POOL_ID, COGNITO_APP_CLIENT_ID")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("setup")
def setup(
    pool_name: str = typer.Option("ursa-users", "--name", "-n", help="User pool name"),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="App client name (default: <pool-name>-client)"),
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
    require_uppercase: bool = typer.Option(True, "--require-uppercase/--no-require-uppercase", help="Require uppercase"),
    require_lowercase: bool = typer.Option(True, "--require-lowercase/--no-require-lowercase", help="Require lowercase"),
    require_numbers: bool = typer.Option(True, "--require-numbers/--no-require-numbers", help="Require numbers"),
    require_symbols: bool = typer.Option(False, "--require-symbols/--no-require-symbols", help="Require symbols"),
    mfa: str = typer.Option("off", "--mfa", help="MFA mode: off, optional, required"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags in key=value format"),
):
    """Create Cognito User Pool and App Client."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)

    # Ensure boto3 and any downstream helpers see explicit values from flags.
    os.environ["AWS_PROFILE"] = resolved_profile
    os.environ["AWS_REGION"] = resolved_region

    console.print("[cyan]Creating Cognito resources...[/cyan]")

    try:
        import boto3

        resolved_client_name = client_name or f"{pool_name}-client"
        resolved_callback_url = _resolve_callback_url(callback_url, port, callback_path)
        resolved_oauth_flows = _parse_csv(oauth_flows)
        resolved_scopes = _parse_csv(scopes)
        resolved_idps = _parse_csv(idps)
        resolved_tags = _parse_tags(tags)
        resolved_mfa = _resolve_mfa_configuration(mfa)
        resolved_logout_urls = [logout_url] if logout_url else []

        console.print(f"[dim]Profile: {resolved_profile}[/dim]")
        console.print(f"[dim]Region: {resolved_region}[/dim]")
        cognito = boto3.client("cognito-idp", region_name=resolved_region)

        # Check if pool already exists
        pools = cognito.list_user_pools(MaxResults=60)
        existing = [p for p in pools["UserPools"] if p["Name"] == pool_name]

        if existing:
            console.print(f"[yellow]⚠[/yellow]  User pool '{pool_name}' already exists")
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
            console.print(f"[green]✓[/green]  Created user pool: {pool_name}")

        # Create or reuse app client
        client_id = ""
        if autoprovision:
            existing_clients = cognito.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get(
                "UserPoolClients", []
            )
            existing_match = next((c for c in existing_clients if c.get("ClientName") == resolved_client_name), None)
            if existing_match:
                client_id = existing_match["ClientId"]
                console.print(f"[yellow]⚠[/yellow]  Reusing app client '{resolved_client_name}': {client_id}")

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
            console.print(f"[green]✓[/green]  Created app client: {client_id}")

        # Show configuration
        setup_values = {
            "AWS_PROFILE": resolved_profile,
            "AWS_REGION": resolved_region,
            "COGNITO_REGION": resolved_region,
            "COGNITO_USER_POOL_ID": pool_id,
            "COGNITO_APP_CLIENT_ID": client_id,
            "COGNITO_CALLBACK_URL": resolved_callback_url,
            "COGNITO_CLIENT_NAME": resolved_client_name,
        }
        if logout_url:
            setup_values["COGNITO_LOGOUT_URL"] = logout_url
        pool_config_path = _pool_config_path(pool_name)
        default_config_path = _default_config_path()

        pool_file_values = _read_env_file(pool_config_path)
        pool_file_values.update(setup_values)
        _write_env_file(pool_config_path, pool_file_values)

        default_file_values = _read_env_file(default_config_path)
        default_file_values.update(setup_values)
        _write_env_file(default_config_path, default_file_values)

        console.print("\n[green]✓[/green]  Cognito setup complete")
        console.print("\nSaved config files:")
        console.print(f"   [cyan]{pool_config_path}[/cyan]")
        console.print(f"   [cyan]{default_config_path}[/cyan] [dim](default)[/dim]")
        console.print("\nValues written to default config:")
        console.print(f"   [cyan]COGNITO_USER_POOL_ID={pool_id}[/cyan]")
        console.print(f"   [cyan]COGNITO_APP_CLIENT_ID={client_id}[/cyan]")
        console.print(f"   [cyan]COGNITO_CALLBACK_URL={resolved_callback_url}[/cyan]")
        if logout_url:
            console.print(f"   [cyan]COGNITO_LOGOUT_URL={logout_url}[/cyan]")
        if print_exports:
            console.print("\n[bold]Shell exports:[/bold]")
            console.print(f'export AWS_PROFILE="{resolved_profile}"')
            console.print(f'export AWS_REGION="{resolved_region}"')
            console.print(f'export COGNITO_REGION="{resolved_region}"')
            console.print(f'export COGNITO_USER_POOL_ID="{pool_id}"')
            console.print(f'export COGNITO_APP_CLIENT_ID="{client_id}"')
            console.print(f'export COGNITO_CALLBACK_URL="{resolved_callback_url}"')
            console.print(f'export COGNITO_CLIENT_NAME="{resolved_client_name}"')
            if logout_url:
                console.print(f'export COGNITO_LOGOUT_URL="{logout_url}"')

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@config_app.command("print")
def config_print(
    pool_name: Optional[str] = typer.Option(
        None, "--pool-name", "--poor-name", help="Pool name for per-pool config file"
    ),
) -> None:
    """Print config file path and file contents."""
    config_path = _pool_config_path(pool_name) if pool_name else _default_config_path()
    console.print(str(config_path))
    if config_path.exists():
        contents = config_path.read_text(encoding="utf-8")
        if contents:
            console.print(contents, end="")


@config_app.command("create")
def config_create(
    pool_name: str = typer.Option(..., "--pool-name", "--poor-name", help="Pool name to resolve and write config for"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """Create the pool config file and update default config from AWS."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    pool_details = _get_pool_details_by_name(pool_name, resolved_profile, resolved_region)

    config_values = {
        "AWS_PROFILE": resolved_profile,
        "AWS_REGION": resolved_region,
        "COGNITO_REGION": resolved_region,
        "COGNITO_USER_POOL_ID": pool_details["pool_id"],
    }
    if pool_details["client_id"]:
        config_values["COGNITO_APP_CLIENT_ID"] = pool_details["client_id"]

    config_path = _pool_config_path(pool_name)
    if config_path.exists():
        console.print(f"[red]✗[/red]  Config file already exists: {config_path}")
        raise typer.Exit(1)
    _write_env_file(config_path, config_values)

    default_path = _default_config_path()
    merged_default = _read_env_file(default_path)
    merged_default.update(config_values)
    _write_env_file(default_path, merged_default)

    console.print(str(config_path))
    console.print(config_path.read_text(encoding="utf-8"), end="")
    console.print(str(default_path))
    console.print(default_path.read_text(encoding="utf-8"), end="")


@config_app.command("update")
def config_update(
    pool_name: str = typer.Option(..., "--pool-name", "--poor-name", help="Pool name to resolve and write config for"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    """Update the pool config file and default config from AWS."""
    resolved_profile, resolved_region = _resolve_profile_region(profile, region)
    pool_details = _get_pool_details_by_name(pool_name, resolved_profile, resolved_region)

    config_values = {
        "AWS_PROFILE": resolved_profile,
        "AWS_REGION": resolved_region,
        "COGNITO_REGION": resolved_region,
        "COGNITO_USER_POOL_ID": pool_details["pool_id"],
    }
    if pool_details["client_id"]:
        config_values["COGNITO_APP_CLIENT_ID"] = pool_details["client_id"]

    pool_path = _pool_config_path(pool_name)
    merged_pool = _read_env_file(pool_path)
    merged_pool.update(config_values)
    _write_env_file(pool_path, merged_pool)

    default_path = _default_config_path()
    merged_default = _read_env_file(default_path)
    merged_default.update(config_values)
    _write_env_file(default_path, merged_default)

    console.print(str(pool_path))
    console.print(pool_path.read_text(encoding="utf-8"), end="")
    console.print(str(default_path))
    console.print(default_path.read_text(encoding="utf-8"), end="")


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
        count = 0
        for page in paginator.paginate(MaxResults=60):
            for pool in page.get("UserPools", []):
                table.add_row(pool.get("Name", ""), pool.get("Id", ""))
                count += 1

        console.print(table)
        console.print(f"\n[dim]Total: {count} pools[/dim]")
    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("delete-pool")
def delete_pool(
    pool_name: Optional[str] = typer.Option(None, "--pool-name", help="Cognito pool name to delete"),
    pool_id: Optional[str] = typer.Option(None, "--pool-id", help="Cognito pool ID to delete"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile to use"),
    region: Optional[str] = typer.Option(None, "--region", help="AWS region to use"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a Cognito user pool by name or ID."""
    if not pool_name and not pool_id:
        console.print("[red]✗[/red]  Provide one of: [cyan]--pool-name[/cyan] or [cyan]--pool-id[/cyan]")
        raise typer.Exit(1)

    resolved_profile, resolved_region = _resolve_profile_region(profile, region)

    try:
        import boto3

        session = boto3.Session(profile_name=resolved_profile, region_name=resolved_region)
        cognito = session.client("cognito-idp")

        resolved_pool_id = pool_id
        resolved_pool_name = pool_name
        if not resolved_pool_id and pool_name:
            resolved_pool_id = _find_pool_id_by_name(cognito, pool_name)

        if resolved_pool_id and not resolved_pool_name:
            pool_info = cognito.describe_user_pool(UserPoolId=resolved_pool_id)
            resolved_pool_name = pool_info["UserPool"]["Name"]

        if not force:
            console.print("[red]⚠  WARNING: This will delete the Cognito pool:[/red]")
            console.print(f"   Pool Name: {resolved_pool_name}")
            console.print(f"   Pool ID: {resolved_pool_id}")
            console.print("   [red]All users will be permanently deleted![/red]")
            confirm = typer.confirm("Are you absolutely sure?")
            if not confirm:
                console.print("[dim]Cancelled[/dim]")
                return

        cognito.delete_user_pool(UserPoolId=resolved_pool_id)
        console.print(f"[green]✓[/green]  Deleted Cognito pool: {resolved_pool_name} ({resolved_pool_id})")
    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("fix-auth-flows")
def fix_auth_flows():
    """Enable required auth flows on the app client.

    Fixes 'Auth flow not enabled for this client' error by enabling
    ALLOW_ADMIN_USER_PASSWORD_AUTH on the existing app client.
    """
    _check_aws_profile()

    # Get pool and client IDs from env or config
    pool_id = _get_pool_id()
    client_id = _get_client_id()

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        # Get current client config
        client_config = cognito.describe_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
        )["UserPoolClient"]

        console.print(f"[cyan]Updating app client {client_id}...[/cyan]")

        # Update with required auth flows
        cognito.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
            ClientName=client_config.get("ClientName", "ursa-client"),
            ExplicitAuthFlows=[
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
            ],
            # Preserve existing OAuth config if present
            AllowedOAuthFlows=client_config.get("AllowedOAuthFlows", []),
            AllowedOAuthScopes=client_config.get("AllowedOAuthScopes", []),
            AllowedOAuthFlowsUserPoolClient=client_config.get("AllowedOAuthFlowsUserPoolClient", False),
            CallbackURLs=client_config.get("CallbackURLs", []),
            SupportedIdentityProviders=client_config.get("SupportedIdentityProviders", ["COGNITO"]),
        )

        console.print("[green]✓[/green]  Enabled auth flows:")
        console.print("     - ALLOW_USER_PASSWORD_AUTH")
        console.print("     - ALLOW_ADMIN_USER_PASSWORD_AUTH")
        console.print("     - ALLOW_REFRESH_TOKEN_AUTH")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("set-password")
def set_password(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email address"),
    password: str = typer.Option(..., "--password", "-p", prompt="New password", hide_input=True, help="New password"),
):
    """Set password for a Cognito user."""
    _check_aws_profile()

    # Get pool ID from env or config
    pool_id = _get_pool_id()

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)
        cognito.admin_set_user_password(
            UserPoolId=pool_id,
            Username=email,
            Password=password,
            Permanent=True,
        )

        console.print(f"[green]✓[/green]  Password set for: {email}")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


def _get_pool_id() -> str:
    """Get user pool ID from named config or env var.

    Priority order:
    1. Named config (if --config provided)
    2. COGNITO_USER_POOL_ID environment variable

    Raises:
        typer.Exit(1) if not configured anywhere.
    """
    # Check named config first
    if _config_name:
        try:
            config = CognitoConfig.from_env(_config_name)
            return config.user_pool_id
        except ValueError:
            pass  # Fall through to legacy

    # Legacy: environment variable
    pool_id = os.environ.get("COGNITO_USER_POOL_ID")
    if pool_id:
        return pool_id

    # Not configured anywhere
    console.print("[red]✗[/red]  Cognito User Pool ID not configured")
    console.print("   Set via environment: [cyan]export COGNITO_USER_POOL_ID=your-pool-id[/cyan]")
    console.print("   Or use --config NAME with DAYCOG_<NAME>_USER_POOL_ID")
    raise typer.Exit(1)


def _get_client_id() -> str:
    """Get app client ID from named config or env var.

    Priority order:
    1. Named config (if --config provided)
    2. COGNITO_APP_CLIENT_ID environment variable
    3. COGNITO_CLIENT_ID environment variable (fallback)

    Raises:
        typer.Exit(1) if not configured anywhere.
    """
    # Check named config first
    if _config_name:
        try:
            config = CognitoConfig.from_env(_config_name)
            return config.app_client_id
        except ValueError:
            pass  # Fall through to legacy

    # Legacy: environment variables
    client_id = os.environ.get("COGNITO_APP_CLIENT_ID") or os.environ.get("COGNITO_CLIENT_ID")
    if client_id:
        return client_id

    # Not configured anywhere
    console.print("[red]✗[/red]  Cognito App Client ID not configured")
    console.print("   Set via environment: [cyan]export COGNITO_APP_CLIENT_ID=your-client-id[/cyan]")
    console.print("   Or use --config NAME with DAYCOG_<NAME>_APP_CLIENT_ID")
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
    _check_aws_profile()
    pool_id = _get_pool_id()

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

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
        console.print(f"[green]✓[/green]  Created user: {email}")

        # If --no-verify, set permanent password immediately
        if no_verify and password:
            cognito.admin_set_user_password(
                UserPoolId=pool_id,
                Username=email,
                Password=password,
                Permanent=True,
            )
            console.print("[green]✓[/green]  Password set (permanent)")
        elif is_temp:
            console.print(f"\n[yellow]Temporary password:[/yellow] {temp_password}")
            console.print("[dim]User must change password on first login[/dim]")
        else:
            console.print("[green]✓[/green]  Password set (temporary - must change on first login)")

    except cognito.exceptions.UsernameExistsException:
        console.print(f"[red]✗[/red]  User already exists: {email}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("list-users")
def list_users(
    limit: int = typer.Option(50, "--limit", "-l", help="Max users to list"),
):
    """List all Cognito users."""
    _check_aws_profile()
    pool_id = _get_pool_id()

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

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

        console.print(table)
        console.print(f"\n[dim]Total: {user_count} users[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("export")
def export_users(
    output: str = typer.Option("cognito_users.log", "--output", "-o", help="Output file path"),
):
    """Export all Cognito users to a log file."""
    _check_aws_profile()
    pool_id = _get_pool_id()

    try:
        import json
        from datetime import datetime

        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        console.print(f"[cyan]Exporting users from pool {pool_id}...[/cyan]")

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
            "exported_at": datetime.utcnow().isoformat(),
            "pool_id": pool_id,
            "region": region,
            "user_count": len(users),
            "users": users,
        }

        with open(output, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        console.print(f"[green]✓[/green]  Exported {len(users)} users to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("delete-user")
def delete_user(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a single Cognito user."""
    _check_aws_profile()
    pool_id = _get_pool_id()

    if not force:
        console.print(f"[yellow]⚠[/yellow]  This will delete user: {email}")
        confirm = typer.confirm("Are you sure?")
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            return

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        cognito.admin_delete_user(UserPoolId=pool_id, Username=email)
        console.print(f"[green]✓[/green]  Deleted user: {email}")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("delete-all-users")
def delete_all_users(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete ALL users from the Cognito pool. Use with caution!"""
    _check_aws_profile()
    pool_id = _get_pool_id()

    if not force:
        console.print(f"[red]⚠  WARNING: This will delete ALL users from pool {pool_id}![/red]")
        confirm = typer.confirm("Are you absolutely sure?")
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            return

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        console.print(f"[cyan]Deleting all users from pool {pool_id}...[/cyan]")

        deleted_count = 0
        paginator = cognito.get_paginator("list_users")

        for page in paginator.paginate(UserPoolId=pool_id):
            for user in page.get("Users", []):
                username = user.get("Username")
                try:
                    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
                    console.print(f"[dim]  Deleted: {username}[/dim]")
                    deleted_count += 1
                except Exception as e:
                    console.print(f"[yellow]  Failed to delete {username}: {e}[/yellow]")

        console.print(f"\n[green]✓[/green]  Deleted {deleted_count} users")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("teardown")
def teardown(
    pool_name: str = typer.Option(None, "--name", "-n", help="Pool name to delete (if not using env var)"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete the Cognito User Pool and all its users."""
    _check_aws_profile()

    try:
        import boto3

        region = _get_cognito_region()
        cognito = boto3.client("cognito-idp", region_name=region)

        # Get pool ID from named config, env, or find by name
        pool_id: Optional[str] = None

        if _config_name:
            try:
                config = CognitoConfig.from_env(_config_name)
                pool_id = config.user_pool_id
            except ValueError:
                pass

        if not pool_id:
            pool_id = os.environ.get("COGNITO_USER_POOL_ID")

        if not pool_id and pool_name:
            pools = cognito.list_user_pools(MaxResults=60)
            for p in pools["UserPools"]:
                if p["Name"] == pool_name:
                    pool_id = p["Id"]
                    break

        if not pool_id:
            console.print("[red]✗[/red]  No pool ID found")
            console.print("   Set via environment: [cyan]export COGNITO_USER_POOL_ID=...[/cyan]")
            console.print("   Or use --config NAME with DAYCOG_<NAME>_USER_POOL_ID")
            console.print("   Or use --name to search by pool name")
            raise typer.Exit(1)

        # Get pool info for confirmation
        pool_info = cognito.describe_user_pool(UserPoolId=pool_id)
        pool_name_actual = pool_info["UserPool"]["Name"]

        if not force:
            console.print("[red]⚠  WARNING: This will delete the Cognito pool:[/red]")
            console.print(f"   Pool ID: {pool_id}")
            console.print(f"   Pool Name: {pool_name_actual}")
            console.print("   [red]All users will be permanently deleted![/red]")
            confirm = typer.confirm("Are you absolutely sure?")
            if not confirm:
                console.print("[dim]Cancelled[/dim]")
                return

        console.print(f"[cyan]Deleting pool {pool_id}...[/cyan]")
        cognito.delete_user_pool(UserPoolId=pool_id)
        console.print(f"[green]✓[/green]  Deleted Cognito pool: {pool_name_actual} ({pool_id})")
        console.print("\n[yellow]Remember to unset environment variables:[/yellow]")
        console.print("   unset COGNITO_USER_POOL_ID")
        console.print("   unset COGNITO_APP_CLIENT_ID")

    except Exception as e:
        console.print(f"[red]✗[/red]  Error: {e}")
        raise typer.Exit(1)


@cognito_app.command("setup-google")
def setup_google(
    google_client_id: str = typer.Option(..., "--client-id", help="Google OAuth2 client ID"),
    google_client_secret: str = typer.Option(..., "--client-secret", help="Google OAuth2 client secret"),
    redirect_port: int = typer.Option(8000, "--port", "-p", help="Local server port for redirect URI"),
) -> None:
    """Display environment variables for Google OAuth integration.

    Generates the env var export commands needed to enable Google OAuth
    with daylily-cognito. Does not store credentials — print only.
    """
    redirect_uri = f"http://localhost:{redirect_port}/auth/google/callback"

    console.print("\n[bold cyan]Google OAuth Configuration[/bold cyan]\n")
    console.print("Set these environment variables:\n")

    if _config_name:
        name_upper = _config_name.upper()
        console.print(f'  export DAYCOG_{name_upper}_GOOGLE_CLIENT_ID="{google_client_id}"')
        console.print(f'  export DAYCOG_{name_upper}_GOOGLE_CLIENT_SECRET="{google_client_secret}"')
    else:
        console.print(f'  export GOOGLE_CLIENT_ID="{google_client_id}"')
        console.print(f'  export GOOGLE_CLIENT_SECRET="{google_client_secret}"')

    console.print("\n[dim]Redirect URI (register in Google Cloud Console):[/dim]")
    console.print(f"  {redirect_uri}\n")

    # Show a quick integration snippet
    console.print("[bold]Quick integration example:[/bold]\n")
    console.print("[dim]from daylily_cognito import ([/dim]")
    console.print("[dim]    build_google_authorization_url,[/dim]")
    console.print("[dim]    exchange_google_code_for_tokens,[/dim]")
    console.print("[dim]    fetch_google_userinfo,[/dim]")
    console.print("[dim]    auto_create_cognito_user_from_google,[/dim]")
    console.print("[dim])[/dim]\n")

    console.print("[green]✓[/green] Configuration displayed. Set the env vars above to enable Google OAuth.\n")


def main() -> None:
    """Entry point for the daycog CLI."""
    cognito_app()
