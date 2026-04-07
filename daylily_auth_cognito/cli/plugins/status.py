"""Status command registration."""

from __future__ import annotations

from typing import Any

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.runtime import get_context
from cli_core_yo.spec import CliSpec
from rich.table import Table

from . import config as plugin_config


def status() -> None:
    """Check Cognito configuration status."""
    try:
        admin, runtime = plugin_config._get_admin_client(require_profile=True)
        pool_id = runtime.values.get("COGNITO_USER_POOL_ID", "")
        client_id = runtime.values.get("COGNITO_APP_CLIENT_ID", "")

        if get_context().json_mode:
            payload: dict[str, Any] = {
                "config_path": str(runtime.path),
                "region": runtime.aws_region,
                "pool_id": pool_id or None,
                "client_id": client_id or None,
            }
            if pool_id:
                try:
                    pool = admin.cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
                    payload["pool_name"] = pool.get("Name")
                    payload["status"] = "active"
                except Exception as exc:  # pragma: no cover - exercised through human path tests
                    payload["status"] = f"error: {exc}"
            ccyo_out.emit_json(payload)
            return

        ccyo_out.info("[cyan]Checking Cognito configuration...[/cyan]\n")
        table = Table(title="Cognito Configuration")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_column("Source", style="dim")

        source = str(runtime.path)
        table.add_row("Region", runtime.aws_region, source)

        if pool_id:
            try:
                pool = admin.cognito.describe_user_pool(UserPoolId=pool_id)
                table.add_row("User Pool ID", pool_id, source)
                table.add_row("User Pool Name", pool["UserPool"]["Name"], "")
                table.add_row("Status", "[green]Active[/green]", "")
            except Exception as exc:
                table.add_row("User Pool ID", pool_id, source)
                table.add_row("Status", f"[red]Error: {exc}[/red]", "")
        else:
            table.add_row("User Pool ID", "[dim]Not configured[/dim]", "")

        if client_id:
            table.add_row("App Client ID", client_id, source)
        else:
            table.add_row("App Client ID", "[dim]Not configured[/dim]", "")

        plugin_config._print_rich(table)
        if not pool_id or not client_id:
            ccyo_out.info("\n[yellow]⚠[/yellow]  Cognito not fully configured")
            ccyo_out.info(
                "   Populate the active config file via [cyan]daycog setup[/cyan] or [cyan]daycog auth-config create[/cyan]"
            )
    except Exception as exc:
        if isinstance(exc, typer.Exit):
            raise
        ccyo_out.info(f"[red]✗[/red]  Error: {exc}")
        raise typer.Exit(1)


def register(registry: CommandRegistry, spec: CliSpec) -> None:
    del spec
    registry.add_command(
        None,
        "status",
        status,
        help_text="Check Cognito configuration status.",
        policy=plugin_config.READ_ONLY_POLICY,
    )
