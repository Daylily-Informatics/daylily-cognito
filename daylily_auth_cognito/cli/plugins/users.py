"""User-management daycog commands."""

from __future__ import annotations

import json

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CliSpec

from daylily_auth_cognito.admin.passwords import set_user_password
from daylily_auth_cognito.admin.users import (
    add_user_to_group,
    create_user,
    delete_all_users,
    delete_user,
    ensure_group,
    export_users,
    generate_temporary_password,
    list_users,
    set_user_attributes,
)

from .config import MUTATE_POLICY, READ_POLICY, _get_admin_client, _parse_attributes


def set_password(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email address"),
    password: str = typer.Option(..., "--password", "-p", prompt="New password", hide_input=True, help="New password"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    set_user_password(admin, email=email, password=password, permanent=True)
    ccyo_out.info(f"Password set for: {email}")


def ensure_group_cmd(
    group_name: str = typer.Argument(..., help="Group name"),
    description: str = typer.Option("", "--description", help="Optional group description"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    created = ensure_group(admin, group_name=group_name, description=description)
    ccyo_out.info(("Created" if created else "Group already exists") + f": {group_name}")


def add_user_to_group_cmd(
    email: str = typer.Option(..., "--email", help="User email address"),
    group_name: str = typer.Option(..., "--group", help="Target Cognito group"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    add_user_to_group(admin, email=email, group_name=group_name)
    ccyo_out.info(f"Added {email} to group: {group_name}")


def set_user_attributes_cmd(
    email: str = typer.Option(..., "--email", help="User email address"),
    attribute: list[str] = typer.Option(
        [], "--attribute", "-a", help="Attribute assignment in Name=Value form. Repeat for multiple attributes."
    ),
) -> None:
    attributes = _parse_attributes(attribute)
    if not attributes:
        ccyo_out.info("[red]x[/red] Provide at least one --attribute Name=Value pair")
        raise typer.Exit(1)
    admin, _runtime = _get_admin_client(require_profile=True)
    set_user_attributes(admin, email=email, attributes=attributes)
    ccyo_out.info(f"Updated attributes for: {email}")


def add_user(
    email: str = typer.Argument(..., help="User email address"),
    password: str | None = typer.Option(None, "--password", "-p", help="Password (generated if not provided)"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip email verification (auto-confirm)"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    temp_password = password or generate_temporary_password()
    is_temp = password is None
    create_user(
        admin,
        email=email,
        temporary_password=temp_password,
        email_verified=no_verify,
        suppress_message=True,
    )
    if no_verify and password:
        set_user_password(admin, email=email, password=password, permanent=True)
        ccyo_out.info(f"Created user: {email}")
        ccyo_out.info("Password set (permanent)")
        return
    ccyo_out.info(f"Created user: {email}")
    if is_temp:
        ccyo_out.info(f"Temporary password: {temp_password}")
        ccyo_out.info("User must change password on first login")
    else:
        ccyo_out.info("Password set (temporary - must change on first login)")


def list_users_cmd(
    limit: int = typer.Option(50, "--limit", "-l", help="Max users to list"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    users = list_users(admin, limit=limit)
    for user in users:
        attrs = {attr["Name"]: attr["Value"] for attr in user.get("Attributes", [])}
        ccyo_out.info(
            f"- {attrs.get('email', user.get('Username', ''))} | customer_id={attrs.get('custom:customer_id', '')} | status={user.get('UserStatus', '')}"
        )
    ccyo_out.info(f"Total: {len(users)} users")


def export_users_cmd(
    output: str = typer.Option("cognito_users.log", "--output", "-o", help="Output file path"),
) -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    payload = export_users(admin)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    ccyo_out.info(f"Exported {payload['user_count']} users to: {output}")


def delete_user_cmd(
    email: str = typer.Option(..., "--email", "-e", prompt="User email", help="User email to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    if not force and not typer.confirm(f"Delete user {email}?"):
        ccyo_out.info("Cancelled")
        return
    admin, _runtime = _get_admin_client(require_profile=True)
    if delete_user(admin, email=email):
        ccyo_out.info(f"Deleted user: {email}")
        return
    ccyo_out.info(f"Failed to delete user: {email}")
    raise typer.Exit(1)


def delete_all_users_cmd(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    if not force and not typer.confirm("Delete all users from the configured pool?"):
        ccyo_out.info("Cancelled")
        return
    admin, _runtime = _get_admin_client(require_profile=True)
    deleted = delete_all_users(admin)
    ccyo_out.info(f"Deleted {deleted} users")


def register(registry: CommandRegistry, spec: CliSpec | None = None) -> None:
    del spec
    registry.add_command(
        None, "set-password", set_password, help_text="Set password for a Cognito user.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None, "ensure-group", ensure_group_cmd, help_text="Ensure a Cognito group exists.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None,
        "add-user-to-group",
        add_user_to_group_cmd,
        help_text="Add a user to a Cognito group.",
        policy=MUTATE_POLICY,
    )
    registry.add_command(
        None,
        "set-user-attributes",
        set_user_attributes_cmd,
        help_text="Update Cognito user attributes.",
        policy=MUTATE_POLICY,
    )
    registry.add_command(
        None, "add-user", add_user, help_text="Add a new user to the Cognito pool.", policy=MUTATE_POLICY
    )
    registry.add_command(None, "list-users", list_users_cmd, help_text="List all Cognito users.", policy=READ_POLICY)
    registry.add_command(
        None, "export", export_users_cmd, help_text="Export all Cognito users to a log file.", policy=READ_POLICY
    )
    registry.add_command(
        None, "delete-user", delete_user_cmd, help_text="Delete a single Cognito user.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None,
        "delete-all-users",
        delete_all_users_cmd,
        help_text="Delete all Cognito users from the configured pool.",
        policy=MUTATE_POLICY,
    )
