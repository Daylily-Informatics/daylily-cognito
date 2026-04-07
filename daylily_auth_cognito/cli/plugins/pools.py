"""Pool-oriented daycog commands."""

from __future__ import annotations

import typer
from cli_core_yo import ccyo_out
from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CliSpec

from daylily_auth_cognito.admin.app_clients import create_app_client, find_app_client, update_app_client_auth_flows
from daylily_auth_cognito.admin.pools import (
    delete_user_pool,
    ensure_user_pool,
    ensure_user_pool_domain,
    list_user_pools,
    resolve_pool,
)

from .config import (
    MUTATE_POLICY,
    READ_POLICY,
    _build_config_values,
    _get_admin_client,
    _get_client_id,
    _get_pool_id,
    _parse_csv,
    _parse_tags,
    _resolve_callback_url,
    _resolve_mfa_configuration,
    _write_effective_config,
)


def list_pools(
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
) -> None:
    admin, runtime = _get_admin_client(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )
    pools = list_user_pools(admin)
    ccyo_out.info(f"Cognito User Pools ({runtime.aws_region})")
    for pool in pools:
        ccyo_out.info(f"- {pool.get('Name', '')} ({pool.get('Id', '')})")
    ccyo_out.info(f"Total: {len(pools)} pools")


def setup(
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
    autoprovision: bool = typer.Option(
        False, "--autoprovision", help="Reuse existing app client by --client-name when present"
    ),
    generate_secret: bool = typer.Option(False, "--generate-secret", help="Create app client with a secret"),
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
) -> None:
    admin, runtime = _get_admin_client(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )
    resolved_profile = runtime.require_aws_profile()
    resolved_region = runtime.aws_region
    resolved_client_name = client_name or f"{pool_name}-client"
    resolved_domain_prefix = domain_prefix or pool_name
    resolved_callback_url = _resolve_callback_url(callback_url, port, callback_path)
    resolved_oauth_flows = _parse_csv(oauth_flows)
    resolved_scopes = _parse_csv(scopes)
    resolved_idps = _parse_csv(idps)
    resolved_tags = _parse_tags(tags)
    resolved_mfa = _resolve_mfa_configuration(mfa)
    resolved_logout_urls = [logout_url] if logout_url else []

    existing_pool = next((pool for pool in list_user_pools(admin) if pool.get("Name") == pool_name), None)
    resolved_pool = ensure_user_pool(
        admin,
        pool_name=pool_name,
        password_min_length=password_min_length,
        require_uppercase=require_uppercase,
        require_lowercase=require_lowercase,
        require_numbers=require_numbers,
        require_symbols=require_symbols,
        mfa_configuration=resolved_mfa,
        tags=resolved_tags,
    )
    pool_id = resolved_pool["pool_id"]
    if existing_pool:
        ccyo_out.info(f"User pool '{pool_name}' already exists")
    else:
        ccyo_out.info(f"Created user pool: {pool_name}")

    resolved_cognito_domain = ""
    if attach_domain:
        current_domain = str(resolved_pool["pool_info"].get("Domain") or "")
        if current_domain:
            if current_domain != resolved_domain_prefix:
                ccyo_out.info(
                    f"Pool already has domain '{current_domain}' (requested '{resolved_domain_prefix}'). Keeping existing domain."
                )
            resolved_cognito_domain = f"{current_domain}.auth.{resolved_region}.amazoncognito.com"
        else:
            resolved_cognito_domain = ensure_user_pool_domain(
                admin, user_pool_id=pool_id, domain_prefix=resolved_domain_prefix
            )
            ccyo_out.info(f"Attached hosted UI domain: {resolved_domain_prefix}")

    existing_client = None
    try:
        existing_client = find_app_client(admin, user_pool_id=pool_id, client_name=resolved_client_name)
    except ValueError:
        existing_client = None

    if existing_client and autoprovision:
        client_details = {"ClientId": existing_client["client_id"], "ClientName": existing_client["client_name"]}
        admin.app_client_id = existing_client["client_id"]
        ccyo_out.info(f"Reusing app client '{resolved_client_name}': {existing_client['client_id']}")
    else:
        client_details = create_app_client(
            admin,
            client_name=resolved_client_name,
            user_pool_id=pool_id,
            generate_secret=generate_secret,
            explicit_auth_flows=None,
            allowed_oauth_flows=resolved_oauth_flows,
            allowed_oauth_scopes=resolved_scopes,
            allowed_oauth_flows_user_pool_client=True,
            callback_urls=[resolved_callback_url],
            logout_urls=resolved_logout_urls,
            supported_identity_providers=resolved_idps,
            reuse_if_exists=autoprovision,
        )
        if not existing_client:
            ccyo_out.info(f"Created app client: {client_details['ClientId']}")

    setup_values = _build_config_values(
        resolved_profile,
        resolved_region,
        {
            "pool_id": pool_id,
            "client_id": str(client_details["ClientId"]),
            "client_name": resolved_client_name,
            "callback_url": resolved_callback_url,
            "logout_url": logout_url or "",
            "cognito_domain": resolved_cognito_domain,
        },
        existing=runtime.values,
    )
    config_path = _write_effective_config(setup_values)
    ccyo_out.info(f"Wrote config file: {config_path}")
    ccyo_out.info(f"COGNITO_USER_POOL_ID={pool_id}")
    ccyo_out.info(f"COGNITO_APP_CLIENT_ID={client_details['ClientId']}")
    ccyo_out.info(f"COGNITO_CLIENT_NAME={resolved_client_name}")
    if resolved_cognito_domain:
        ccyo_out.info(f"COGNITO_DOMAIN={resolved_cognito_domain}")
    if print_exports:
        ccyo_out.info(f'export AWS_PROFILE="{resolved_profile}"')
        ccyo_out.info(f'export AWS_REGION="{resolved_region}"')


def delete_pool(
    pool_name: str | None = typer.Option(None, "--pool-name", help="Cognito pool name to delete"),
    pool_id: str | None = typer.Option(None, "--pool-id", help="Cognito pool ID to delete"),
    profile: str | None = typer.Option(None, "--profile", help="AWS profile to use"),
    region: str | None = typer.Option(None, "--region", help="AWS region to use"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    delete_domain_first: bool = typer.Option(
        False, "--delete-domain-first", help="Delete configured Cognito domain before deleting pool"
    ),
) -> None:
    if not pool_name and not pool_id:
        ccyo_out.info("[red]x[/red] Provide one of: --pool-name or --pool-id")
        raise typer.Exit(1)
    admin, _runtime = _get_admin_client(
        profile=profile,
        region=region,
        require_config=False,
        require_required_keys=False,
        require_profile=True,
    )
    try:
        resolved_pool = resolve_pool(admin, pool_name=pool_name, pool_id=pool_id)
    except ValueError as exc:
        ccyo_out.info(f"[red]x[/red] {exc}")
        raise typer.Exit(1) from exc

    if not force and not typer.confirm(
        f"Delete Cognito pool {resolved_pool['pool_name']} ({resolved_pool['pool_id']})?"
    ):
        ccyo_out.info("Cancelled")
        return

    delete_user_pool(
        admin,
        user_pool_id=resolved_pool["pool_id"],
        delete_domain_first=delete_domain_first,
    )
    ccyo_out.info(f"Deleted Cognito pool: {resolved_pool['pool_name']} ({resolved_pool['pool_id']})")


def teardown(
    pool_name: str | None = typer.Option(None, "--name", "-n", help="Pool name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    pool_id = None
    try:
        pool_id = _get_pool_id()
    except SystemExit:
        pool_id = None
    delete_pool(pool_name=pool_name, pool_id=pool_id, force=force)


def fix_auth_flows() -> None:
    admin, _runtime = _get_admin_client(require_profile=True)
    admin.user_pool_id = _get_pool_id()
    admin.app_client_id = _get_client_id()
    update_kwargs = update_app_client_auth_flows(admin)
    ccyo_out.info(f"Enabled auth flows on app client {update_kwargs['ClientId']}")


def register(registry: CommandRegistry, spec: CliSpec | None = None) -> None:
    del spec
    registry.add_command(
        None, "setup", setup, help_text="Create Cognito User Pool and App Client.", policy=MUTATE_POLICY
    )
    registry.add_command(None, "list-pools", list_pools, help_text="List Cognito user pools.", policy=READ_POLICY)
    registry.add_command(
        None, "delete-pool", delete_pool, help_text="Delete a Cognito user pool.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None, "teardown", teardown, help_text="Delete the configured Cognito user pool.", policy=MUTATE_POLICY
    )
    registry.add_command(
        None,
        "fix-auth-flows",
        fix_auth_flows,
        help_text="Enable required auth flows on the app client.",
        policy=MUTATE_POLICY,
    )
