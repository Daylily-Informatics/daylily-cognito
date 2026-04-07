"""Seam tests for Cognito user-pool admin helpers."""

from __future__ import annotations

from unittest import mock

import pytest

from daylily_auth_cognito.admin import pools
from daylily_auth_cognito.admin.client import CognitoAdminClient


def _admin(client: mock.Mock | None = None, **overrides) -> CognitoAdminClient:
    defaults = {
        "region": "us-west-2",
        "user_pool_id": "pool-123",
        "app_client_id": "client-123",
        "client": client or mock.Mock(),
    }
    defaults.update(overrides)
    return CognitoAdminClient(**defaults)


def test_list_user_pools_flattens_pages() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [
        {"UserPools": [{"Id": "pool-a", "Name": "alpha"}]},
        {"UserPools": [{"Id": "pool-b", "Name": "beta"}]},
    ]
    cognito.get_paginator.return_value = paginator
    admin = _admin(cognito)

    result = pools.list_user_pools(admin, max_results=10)

    assert result == [{"Id": "pool-a", "Name": "alpha"}, {"Id": "pool-b", "Name": "beta"}]
    paginator.paginate.assert_called_once_with(MaxResults=10)


def test_find_user_pool_id_by_name_and_missing_pool() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"UserPools": [{"Id": "pool-a", "Name": "alpha"}]}]
    cognito.get_paginator.return_value = paginator
    admin = _admin(cognito)

    assert pools.find_user_pool_id_by_name(admin, "alpha") == "pool-a"
    with pytest.raises(ValueError, match="Pool not found: missing"):
        pools.find_user_pool_id_by_name(admin, "missing")


def test_resolve_pool_requires_identifier_and_validates_name() -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool.return_value = {"UserPool": {"Name": "alpha"}}
    admin = _admin(cognito)

    with pytest.raises(ValueError, match="pool_name or pool_id is required"):
        pools.resolve_pool(admin)
    with pytest.raises(ValueError, match="does not match resolved pool"):
        pools.resolve_pool(admin, pool_name="beta", pool_id="pool-a")

    resolved = pools.resolve_pool(admin, pool_id="pool-a")

    assert resolved == {"pool_id": "pool-a", "pool_name": "alpha", "pool_info": {"Name": "alpha"}}


def test_ensure_user_pool_reuses_existing_pool_and_updates_admin_state() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"UserPools": [{"Id": "pool-a", "Name": "alpha"}]}]
    cognito.get_paginator.return_value = paginator
    cognito.describe_user_pool.return_value = {"UserPool": {"Name": "alpha"}}
    admin = _admin(cognito)

    resolved = pools.ensure_user_pool(admin, pool_name="alpha")

    assert resolved["pool_id"] == "pool-a"
    assert admin.user_pool_id == "pool-a"
    cognito.create_user_pool.assert_not_called()


def test_ensure_user_pool_creates_pool_with_requested_policy() -> None:
    cognito = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [{"UserPools": []}]
    cognito.get_paginator.return_value = paginator
    cognito.create_user_pool.return_value = {"UserPool": {"Id": "pool-new"}}
    cognito.describe_user_pool.return_value = {"UserPool": {"Name": "alpha"}}
    admin = _admin(cognito)

    resolved = pools.ensure_user_pool(
        admin,
        pool_name="alpha",
        password_min_length=12,
        require_uppercase=False,
        require_lowercase=True,
        require_numbers=False,
        require_symbols=True,
        mfa_configuration="OPTIONAL",
        tags={"team": "daylily"},
    )

    assert resolved["pool_id"] == "pool-new"
    call_kwargs = cognito.create_user_pool.call_args.kwargs
    assert call_kwargs["PoolName"] == "alpha"
    assert call_kwargs["MfaConfiguration"] == "OPTIONAL"
    assert call_kwargs["Policies"]["PasswordPolicy"]["MinimumLength"] == 12
    assert call_kwargs["Policies"]["PasswordPolicy"]["RequireUppercase"] is False
    assert call_kwargs["Policies"]["PasswordPolicy"]["RequireNumbers"] is False
    assert call_kwargs["UserPoolTags"] == {"team": "daylily"}
    assert admin.user_pool_id == "pool-new"


def test_ensure_user_pool_domain_reuses_existing_domain_and_creates_missing_domain() -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool.side_effect = [
        {"UserPool": {"Name": "alpha", "Domain": "existing"}},
        {"UserPool": {"Name": "alpha", "Domain": ""}},
    ]
    admin = _admin(cognito)

    assert (
        pools.ensure_user_pool_domain(admin, user_pool_id="pool-a", domain_prefix="alpha")
        == "existing.auth.us-west-2.amazoncognito.com"
    )
    assert (
        pools.ensure_user_pool_domain(admin, user_pool_id="pool-a", domain_prefix="alpha")
        == "alpha.auth.us-west-2.amazoncognito.com"
    )
    cognito.create_user_pool_domain.assert_called_once_with(UserPoolId="pool-a", Domain="alpha")


def test_delete_user_pool_waits_for_domain_removal_before_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool.side_effect = [
        {"UserPool": {"Domain": "alpha"}},
        {"UserPool": {"Domain": "alpha"}},
        {"UserPool": {"Domain": ""}},
    ]
    admin = _admin(cognito)
    sleeps: list[int] = []
    monkeypatch.setattr(pools.time, "sleep", lambda seconds: sleeps.append(seconds))

    pools.delete_user_pool(admin, user_pool_id="pool-a", delete_domain_first=True, wait_seconds=3)

    cognito.delete_user_pool_domain.assert_called_once_with(UserPoolId="pool-a", Domain="alpha")
    cognito.delete_user_pool.assert_called_once_with(UserPoolId="pool-a")
    assert sleeps == [1]


def test_delete_user_pool_uses_custom_domain_and_default_delete_path() -> None:
    cognito = mock.Mock()
    cognito.describe_user_pool.return_value = {"UserPool": {"CustomDomain": "custom.domain"}}
    admin = _admin(cognito)

    pools.delete_user_pool(admin, delete_domain_first=True)

    cognito.delete_user_pool_domain.assert_called_once_with(UserPoolId="pool-123", Domain="custom.domain")
    cognito.delete_user_pool.assert_called_once_with(UserPoolId="pool-123")
