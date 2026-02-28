"""Tests for CognitoAuth (daylily_cognito.auth)."""

from unittest import mock

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials


def _make_client_error(code: str, message: str = "test error") -> ClientError:
    """Build a botocore ClientError for test assertions."""
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


def _build_auth(**overrides) -> "CognitoAuth":  # noqa: F821
    """Build a CognitoAuth with mocked boto3 session.

    Returns the (auth_instance, mock_cognito_client) tuple.
    """
    from daylily_cognito.auth import CognitoAuth

    defaults = {
        "region": "us-west-2",
        "user_pool_id": "us-west-2_TestPool",
        "app_client_id": "test-client-id",
    }
    defaults.update(overrides)

    with mock.patch("daylily_cognito.auth.boto3.Session") as mock_session_cls:
        mock_client = mock.MagicMock()
        mock_session_cls.return_value.client.return_value = mock_client
        auth = CognitoAuth(**defaults)
    return auth, mock_client


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestInit:
    @mock.patch("daylily_cognito.auth.boto3.Session")
    def test_basic_init(self, mock_session_cls: mock.MagicMock) -> None:
        from daylily_cognito.auth import CognitoAuth

        mock_session_cls.return_value.client.return_value = mock.MagicMock()
        auth = CognitoAuth(
            region="us-west-2",
            user_pool_id="us-west-2_Pool1",
            app_client_id="cid",
        )
        assert auth.region == "us-west-2"
        assert auth.user_pool_id == "us-west-2_Pool1"
        assert auth.app_client_id == "cid"
        assert auth.app_client_secret is None
        assert auth.profile is None
        assert auth.jwks_url != ""

    @mock.patch("daylily_cognito.auth.boto3.Session")
    def test_init_with_profile(self, mock_session_cls: mock.MagicMock) -> None:
        from daylily_cognito.auth import CognitoAuth

        mock_session_cls.return_value.client.return_value = mock.MagicMock()
        CognitoAuth(region="us-east-1", profile="my-prof")
        mock_session_cls.assert_called_once_with(region_name="us-east-1", profile_name="my-prof")

    @mock.patch("daylily_cognito.auth.boto3.Session")
    def test_init_no_pool_id_gives_empty_jwks(self, mock_session_cls: mock.MagicMock) -> None:
        from daylily_cognito.auth import CognitoAuth

        mock_session_cls.return_value.client.return_value = mock.MagicMock()
        auth = CognitoAuth(region="us-west-2")
        assert auth.jwks_url == ""

    @mock.patch("daylily_cognito.auth.boto3.Session")
    def test_init_with_secret(self, mock_session_cls: mock.MagicMock) -> None:
        from daylily_cognito.auth import CognitoAuth

        mock_session_cls.return_value.client.return_value = mock.MagicMock()
        auth = CognitoAuth(
            region="us-west-2",
            user_pool_id="us-west-2_P",
            app_client_id="cid",
            app_client_secret="secret123",
        )
        assert auth.app_client_secret == "secret123"


# ---------------------------------------------------------------------------
# create_with_new_pool (classmethod)
# ---------------------------------------------------------------------------


class TestCreateWithNewPool:
    @mock.patch("daylily_cognito.auth.boto3.Session")
    def test_creates_pool_and_client(self, mock_session_cls: mock.MagicMock) -> None:
        from daylily_cognito.auth import CognitoAuth

        mock_client = mock.MagicMock()
        mock_session_cls.return_value.client.return_value = mock_client

        # list_user_pools returns empty -> will create
        mock_client.list_user_pools.return_value = {"UserPools": []}
        mock_client.create_user_pool.return_value = {"UserPool": {"Id": "us-west-2_New1"}}
        # list_user_pool_clients returns empty -> will create
        mock_client.list_user_pool_clients.return_value = {"UserPoolClients": []}
        mock_client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "new-cid"}}

        auth = CognitoAuth.create_with_new_pool(region="us-west-2")
        assert auth.user_pool_id == "us-west-2_New1"
        assert auth.app_client_id == "new-cid"


# ---------------------------------------------------------------------------
# create_user_pool_if_not_exists
# ---------------------------------------------------------------------------


class TestCreateUserPoolIfNotExists:
    def test_returns_existing_pool(self) -> None:
        auth, mock_client = _build_auth(user_pool_id="")
        mock_client.list_user_pools.return_value = {"UserPools": [{"Name": "my-pool", "Id": "us-west-2_Existing"}]}
        pool_id = auth.create_user_pool_if_not_exists(pool_name="my-pool")
        assert pool_id == "us-west-2_Existing"
        assert auth.user_pool_id == "us-west-2_Existing"
        mock_client.create_user_pool.assert_not_called()

    def test_creates_new_pool(self) -> None:
        auth, mock_client = _build_auth(user_pool_id="")
        mock_client.list_user_pools.return_value = {"UserPools": []}
        mock_client.create_user_pool.return_value = {"UserPool": {"Id": "us-west-2_Brand"}}
        pool_id = auth.create_user_pool_if_not_exists(pool_name="brand-new")
        assert pool_id == "us-west-2_Brand"
        mock_client.create_user_pool.assert_called_once()

    def test_propagates_client_error(self) -> None:
        auth, mock_client = _build_auth(user_pool_id="")
        mock_client.list_user_pools.side_effect = _make_client_error("InternalError")
        with pytest.raises(ClientError):
            auth.create_user_pool_if_not_exists()


# ---------------------------------------------------------------------------
# create_app_client
# ---------------------------------------------------------------------------


class TestCreateAppClient:
    def test_raises_if_no_pool_id(self) -> None:
        auth, _ = _build_auth(user_pool_id="")
        with pytest.raises(ValueError, match="user_pool_id is not set"):
            auth.create_app_client()

    def test_returns_existing_client(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.list_user_pool_clients.return_value = {
            "UserPoolClients": [{"ClientName": "daylily-workset-api", "ClientId": "existing-cid"}]
        }
        cid = auth.create_app_client()
        assert cid == "existing-cid"
        mock_client.create_user_pool_client.assert_not_called()

    def test_creates_new_client(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.list_user_pool_clients.return_value = {"UserPoolClients": []}
        mock_client.create_user_pool_client.return_value = {"UserPoolClient": {"ClientId": "brand-new-cid"}}
        cid = auth.create_app_client()
        assert cid == "brand-new-cid"
        assert auth.app_client_id == "brand-new-cid"


# ---------------------------------------------------------------------------
# update_app_client_auth_flows
# ---------------------------------------------------------------------------


class TestUpdateAppClientAuthFlows:
    def test_raises_if_missing_ids(self) -> None:
        auth, _ = _build_auth(user_pool_id="", app_client_id="")
        with pytest.raises(ValueError, match="must be set"):
            auth.update_app_client_auth_flows()

    def test_updates_successfully(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.describe_user_pool_client.return_value = {
            "UserPoolClient": {
                "ClientName": "test-client",
                "ReadAttributes": ["email"],
                "WriteAttributes": ["email"],
            }
        }
        auth.update_app_client_auth_flows()
        mock_client.update_user_pool_client.assert_called_once()
        call_kwargs = mock_client.update_user_pool_client.call_args[1]
        assert "ALLOW_ADMIN_USER_PASSWORD_AUTH" in call_kwargs["ExplicitAuthFlows"]


# ---------------------------------------------------------------------------
# create_customer_user
# ---------------------------------------------------------------------------


class TestCreateCustomerUser:
    def test_creates_user_successfully(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_create_user.return_value = {
            "User": {"Username": "u@example.com", "UserStatus": "FORCE_CHANGE_PASSWORD"}
        }
        result = auth.create_customer_user("u@example.com", "cust1")
        assert result["Username"] == "u@example.com"
        mock_client.admin_create_user.assert_called_once()

    def test_with_temp_password(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_create_user.return_value = {"User": {"Username": "u@x.com"}}
        auth.create_customer_user("u@x.com", "c1", temporary_password="TempPass1")
        call_kwargs = mock_client.admin_create_user.call_args[1]
        assert call_kwargs["TemporaryPassword"] == "TempPass1"

    def test_duplicate_user_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_create_user.side_effect = _make_client_error("UsernameExistsException")
        with pytest.raises(ValueError, match="already exists"):
            auth.create_customer_user("u@x.com", "c1")

    def test_domain_validation_called(self) -> None:
        mock_settings = mock.MagicMock()
        mock_settings.validate_email_domain.return_value = (False, "blocked domain")
        auth, _ = _build_auth()
        auth.settings = mock_settings
        with pytest.raises(HTTPException) as exc_info:
            auth.create_customer_user("u@blocked.com", "c1")
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------


_JWKS_VERIFY_PATH = "daylily_cognito.jwks.verify_token_with_jwks"


class TestVerifyToken:
    def test_valid_token_with_jwks(self) -> None:
        """verify_token uses JWKS verification by default."""
        import time

        auth, _ = _build_auth()
        claims = {
            "sub": "user-1",
            "client_id": "test-client-id",
            "exp": time.time() + 3600,
        }
        with mock.patch(_JWKS_VERIFY_PATH, return_value=claims):
            result = auth.verify_token("fake.jwt.token")
        assert result["sub"] == "user-1"

    def test_valid_token_without_signature_verification(self) -> None:
        """verify_signature=False skips JWKS and uses unverified decode."""
        import time

        auth, _ = _build_auth()
        claims = {
            "sub": "user-1",
            "client_id": "test-client-id",
            "exp": time.time() + 3600,
        }
        with mock.patch("daylily_cognito.auth.jwt") as mock_jwt:
            mock_jwt.get_unverified_header.return_value = {"alg": "RS256"}
            mock_jwt.decode.return_value = claims
            result = auth.verify_token("fake.jwt.token", verify_signature=False)
        assert result["sub"] == "user-1"

    def test_expired_token_raises(self) -> None:
        import time

        auth, _ = _build_auth()
        claims = {
            "sub": "user-1",
            "client_id": "test-client-id",
            "exp": time.time() - 100,
        }
        with mock.patch(_JWKS_VERIFY_PATH, return_value=claims):
            with pytest.raises(HTTPException) as exc_info:
                auth.verify_token("expired.jwt.token")
            assert exc_info.value.status_code == 401
            assert "expired" in exc_info.value.detail.lower()

    def test_wrong_audience_raises(self) -> None:
        import time

        auth, _ = _build_auth()
        claims = {
            "sub": "user-1",
            "client_id": "wrong-client-id",
            "exp": time.time() + 3600,
        }
        with mock.patch(_JWKS_VERIFY_PATH, return_value=claims):
            with pytest.raises(HTTPException) as exc_info:
                auth.verify_token("wrong-aud.jwt.token")
            assert exc_info.value.status_code == 401

    def test_jwt_error_raises(self) -> None:
        from jose import JWTError

        auth, _ = _build_auth()
        with mock.patch(_JWKS_VERIFY_PATH, side_effect=JWTError("bad")):
            with pytest.raises(HTTPException) as exc_info:
                auth.verify_token("bad.jwt.token")
            assert exc_info.value.status_code == 401

    def test_jwks_key_error_raises_401(self) -> None:
        """KeyError from JWKS cache results in 401."""
        auth, _ = _build_auth()
        with mock.patch(_JWKS_VERIFY_PATH, side_effect=KeyError("kid not found")):
            with pytest.raises(HTTPException) as exc_info:
                auth.verify_token("fake.jwt.token")
            assert exc_info.value.status_code == 401

    def test_jwks_runtime_error_raises_401(self) -> None:
        """RuntimeError from JWKS fetch failure results in 401."""
        auth, _ = _build_auth()
        with mock.patch(_JWKS_VERIFY_PATH, side_effect=RuntimeError("fetch failed")):
            with pytest.raises(HTTPException) as exc_info:
                auth.verify_token("fake.jwt.token")
            assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_current_user
# ---------------------------------------------------------------------------


class TestGetCurrentUser:
    def test_no_credentials_raises_401(self) -> None:
        auth, _ = _build_auth()
        with pytest.raises(HTTPException) as exc_info:
            auth.get_current_user(credentials=None)
        assert exc_info.value.status_code == 401

    def test_with_valid_credentials(self) -> None:
        import time

        auth, _ = _build_auth()
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="fake.jwt")
        claims = {"sub": "u1", "client_id": "test-client-id", "exp": time.time() + 3600}
        with mock.patch(_JWKS_VERIFY_PATH, return_value=claims):
            result = auth.get_current_user(credentials=creds)
        assert result["sub"] == "u1"


# ---------------------------------------------------------------------------
# get_customer_id
# ---------------------------------------------------------------------------


class TestGetCustomerId:
    def test_extracts_customer_id(self) -> None:
        auth, _ = _build_auth()
        claims = {"sub": "u1", "custom:customer_id": "cust-42"}
        assert auth.get_customer_id(claims) == "cust-42"

    def test_missing_customer_id_raises_403(self) -> None:
        auth, _ = _build_auth()
        with pytest.raises(HTTPException) as exc_info:
            auth.get_customer_id({"sub": "u1"})
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# list_customer_users
# ---------------------------------------------------------------------------


class TestListCustomerUsers:
    def test_returns_users(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.list_users.return_value = {
            "Users": [
                {"Username": "a@x.com", "Attributes": [{"Name": "email", "Value": "a@x.com"}]},
            ]
        }
        users = auth.list_customer_users("cust1")
        assert len(users) == 1
        mock_client.list_users.assert_called_once()

    def test_client_error_returns_empty(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.list_users.side_effect = _make_client_error("InternalError")
        users = auth.list_customer_users("cust1")
        assert users == []


# ---------------------------------------------------------------------------
# delete_user
# ---------------------------------------------------------------------------


class TestDeleteUser:
    def test_success_returns_true(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_delete_user.return_value = {}
        assert auth.delete_user("u@x.com") is True

    def test_failure_returns_false(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_delete_user.side_effect = _make_client_error("UserNotFoundException")
        assert auth.delete_user("u@x.com") is False


# ---------------------------------------------------------------------------
# set_user_password
# ---------------------------------------------------------------------------


class TestSetUserPassword:
    def test_sets_permanent_password(self) -> None:
        auth, mock_client = _build_auth()
        auth.set_user_password("u@x.com", "NewPass1", permanent=True)
        mock_client.admin_set_user_password.assert_called_once_with(
            UserPoolId="us-west-2_TestPool",
            Username="u@x.com",
            Password="NewPass1",
            Permanent=True,
        )

    def test_sets_temporary_password(self) -> None:
        auth, mock_client = _build_auth()
        auth.set_user_password("u@x.com", "Temp1", permanent=False)
        call_kwargs = mock_client.admin_set_user_password.call_args[1]
        assert call_kwargs["Permanent"] is False

    def test_invalid_password_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_set_user_password.side_effect = _make_client_error("InvalidPasswordException")
        with pytest.raises(ValueError, match="requirements"):
            auth.set_user_password("u@x.com", "weak", permanent=True)

    def test_user_not_found_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_set_user_password.side_effect = _make_client_error("UserNotFoundException")
        with pytest.raises(ValueError, match="not found"):
            auth.set_user_password("u@x.com", "P1", permanent=True)

    def test_missing_pool_id_raises(self) -> None:
        auth, _ = _build_auth(user_pool_id="")
        with pytest.raises(ValueError, match="not configured"):
            auth.set_user_password("u@x.com", "P1", permanent=True)


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------


class TestAuthenticate:
    def test_successful_auth(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "at",
                "IdToken": "it",
                "RefreshToken": "rt",
                "ExpiresIn": 3600,
                "TokenType": "Bearer",
            }
        }
        result = auth.authenticate("u@x.com", "pass")
        assert result["access_token"] == "at"
        assert result["id_token"] == "it"
        assert result["refresh_token"] == "rt"

    def test_challenge_response(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_initiate_auth.return_value = {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": "sess-tok",
            "ChallengeParameters": {"USER_ID_FOR_SRP": "u@x.com"},
        }
        result = auth.authenticate("u@x.com", "temp")
        assert result["challenge"] == "NEW_PASSWORD_REQUIRED"
        assert result["session"] == "sess-tok"

    def test_not_authorized_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_initiate_auth.side_effect = _make_client_error("NotAuthorizedException")
        with pytest.raises(ValueError, match="Invalid email or password"):
            auth.authenticate("u@x.com", "wrong")

    def test_user_not_found_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_initiate_auth.side_effect = _make_client_error("UserNotFoundException")
        with pytest.raises(ValueError, match="Invalid email or password"):
            auth.authenticate("missing@x.com", "p")

    def test_user_not_confirmed_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_initiate_auth.side_effect = _make_client_error("UserNotConfirmedException")
        with pytest.raises(ValueError, match="not confirmed"):
            auth.authenticate("u@x.com", "p")

    def test_includes_secret_hash_when_secret_set(self) -> None:
        auth, mock_client = _build_auth(app_client_secret="my-secret")
        mock_client.admin_initiate_auth.return_value = {
            "AuthenticationResult": {
                "AccessToken": "at",
                "IdToken": "it",
                "RefreshToken": "rt",
                "ExpiresIn": 3600,
            }
        }
        auth.authenticate("u@x.com", "pass")
        call_kwargs = mock_client.admin_initiate_auth.call_args[1]
        assert "SECRET_HASH" in call_kwargs["AuthParameters"]


# ---------------------------------------------------------------------------
# respond_to_new_password_challenge
# ---------------------------------------------------------------------------


class TestRespondToNewPasswordChallenge:
    def test_success(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_respond_to_auth_challenge.return_value = {
            "AuthenticationResult": {
                "AccessToken": "at2",
                "IdToken": "it2",
                "RefreshToken": "rt2",
                "ExpiresIn": 3600,
            }
        }
        result = auth.respond_to_new_password_challenge("u@x.com", "NewPass1", "sess")
        assert result["access_token"] == "at2"

    def test_invalid_password_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_respond_to_auth_challenge.side_effect = _make_client_error("InvalidPasswordException")
        with pytest.raises(ValueError, match="requirements"):
            auth.respond_to_new_password_challenge("u@x.com", "weak", "sess")

    def test_other_error_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.admin_respond_to_auth_challenge.side_effect = _make_client_error(
            "SomeOtherError", "something went wrong"
        )
        with pytest.raises(ValueError, match="Password change failed"):
            auth.respond_to_new_password_challenge("u@x.com", "p", "sess")


# ---------------------------------------------------------------------------
# forgot_password
# ---------------------------------------------------------------------------


class TestForgotPassword:
    def test_success(self) -> None:
        auth, mock_client = _build_auth()
        auth.forgot_password("u@x.com")
        mock_client.forgot_password.assert_called_once_with(
            ClientId="test-client-id",
            Username="u@x.com",
        )

    def test_user_not_found_silently_returns(self) -> None:
        """Security: don't reveal whether user exists."""
        auth, mock_client = _build_auth()
        mock_client.forgot_password.side_effect = _make_client_error("UserNotFoundException")
        # Should NOT raise — prevents user enumeration
        auth.forgot_password("ghost@x.com")

    def test_limit_exceeded_raises_value_error(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.forgot_password.side_effect = _make_client_error("LimitExceededException")
        with pytest.raises(ValueError, match="Too many requests"):
            auth.forgot_password("u@x.com")

    def test_domain_validation(self) -> None:
        mock_settings = mock.MagicMock()
        mock_settings.validate_email_domain.return_value = (False, "nope")
        auth, _ = _build_auth()
        auth.settings = mock_settings
        with pytest.raises(HTTPException) as exc_info:
            auth.forgot_password("u@evil.com")
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# confirm_forgot_password
# ---------------------------------------------------------------------------


class TestConfirmForgotPassword:
    def test_success(self) -> None:
        auth, mock_client = _build_auth()
        auth.confirm_forgot_password("u@x.com", "123456", "NewPass1")
        mock_client.confirm_forgot_password.assert_called_once_with(
            ClientId="test-client-id",
            Username="u@x.com",
            ConfirmationCode="123456",
            Password="NewPass1",
        )

    def test_code_mismatch_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.confirm_forgot_password.side_effect = _make_client_error("CodeMismatchException")
        with pytest.raises(ValueError, match="Invalid verification code"):
            auth.confirm_forgot_password("u@x.com", "wrong", "P1")

    def test_expired_code_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.confirm_forgot_password.side_effect = _make_client_error("ExpiredCodeException")
        with pytest.raises(ValueError, match="expired"):
            auth.confirm_forgot_password("u@x.com", "old", "P1")

    def test_invalid_password_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.confirm_forgot_password.side_effect = _make_client_error("InvalidPasswordException")
        with pytest.raises(ValueError, match="requirements"):
            auth.confirm_forgot_password("u@x.com", "123", "weak")


# ---------------------------------------------------------------------------
# change_password
# ---------------------------------------------------------------------------


class TestChangePassword:
    def test_success(self) -> None:
        auth, mock_client = _build_auth()
        auth.change_password("access-tok", "old-pass", "new-pass")
        mock_client.change_password.assert_called_once_with(
            AccessToken="access-tok",
            PreviousPassword="old-pass",
            ProposedPassword="new-pass",
        )

    def test_wrong_old_password_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.change_password.side_effect = _make_client_error("NotAuthorizedException")
        with pytest.raises(ValueError, match="incorrect"):
            auth.change_password("at", "wrong", "new")

    def test_invalid_new_password_raises(self) -> None:
        auth, mock_client = _build_auth()
        mock_client.change_password.side_effect = _make_client_error("InvalidPasswordException")
        with pytest.raises(ValueError, match="requirements"):
            auth.change_password("at", "old", "weak")
