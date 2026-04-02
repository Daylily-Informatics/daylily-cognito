"""Shared browser-session helpers for Cognito Hosted UI integrations."""

from __future__ import annotations

import inspect
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from .oauth import build_authorization_url, exchange_authorization_code

DEFAULT_AUTHENTICATED_REDIRECT = "/"
DEFAULT_ERROR_REDIRECT_PATH = "/auth/error"
SESSION_EXPIRED_REASON = "session_expired"
STATE_SESSION_KEY = "_cognito_oauth_state"
NEXT_PATH_SESSION_KEY = "_cognito_post_auth_redirect"
CONFIG_STATE_KEY = "_daylily_cognito_web_session_config"
TOKEN_FIELD_NAMES = frozenset({"access_token", "id_token", "refresh_token"})
PRINCIPAL_SESSION_FIELDS = (
    "user_sub",
    "email",
    "name",
    "roles",
    "cognito_groups",
    "auth_mode",
    "authenticated_at",
    "server_instance_id",
    "app_context",
)


class CognitoWebAuthError(Exception):
    """Raised when the hosted-ui browser flow cannot complete."""

    def __init__(
        self,
        reason: str,
        detail: str,
        *,
        status_code: int = 400,
        redirect_to_error: bool = False,
    ) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.status_code = status_code
        self.redirect_to_error = redirect_to_error

    @property
    def message(self) -> str:
        """Backward-compatible alias for detail."""
        return self.detail


@dataclass(frozen=True)
class CognitoWebSessionConfig:
    """Configuration for cookie-backed Cognito Hosted UI browser auth."""

    domain: str
    client_id: str
    redirect_uri: str
    logout_uri: str
    session_secret_key: str
    session_cookie_name: str
    session_max_age: int = 60 * 60 * 12
    public_base_url: str | None = None
    auth_mode: str = "cognito"
    scope: str = "openid email profile"
    response_type: str = "code"
    client_secret: str | None = None
    code_verifier: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    same_site: str = "lax"
    allow_insecure_http: bool = False
    state_session_key: str = STATE_SESSION_KEY
    next_path_session_key: str = NEXT_PATH_SESSION_KEY
    error_redirect_path: str = DEFAULT_ERROR_REDIRECT_PATH
    server_instance_id: str | None = None

    @property
    def normalized_domain(self) -> str:
        """Return the Cognito domain without a scheme prefix."""
        return _normalize_domain(self.domain)

    @property
    def effective_public_base_url(self) -> str:
        """Return the normalized base URL used for cookie and URI validation."""
        return _normalized_public_base_url(self, self.public_base_url)

    @property
    def https_only(self) -> bool:
        """Return whether the session cookie must be marked Secure."""
        return urlparse(self.effective_public_base_url).scheme == "https"

    @property
    def secret_key(self) -> str:
        """Backward-compatible alias for earlier drafts."""
        return self.session_secret_key

    @property
    def cookie_name(self) -> str:
        """Backward-compatible alias for earlier drafts."""
        return self.session_cookie_name


@dataclass(frozen=True)
class SessionPrincipal:
    """Normalized identity persisted in the browser session."""

    user_sub: str
    email: str
    name: str | None = None
    roles: list[str] = field(default_factory=list)
    cognito_groups: list[str] = field(default_factory=list)
    auth_mode: str = "cognito"
    authenticated_at: str | None = None
    server_instance_id: str | None = None
    app_context: dict[str, Any] = field(default_factory=dict)

    def to_session_dict(self) -> dict[str, Any]:
        """Return a flat session payload suitable for SessionMiddleware."""
        if not self.user_sub:
            raise ValueError("SessionPrincipal.user_sub is required")
        if not self.email:
            raise ValueError("SessionPrincipal.email is required")

        _reject_token_fields(self.app_context)
        return {
            "user_sub": self.user_sub,
            "email": self.email,
            "name": self.name,
            "roles": list(self.roles),
            "cognito_groups": list(self.cognito_groups),
            "auth_mode": self.auth_mode,
            "authenticated_at": self.authenticated_at,
            "server_instance_id": self.server_instance_id,
            "app_context": dict(self.app_context),
        }

    @classmethod
    def from_session(cls, session: Mapping[str, Any]) -> "SessionPrincipal | None":
        """Parse a session payload into a SessionPrincipal."""
        user_sub = session.get("user_sub")
        email = session.get("email")
        if not user_sub or not email:
            return None

        app_context = session.get("app_context") or {}
        if not isinstance(app_context, Mapping):
            raise ValueError("Session app_context must be a mapping")

        return cls(
            user_sub=str(user_sub),
            email=str(email),
            name=session.get("name"),
            roles=_normalize_string_list(session.get("roles")),
            cognito_groups=_normalize_string_list(session.get("cognito_groups")),
            auth_mode=str(session.get("auth_mode") or "cognito"),
            authenticated_at=session.get("authenticated_at"),
            server_instance_id=session.get("server_instance_id"),
            app_context={str(key): value for key, value in dict(app_context).items()},
        )

    @classmethod
    def from_session_dict(cls, payload: Mapping[str, Any]) -> "SessionPrincipal | None":
        """Backward-compatible alias for earlier drafts."""
        return cls.from_session(payload)


ResolvePrincipalResult = Union[SessionPrincipal, Mapping[str, Any]]
ResolvePrincipal = Callable[[Mapping[str, Any], Request], Union[ResolvePrincipalResult, Awaitable[ResolvePrincipalResult]]]


def configure_session_middleware(app: FastAPI, config: CognitoWebSessionConfig) -> None:
    """Attach SessionMiddleware using the hardened shared cookie contract."""
    validate_web_auth_contract(config, config.public_base_url)
    if any(m.cls is SessionMiddleware for m in app.user_middleware):
        raise ValueError("SessionMiddleware is already configured on this app")

    app.state.__dict__[CONFIG_STATE_KEY] = config
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.session_secret_key,
        max_age=config.session_max_age,
        same_site="lax",
        https_only=config.https_only,
        session_cookie=config.session_cookie_name,
    )


def start_cognito_login(
    request: Request,
    config: CognitoWebSessionConfig,
    next_path: str | None = None,
) -> RedirectResponse:
    """Start the hosted-ui login redirect and persist CSRF state."""
    validate_web_auth_contract(config, config.public_base_url)
    _set_request_config(request, config)

    state = secrets.token_urlsafe(32)
    request.session[config.state_session_key] = state
    request.session[config.next_path_session_key] = _sanitize_next_path(next_path)

    login_url = build_authorization_url(
        domain=config.normalized_domain,
        client_id=config.client_id,
        redirect_uri=config.redirect_uri,
        response_type=config.response_type,
        scope=config.scope,
        state=state,
        code_challenge=config.code_challenge,
        code_challenge_method=config.code_challenge_method,
    )
    return RedirectResponse(url=login_url, status_code=302)


async def complete_cognito_callback(
    request: Request,
    config: CognitoWebSessionConfig,
    code: str | None,
    state: str | None,
    resolve_principal: ResolvePrincipal,
) -> RedirectResponse:
    """Validate state, exchange the auth code, persist the session, and redirect."""
    validate_web_auth_contract(config, config.public_base_url)
    _set_request_config(request, config)

    if not code:
        raise CognitoWebAuthError("missing_code", "Missing authorization code")

    _verify_oauth_state(request, config, state)
    request.session.pop(config.state_session_key, None)

    try:
        tokens = exchange_authorization_code(
            domain=config.normalized_domain,
            client_id=config.client_id,
            code=code,
            redirect_uri=config.redirect_uri,
            client_secret=config.client_secret,
            code_verifier=config.code_verifier,
        )
    except RuntimeError as exc:
        raise CognitoWebAuthError(
            "token_exchange_failed",
            str(exc),
            status_code=401,
        ) from exc

    try:
        resolved = resolve_principal(tokens, request)
        if inspect.isawaitable(resolved):
            resolved = await resolved
    except CognitoWebAuthError as exc:
        if exc.redirect_to_error:
            clear_session_principal(request)
            request.session.pop(config.next_path_session_key, None)
            return RedirectResponse(
                url=_build_error_redirect_path(config.error_redirect_path, exc.reason),
                status_code=302,
            )
        raise

    principal = _coerce_principal(resolved)
    store_session_principal(request, config, principal)
    redirect_path = request.session.pop(config.next_path_session_key, None)
    return RedirectResponse(url=_sanitize_next_path(redirect_path), status_code=302)


def store_session_principal(
    request: Request,
    config: CognitoWebSessionConfig,
    principal: ResolvePrincipalResult,
) -> SessionPrincipal:
    """Persist a normalized principal to the browser session."""
    _set_request_config(request, config)
    normalized = _coerce_principal(principal)
    payload = normalized.to_session_dict()

    if not payload.get("authenticated_at"):
        payload["authenticated_at"] = datetime.now(timezone.utc).isoformat()
    if config.server_instance_id and not payload.get("server_instance_id"):
        payload["server_instance_id"] = config.server_instance_id
    if not payload.get("auth_mode"):
        payload["auth_mode"] = config.auth_mode

    clear_session_principal(request)
    request.session.update(payload)
    stored = SessionPrincipal.from_session(request.session)
    assert stored is not None
    request.state.cognito_session_principal = stored
    request.state.cognito_auth_reason = None
    return stored


def load_session_principal(request: Request) -> SessionPrincipal | None:
    """Load the current authenticated browser principal from session state."""
    config = _get_request_config(request)

    if hasattr(request.state, "cognito_session_principal"):
        return request.state.cognito_session_principal

    try:
        principal = SessionPrincipal.from_session(request.session)
    except ValueError:
        clear_session_principal(request)
        request.state.cognito_auth_reason = "invalid_session"
        request.state.cognito_session_principal = None
        return None

    if principal is None:
        request.state.cognito_auth_reason = None
        request.state.cognito_session_principal = None
        return None

    if config.server_instance_id and principal.server_instance_id != config.server_instance_id:
        clear_session_principal(request)
        request.state.cognito_auth_reason = SESSION_EXPIRED_REASON
        request.state.cognito_session_principal = None
        return None

    request.state.cognito_auth_reason = None
    request.state.cognito_session_principal = principal
    return principal


def clear_session_principal(request: Request) -> None:
    """Remove the persisted browser principal and any legacy token fields."""
    session = getattr(request, "session", None)
    if session is None:
        return

    for key in tuple(PRINCIPAL_SESSION_FIELDS) + tuple(TOKEN_FIELD_NAMES):
        session.pop(key, None)
    request.state.cognito_session_principal = None


def validate_web_auth_contract(
    config: CognitoWebSessionConfig,
    public_base_url: str | None,
) -> None:
    """Validate the shared hosted-ui session contract."""
    if not config.session_secret_key:
        raise ValueError("session_secret_key is required")
    if not config.session_cookie_name:
        raise ValueError("session_cookie_name is required")
    if config.session_cookie_name == "session":
        raise ValueError("session_cookie_name must not use the Starlette default 'session'")
    if config.same_site.lower() != "lax":
        raise ValueError("same_site must be 'lax'")
    if config.session_max_age <= 0:
        raise ValueError("session_max_age must be positive")
    if not config.server_instance_id:
        raise ValueError("server_instance_id is required")

    _normalize_domain(config.domain)
    redirect = _require_absolute_url(config.redirect_uri, "redirect_uri")
    logout = _require_absolute_url(config.logout_uri, "logout_uri")
    base = _require_absolute_url(_normalized_public_base_url(config, public_base_url), "public_base_url")

    if redirect.scheme != base.scheme or redirect.netloc != base.netloc:
        raise ValueError("redirect_uri must share scheme and host with public_base_url")
    if logout.scheme != base.scheme or logout.netloc != base.netloc:
        raise ValueError("logout_uri must share scheme and host with public_base_url")


def _coerce_principal(principal: ResolvePrincipalResult) -> SessionPrincipal:
    if isinstance(principal, SessionPrincipal):
        return principal
    if isinstance(principal, Mapping):
        normalized = SessionPrincipal.from_session(principal)
        if normalized is None:
            raise ValueError("resolve_principal() produced an incomplete principal")
        return normalized
    raise TypeError("resolve_principal() must return SessionPrincipal or mapping")


def _verify_oauth_state(
    request: Request,
    config: CognitoWebSessionConfig,
    state: str | None,
) -> None:
    expected_state = request.session.get(config.state_session_key)
    if not expected_state or state != expected_state:
        raise CognitoWebAuthError("invalid_state", "Invalid state parameter")


def _build_error_redirect_path(base_path: str, reason: str) -> str:
    parsed = urlparse(base_path if base_path.startswith("/") else f"/{base_path}")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["reason"] = reason
    return urlunparse(parsed._replace(query=urlencode(query)))


def _sanitize_next_path(next_path: str | None) -> str:
    if not next_path:
        return DEFAULT_AUTHENTICATED_REDIRECT

    parsed = urlparse(next_path)
    if parsed.scheme or parsed.netloc:
        return DEFAULT_AUTHENTICATED_REDIRECT
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return DEFAULT_AUTHENTICATED_REDIRECT

    candidate = urlunparse(("", "", parsed.path, parsed.params, parsed.query, parsed.fragment))
    if candidate in {"/login", "/auth/login", "/auth/callback", "/auth/logout", "/auth/error"}:
        return DEFAULT_AUTHENTICATED_REDIRECT
    return candidate


def _normalize_domain(domain: str) -> str:
    value = (domain or "").strip().rstrip("/")
    if value.startswith("https://"):
        value = value[len("https://") :]
    elif value.startswith("http://"):
        value = value[len("http://") :]
    if not value:
        raise ValueError("domain is required")
    return value


def _normalized_public_base_url(
    config: CognitoWebSessionConfig,
    public_base_url: str | None,
) -> str:
    base_url = (public_base_url or config.public_base_url or _origin(config.redirect_uri)).strip()
    parsed = _require_absolute_url(base_url, "public_base_url")
    if parsed.scheme != "https" and not config.allow_insecure_http:
        raise ValueError("HTTP public_base_url requires allow_insecure_http=True")
    return f"{parsed.scheme}://{parsed.netloc}"


def _origin(url: str) -> str:
    parsed = _require_absolute_url(url, "url")
    return f"{parsed.scheme}://{parsed.netloc}"


def _require_absolute_url(value: str, field_name: str):
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field_name} must be an absolute http(s) URL")
    return parsed


def _reject_token_fields(value: Any, *, path: str = "app_context") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_str = str(key)
            if key_str in TOKEN_FIELD_NAMES:
                raise ValueError(f"{path}.{key_str} may not contain raw OAuth tokens")
            _reject_token_fields(nested, path=f"{path}.{key_str}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_token_fields(nested, path=f"{path}[{index}]")


def _normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, (list, tuple, set)):
        raise ValueError("Session role and group fields must be string lists")

    result: list[str] = []
    for item in value:
        normalized = str(item or "").strip()
        if normalized:
            result.append(normalized)
    return result


def _get_request_config(request: Request) -> CognitoWebSessionConfig:
    state = getattr(getattr(request, "app", None), "state", None)
    if state is None or CONFIG_STATE_KEY not in state.__dict__:
        raise RuntimeError("Shared Cognito web-session config is not registered on the app")
    return state.__dict__[CONFIG_STATE_KEY]


def _set_request_config(request: Request, config: CognitoWebSessionConfig) -> None:
    request.app.state.__dict__[CONFIG_STATE_KEY] = config
