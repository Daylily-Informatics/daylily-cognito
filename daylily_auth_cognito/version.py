"""Package version metadata."""

from __future__ import annotations

try:
    from importlib.metadata import version as _get_version

    __version__ = _get_version("daylily-auth-cognito")
except Exception:
    __version__ = "0.0.0"
