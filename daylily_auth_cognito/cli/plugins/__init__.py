"""Plugin registration for daycog."""

from __future__ import annotations

from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CliSpec

from . import apps, config, google, pools, status, users


def register(registry: CommandRegistry, spec: CliSpec) -> None:
    for module in (status, config, pools, apps, google, users):
        module.register(registry, spec)


__all__ = ["register"]
