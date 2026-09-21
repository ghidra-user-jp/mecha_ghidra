"""Lazy package re-exports (PEP 562).

A package ``__init__`` that imports its submodules eagerly makes ``import
ghidra_mcp.contracts`` load the whole server (CLI, MCP SDK, JVM bridge).  The
layer packages instead declare *where* each public name lives and resolve it on
first attribute access, so importing a leaf layer costs only that layer.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from typing import Any


def lazy_exports(package: str, exports: dict[str, str]) -> tuple[Callable[[str], Any], Callable[[], list[str]]]:
    """Return ``(__getattr__, __dir__)`` for ``package`` resolving ``exports`` (name -> relative module) lazily."""

    def __getattr__(name: str) -> Any:
        try:
            module_name = exports[name]
        except KeyError:
            raise AttributeError(f"module {package!r} has no attribute {name!r}") from None
        value = getattr(importlib.import_module(module_name, package), name)
        # Cache on the package so later lookups bypass this hook.
        setattr(sys.modules[package], name, value)
        return value

    def __dir__() -> list[str]:
        return sorted(set(vars(sys.modules[package])) | set(exports))

    return __getattr__, __dir__


__all__ = ["lazy_exports"]
