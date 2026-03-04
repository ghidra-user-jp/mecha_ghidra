"""Backward-compatible shim for the new presentation CLI module."""

from __future__ import annotations

import sys

from ghidra_mcp.presentation import cli as _presentation_cli

sys.modules[__name__] = _presentation_cli
