"""Alias module: ``ghidra_mcp.cli`` *is* :mod:`ghidra_mcp.presentation.cli`.

The console script (``ghidra-mcp = ghidra_mcp.cli:main``), the test suite and
downstream users import this path and expect the full module surface, not just
``main``.  Registering the presentation module under this name keeps every
attribute lookup consistent between the two import paths.
"""

from __future__ import annotations

import sys

from ghidra_mcp.presentation import cli as _presentation_cli

sys.modules[__name__] = _presentation_cli
