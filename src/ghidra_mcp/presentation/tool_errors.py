"""Anticipated application failures that may be shown to an MCP client."""

from __future__ import annotations

from ghidra_mcp.domain import ErrorCode


class ToolError(Exception):
    """A validated, public-safe failure at the tool boundary.

    With a ``code`` the reply carries it, and its hint, as a domain error's does.
    """

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        self.code = code
