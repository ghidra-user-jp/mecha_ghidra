"""Anticipated application failures that may be shown to an MCP client."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.domain.output_state import ABSENT


class ToolError(Exception):
    """A validated, public-safe failure at the tool boundary.

    With a ``code`` the reply carries it, and its hint and ``details``, as a
    domain error's does.
    """

    def __init__(self, message: str, *, code: ErrorCode | None = None, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


class ToolInputError(ToolError, ValueError):
    """Arguments the tool's input rules reject: VALIDATION_ERROR, whichever check found it.

    The tool never ran, so a ``write`` tool's refusal says it left nothing behind.
    """

    def __init__(self, message: str, *, write: bool = False) -> None:
        super().__init__(message, code=ErrorCode.VALIDATION_ERROR, details={"output_state": ABSENT} if write else None)
