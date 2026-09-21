"""Anticipated application failures that may be shown to an MCP client."""


class ToolError(Exception):
    """A validated, public-safe failure at the tool boundary."""
