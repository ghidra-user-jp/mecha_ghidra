"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.presentation.tool_registry import ToolRegistry


@dataclass(slots=True)
class MCPServerRuntime:
    mcp: FastMCP
    tools: dict[str, Callable[..., Any]]
    specs: dict[str, ToolSpec]


def create_mcp_server(
    *,
    specs: dict[str, ToolSpec],
    registry_provider: Callable[[], Any],
    dispatcher_provider: Callable[[], Callable[..., Any]],
) -> MCPServerRuntime:
    mcp = FastMCP("GhidraMCP Headless")
    tools = ToolRegistry.register_all(
        mcp,
        specs,
        dispatcher_provider,
        registry_provider,
    )
    runtime = MCPServerRuntime(mcp=mcp, tools=tools, specs=dict(specs))
    return runtime


__all__ = ["MCPServerRuntime", "create_mcp_server"]
