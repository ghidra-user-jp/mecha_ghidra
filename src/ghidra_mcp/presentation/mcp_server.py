"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.contracts.tool_spec import get_all_tool_specs
from ghidra_mcp.presentation.tool_registry import ToolRegistry, register_shared_sync_tools


@dataclass(slots=True)
class MCPServerRuntime:
    mcp: FastMCP
    tools: dict[str, Callable[..., Any]]
    shared_sync_registered: bool = False

    def register_shared_sync(self) -> None:
        if self.shared_sync_registered:
            return
        register_shared_sync_tools(self.mcp, tools=self.tools)
        self.shared_sync_registered = True


def create_mcp_server(
    *,
    registry_provider: Callable[[], Any],
    dispatcher_provider: Callable[[], Callable[..., Any]],
    include_shared_sync: bool = False,
) -> MCPServerRuntime:
    mcp = FastMCP("GhidraMCP Headless")
    specs = get_all_tool_specs(include_shared_sync=True)
    tools = ToolRegistry.register_all(
        mcp,
        specs,
        dispatcher_provider,
        registry_provider,
        include_shared_sync=include_shared_sync,
    )
    runtime = MCPServerRuntime(mcp=mcp, tools=tools, shared_sync_registered=include_shared_sync)
    return runtime


__all__ = ["MCPServerRuntime", "create_mcp_server"]
