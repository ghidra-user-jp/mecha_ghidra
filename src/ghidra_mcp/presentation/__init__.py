"""Presentation-layer exports for ghidra_mcp."""

from .error_mapper import map_exception
from .mcp_server import MCPServerRuntime, create_mcp_server
from .tool_dispatcher import dispatch_tool, normalize_empty_list_result
from .tool_registry import ToolRegistry, build_tool_functions, build_tool_objects

__all__ = [
    "MCPServerRuntime",
    "ToolRegistry",
    "build_tool_functions",
    "create_mcp_server",
    "dispatch_tool",
    "map_exception",
    "normalize_empty_list_result",
    "build_tool_objects",
]
