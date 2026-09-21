"""Presentation-layer exports for ghidra_mcp (resolved lazily; see ``ghidra_mcp._lazy``)."""

from ghidra_mcp._lazy import lazy_exports

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

__getattr__, __dir__ = lazy_exports(
    __name__,
    {
        "map_exception": ".error_mapper",
        "MCPServerRuntime": ".mcp_server",
        "create_mcp_server": ".mcp_server",
        "dispatch_tool": ".tool_dispatcher",
        "normalize_empty_list_result": ".tool_dispatcher",
        "ToolRegistry": ".tool_registry",
        "build_tool_functions": ".tool_registry",
        "build_tool_objects": ".tool_registry",
    },
)
