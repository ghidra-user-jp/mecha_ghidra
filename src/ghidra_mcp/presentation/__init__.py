"""Presentation-layer helpers for ghidra_mcp."""

from .tool_dispatcher import CoreExecutorProtocol, dispatch_tool, normalize_empty_list_result

__all__ = [
    "CoreExecutorProtocol",
    "dispatch_tool",
    "normalize_empty_list_result",
]
