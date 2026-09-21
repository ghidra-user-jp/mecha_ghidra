"""PyGhidraベースのGhidra MCPユーティリティ。

``ghidra_mcp.main`` is resolved lazily: importing a leaf layer such as
``ghidra_mcp.contracts`` or ``ghidra_mcp.domain`` must not start the CLI's
import chain (MCP SDK, JVM bridge, tool registry).
"""

from ghidra_mcp._lazy import lazy_exports

__all__ = ["main"]

__getattr__, __dir__ = lazy_exports(__name__, {"main": ".cli"})
