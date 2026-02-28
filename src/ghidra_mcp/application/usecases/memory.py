"""Memory/data read-only use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure import CoreGateway


MEMORY_COMMANDS: tuple[str, ...] = (
    "list_segments",
    "list_imports",
    "list_exports",
    "list_namespaces",
    "list_data_items",
    "list_strings",
    "get_data_by_label",
    "get_bytes",
    "search_bytes",
)


class MemoryUseCases:
    def __init__(self, core_gateway: CoreGateway) -> None:
        self._core_gateway = core_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in MEMORY_COMMANDS:
            raise ValueError(f"unsupported memory command: {command}")
        return self._core_gateway.execute(command, params, target=target)


__all__ = ["MEMORY_COMMANDS", "MemoryUseCases"]
