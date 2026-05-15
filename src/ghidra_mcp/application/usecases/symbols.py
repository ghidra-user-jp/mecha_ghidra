"""Symbol mutating use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


SYMBOL_COMMANDS: tuple[str, ...] = (
    "rename_function",
    "rename_function_by_address",
    "rename_data",
    "rename_variable",
    "set_decompiler_comment",
    "set_disassembly_comment",
    "set_function_prototype",
    "set_local_variable_type",
    "set_bytes",
    "add_bookmark",
    "list_bookmarks",
    "delete_bookmark",
)


class SymbolsUseCases:
    def __init__(self, core_gateway: CoreGateway) -> None:
        self._core_gateway = core_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in SYMBOL_COMMANDS:
            raise ValueError(f"unsupported symbol command: {command}")
        return self._core_gateway.execute(command, params, target=target)


__all__ = ["SYMBOL_COMMANDS", "SymbolsUseCases"]
