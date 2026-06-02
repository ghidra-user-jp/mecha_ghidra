"""Function-oriented read-only use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


FUNCTION_COMMANDS: tuple[str, ...] = (
    "list_functions",
    "list_classes",
    "search_functions_by_name",
    "get_function",
    "decompile_function",
    "disassemble_function",
    "disassemble_range",
    "create_function",
    "delete_function",
    "analyze_program",
    "reanalyze_program",
    "get_callee",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_function_xrefs",
)


class FunctionsUseCases:
    def __init__(self, core_gateway: CoreGateway) -> None:
        self._core_gateway = core_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in FUNCTION_COMMANDS:
            raise ValueError(f"unsupported function command: {command}")
        return self._core_gateway.execute(command, params, target=target)


__all__ = ["FUNCTION_COMMANDS", "FunctionsUseCases"]
