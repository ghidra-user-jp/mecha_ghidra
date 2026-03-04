"""Core command routing service."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.application.usecases.datatypes import DATATYPE_COMMANDS, DatatypesUseCases
from ghidra_mcp.application.usecases.functions import FUNCTION_COMMANDS, FunctionsUseCases
from ghidra_mcp.application.usecases.memory import MEMORY_COMMANDS, MemoryUseCases
from ghidra_mcp.application.usecases.symbols import SYMBOL_COMMANDS, SymbolsUseCases
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


_SUPPORTED_COMMANDS = frozenset(
    (*FUNCTION_COMMANDS, *MEMORY_COMMANDS, *SYMBOL_COMMANDS, *DATATYPE_COMMANDS)
)


class CoreCommandService:
    def __init__(
        self,
        core_gateway: CoreGateway,
        *,
        functions_usecases: FunctionsUseCases | None = None,
        memory_usecases: MemoryUseCases | None = None,
        symbols_usecases: SymbolsUseCases | None = None,
        datatypes_usecases: DatatypesUseCases | None = None,
    ) -> None:
        self._functions_usecases = functions_usecases or FunctionsUseCases(core_gateway)
        self._memory_usecases = memory_usecases or MemoryUseCases(core_gateway)
        self._symbols_usecases = symbols_usecases or SymbolsUseCases(core_gateway)
        self._datatypes_usecases = datatypes_usecases or DatatypesUseCases(core_gateway)

    def call(self, command: str, params: dict[str, Any] | None = None, target: str = "default") -> Any:
        normalized_params = params or {}
        if command not in _SUPPORTED_COMMANDS:
            raise DomainError(
                code=ErrorCode.CORE_EXECUTOR_UNAVAILABLE,
                message=f"CORE_EXECUTOR_UNAVAILABLE: unsupported command '{command}'",
                hint="Check the command name",
                retryable=False,
                details={"command": command, "target": target},
            )
        if command in FUNCTION_COMMANDS:
            return self._functions_usecases.execute(command, normalized_params, target=target)
        if command in MEMORY_COMMANDS:
            return self._memory_usecases.execute(command, normalized_params, target=target)
        if command in SYMBOL_COMMANDS:
            return self._symbols_usecases.execute(command, normalized_params, target=target)
        return self._datatypes_usecases.execute(command, normalized_params, target=target)


__all__ = ["CoreCommandService"]
