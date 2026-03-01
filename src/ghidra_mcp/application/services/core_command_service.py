"""Core command routing service."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.application.services.ports import CoreCommandRuntimePort
from ghidra_mcp.application.usecases.datatypes import DATATYPE_COMMANDS
from ghidra_mcp.application.usecases.functions import FUNCTION_COMMANDS
from ghidra_mcp.application.usecases.memory import MEMORY_COMMANDS
from ghidra_mcp.application.usecases.symbols import SYMBOL_COMMANDS
from ghidra_mcp.domain import DomainError, ErrorCode


_SUPPORTED_COMMANDS = frozenset(
    (*FUNCTION_COMMANDS, *MEMORY_COMMANDS, *SYMBOL_COMMANDS, *DATATYPE_COMMANDS)
)


class CoreCommandService:
    def __init__(self, runtime_port: CoreCommandRuntimePort) -> None:
        self._runtime = runtime_port

    def call(self, command: str, params: dict[str, Any] | None = None, target: str = "default") -> Any:
        if command not in _SUPPORTED_COMMANDS:
            raise DomainError(
                code=ErrorCode.CORE_EXECUTOR_UNAVAILABLE,
                message=f"CORE_EXECUTOR_UNAVAILABLE: unsupported command '{command}'",
                hint="command名を確認してください",
                retryable=False,
                details={"command": command, "target": target},
            )
        return self._runtime.call(command, params, target)


__all__ = ["CoreCommandService"]
