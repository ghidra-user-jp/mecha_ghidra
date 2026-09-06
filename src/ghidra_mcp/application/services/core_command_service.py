"""Core command routing service."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.application.commands import CORE_COMMANDS
from ghidra_mcp.application.services.ports import CoreGatewayPort
from ghidra_mcp.domain import DomainError, ErrorCode


class CoreCommandService:
    """Validate a core command name and forward it to the gateway."""

    def __init__(self, core_gateway: CoreGatewayPort) -> None:
        self._core_gateway = core_gateway

    def call(self, command: str, params: dict[str, Any] | None = None, target: str = "default") -> Any:
        if command not in CORE_COMMANDS:
            raise DomainError(
                code=ErrorCode.CORE_EXECUTOR_UNAVAILABLE,
                message=f"CORE_EXECUTOR_UNAVAILABLE: unsupported command '{command}'",
                hint="Check the command name",
                retryable=False,
                details={"command": command, "target": target},
            )
        return self._core_gateway.execute(command, params or {}, target=target)


__all__ = ["CoreCommandService"]
