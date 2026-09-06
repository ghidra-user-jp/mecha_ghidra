"""Gateway that exposes the runtime backend's core-command entry point as a port."""

from __future__ import annotations

from typing import Any, Protocol


class CoreCommandBackend(Protocol):
    def execute_core_command(
        self, command: str, params: dict[str, Any] | None = None, *, target: str = "default"
    ) -> Any: ...


class CoreGateway:
    """Adapt ``RuntimeBackend.execute_core_command`` to ``CoreGatewayPort.execute``."""

    def __init__(self, backend: CoreCommandBackend) -> None:
        self._backend = backend

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        return self._backend.execute_core_command(command, params, target=target)


__all__ = ["CoreCommandBackend", "CoreGateway"]
