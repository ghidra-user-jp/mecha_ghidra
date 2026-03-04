"""Gateway for core command execution."""

from __future__ import annotations

from typing import Any, Protocol


class CoreExecutor(Protocol):
    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        ...


class CoreGateway:
    def __init__(self, executor: CoreExecutor) -> None:
        self._executor = executor

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        return self._executor.execute(command, params, key=target)


__all__ = ["CoreGateway", "CoreExecutor"]
