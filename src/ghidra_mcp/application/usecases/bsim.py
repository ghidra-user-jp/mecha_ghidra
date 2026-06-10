"""BSim-oriented core command use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


BSIM_COMMANDS: tuple[str, ...] = (
    "bsim_query_target",
    "bsim_query_function",
    "bsim_set_target_metadata",
    "bsim_register_target",
)


class BsimUseCases:
    def __init__(self, core_gateway: CoreGateway) -> None:
        self._core_gateway = core_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in BSIM_COMMANDS:
            raise ValueError(f"unsupported bsim command: {command}")
        return self._core_gateway.execute(command, params, target=target)


__all__ = ["BSIM_COMMANDS", "BsimUseCases"]
