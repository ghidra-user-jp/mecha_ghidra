"""Datatype/class mutating use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure.ghidra_adapter.core_gateway import CoreGateway


DATATYPE_COMMANDS: tuple[str, ...] = (
    "create_struct",
    "add_struct_members",
    "clear_struct",
    "delete_struct",
    "get_struct",
    "list_data_types",
    "create_enum",
    "add_enum_values",
    "remove_enum_values",
    "delete_enum",
    "get_enum",
    "rename_data_type",
    "create_class",
    "add_class_members",
    "remove_class_members",
    "remove_struct_members",
    "set_global_data_type",
)


class DatatypesUseCases:
    def __init__(self, core_gateway: CoreGateway) -> None:
        self._core_gateway = core_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in DATATYPE_COMMANDS:
            raise ValueError(f"unsupported datatype command: {command}")
        return self._core_gateway.execute(command, params, target=target)


__all__ = ["DATATYPE_COMMANDS", "DatatypesUseCases"]
