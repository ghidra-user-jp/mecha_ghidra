"""Input model helpers for declarative MCP tool specifications."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, create_model


class ToolInputModel(BaseModel):
    """Strict base model for tool input validation."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ToolOutputModel(BaseModel):
    """Strict base model for tool output validation."""

    model_config = ConfigDict(extra="forbid", strict=True)


def create_optional_any_input_model(model_name: str, field_names: tuple[str, ...]) -> type[ToolInputModel]:
    fields = {name: (Any, None) for name in field_names}
    return create_model(model_name, __base__=ToolInputModel, **fields)


def create_typed_input_model(
    model_name: str,
    field_defs: dict[str, tuple[type[Any], Any]],
) -> type[ToolInputModel]:
    return create_model(model_name, __base__=ToolInputModel, **field_defs)


def create_typed_output_model(
    model_name: str,
    field_defs: dict[str, tuple[type[Any], Any]],
) -> type[ToolOutputModel]:
    return create_model(model_name, __base__=ToolOutputModel, **field_defs)


def create_list_output_model(model_name: str, item_type: type[Any] = object) -> type[ToolOutputModel]:
    return create_typed_output_model(model_name, {"payload": (list[item_type], ...)})


def create_map_output_model(
    model_name: str,
    value_type: type[Any] = object,
    *,
    allow_empty_list: bool = False,
) -> type[ToolOutputModel]:
    payload_type = dict[str, value_type] | list[object] if allow_empty_list else dict[str, value_type]
    return create_typed_output_model(model_name, {"payload": (payload_type, ...)})


def create_scalar_output_model(
    model_name: str,
    scalar_type: type[Any],
    *,
    allow_empty_list: bool = False,
) -> type[ToolOutputModel]:
    payload_type = scalar_type | list[object] if allow_empty_list else scalar_type
    return create_typed_output_model(model_name, {"payload": (payload_type, ...)})


def create_any_output_model(model_name: str = "AnyToolOutput") -> type[ToolOutputModel]:
    return create_model(model_name, __base__=ToolOutputModel, payload=(Any, None))


__all__ = [
    "ToolInputModel",
    "ToolOutputModel",
    "create_typed_output_model",
    "create_list_output_model",
    "create_map_output_model",
    "create_scalar_output_model",
    "create_any_output_model",
    "create_optional_any_input_model",
    "create_typed_input_model",
]
