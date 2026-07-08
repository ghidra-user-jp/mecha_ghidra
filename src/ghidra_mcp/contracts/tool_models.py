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


class PayloadToolOutputModel(ToolOutputModel):
    """Validation-only wrapper around a single ``payload`` field.

    dispatch_tool validates list/scalar/map results through this wrapper but
    returns the bare payload, so no client-visible result ever carries the
    ``{"payload": ...}`` shape. Anything published to clients must unwrap it —
    see ``public_output_schema``.
    """


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


def _create_payload_output_model(model_name: str, payload_type: Any) -> type[ToolOutputModel]:
    return create_model(model_name, __base__=PayloadToolOutputModel, payload=(payload_type, ...))


def create_list_output_model(model_name: str, item_type: type[Any] = object) -> type[ToolOutputModel]:
    return _create_payload_output_model(model_name, list[item_type])


def create_map_output_model(
    model_name: str,
    value_type: type[Any] = object,
    *,
    allow_empty_list: bool = False,
) -> type[ToolOutputModel]:
    payload_type = dict[str, value_type] | list[object] if allow_empty_list else dict[str, value_type]
    return _create_payload_output_model(model_name, payload_type)


def create_scalar_output_model(
    model_name: str,
    scalar_type: type[Any],
    *,
    allow_empty_list: bool = False,
) -> type[ToolOutputModel]:
    payload_type = scalar_type | list[object] if allow_empty_list else scalar_type
    return _create_payload_output_model(model_name, payload_type)


__all__ = [
    "PayloadToolOutputModel",
    "ToolInputModel",
    "ToolOutputModel",
    "create_typed_output_model",
    "create_list_output_model",
    "create_map_output_model",
    "create_scalar_output_model",
    "create_optional_any_input_model",
    "create_typed_input_model",
]
