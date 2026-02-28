"""Input model helpers for declarative MCP tool specifications."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, create_model


class ToolInputModel(BaseModel):
    """Strict base model for tool input validation."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ToolOutputModel(BaseModel):
    """Default output model; payload shape is intentionally permissive."""

    model_config = ConfigDict(extra="allow")


def create_optional_any_input_model(model_name: str, field_names: tuple[str, ...]) -> type[ToolInputModel]:
    fields = {name: (Any, None) for name in field_names}
    return create_model(model_name, __base__=ToolInputModel, **fields)


def create_typed_input_model(
    model_name: str,
    field_defs: dict[str, tuple[type[Any], Any]],
) -> type[ToolInputModel]:
    return create_model(model_name, __base__=ToolInputModel, **field_defs)


def create_any_output_model(model_name: str = "AnyToolOutput") -> type[ToolOutputModel]:
    return create_model(model_name, __base__=ToolOutputModel, payload=(Any, None))


__all__ = [
    "ToolInputModel",
    "ToolOutputModel",
    "create_any_output_model",
    "create_optional_any_input_model",
    "create_typed_input_model",
]
