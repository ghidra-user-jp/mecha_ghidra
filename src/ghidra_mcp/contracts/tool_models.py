"""Input model helpers for declarative MCP tool specifications."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, create_model


class ToolInputModel(BaseModel):
    """Strict base model for tool input validation."""

    model_config = ConfigDict(extra="forbid", strict=True)


def create_optional_any_input_model(model_name: str, field_names: tuple[str, ...]) -> type[ToolInputModel]:
    fields = {name: (Any, None) for name in field_names}
    return create_model(model_name, __base__=ToolInputModel, **fields)


def create_typed_input_model(
    model_name: str,
    field_defs: dict[str, tuple[type[Any], Any]],
) -> type[ToolInputModel]:
    return create_model(model_name, __base__=ToolInputModel, **field_defs)


__all__ = [
    "ToolInputModel",
    "create_optional_any_input_model",
    "create_typed_input_model",
]
