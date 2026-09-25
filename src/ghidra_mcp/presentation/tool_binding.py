"""Explicit MCP tool contracts and their application callables."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Callable, get_type_hints

from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations
from pydantic import BaseModel, ConfigDict, create_model

from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.domain.error_hints import recovery_hint

from .response_schemas import wire_output_schema
from .result_compaction import _is_normalized_empty_list_result, _json_text, structured_result


@dataclass(frozen=True)
class ToolBinding:
    definition: Tool
    function: Callable[..., Any]
    arguments: type[BaseModel]
    compact_json: bool = False


def bind_function(
    function: Callable[..., Any], *, description: str, annotations: ToolAnnotations, output_schema: dict[str, Any]
) -> ToolBinding:
    """Build infrastructure tool arguments through Pydantic's public API."""
    hints = get_type_hints(function, include_extras=True)
    fields = {
        name: (hints[name], ... if parameter.default is inspect.Parameter.empty else parameter.default)
        for name, parameter in inspect.signature(function).parameters.items()
    }
    arguments = create_model(
        function.__name__ + "Arguments", __config__=ConfigDict(strict=True, extra="forbid"), **fields
    )
    definition = Tool(
        name=function.__name__,
        description=description,
        input_schema=arguments.model_json_schema(),
        output_schema=wire_output_schema(output_schema, detailed=False),
        annotations=annotations,
    )
    return ToolBinding(definition, function, arguments, compact_json=True)


def complete_tool_result(value: Any, *, compact_json: bool = False) -> CallToolResult:
    if isinstance(value, CallToolResult):
        if _is_normalized_empty_list_result(value):
            return structured_result([], content=value.content)
        return value
    content = [TextContent(type="text", text=_json_text(value))] if compact_json else None
    return structured_result(value, content=content)


def error_result(message: str, *, code: ErrorCode | None = None) -> CallToolResult:
    detail: dict[str, Any] = {"message": message}
    if code is not None:
        detail.update(code=code.value, retryable=False)
        hint = recovery_hint(code, message)
        if hint is not None:
            detail["hint"] = hint
    error = {"error": detail}
    return CallToolResult(
        is_error=True,
        content=[TextContent(type="text", text=_json_text(error))],
        structured_content=error,
    )
