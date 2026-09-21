"""MCP resources exposing detailed tool documentation on demand."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.presentation.response_schemas import (
    _large_error_output_schema,
    _large_result_output_schema,
)
from ghidra_mcp.presentation.tool_registry import (
    public_input_schema,
    public_output_schema,
    public_parameter_names,
    select_tool_description,
    spec_wire_output_schema,
    tool_annotations_for_spec,
)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _annotation_payload(spec: ToolSpec) -> dict[str, Any] | None:
    annotations = tool_annotations_for_spec(spec)
    if annotations is None:
        return None
    return annotations.model_dump(by_alias=True, exclude_none=True)


def tool_docs_index(specs: dict[str, ToolSpec]) -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": spec.name,
                "category": _enum_value(spec.category_tag),
                "safety_tag": _enum_value(spec.safety_tag),
                "operation_level": _enum_value(spec.operation_level),
                "short_description": select_tool_description(spec, "short"),
            }
            for spec in specs.values()
        ]
    }


def tool_docs_detail(spec: ToolSpec) -> dict[str, Any]:
    detail = {
        "name": spec.name,
        "description": spec.description,
        "short_description": select_tool_description(spec, "short"),
        "category": _enum_value(spec.category_tag),
        "safety_tag": _enum_value(spec.safety_tag),
        "operation_level": _enum_value(spec.operation_level),
        "public_signature": public_parameter_names(spec),
        "input_schema": public_input_schema(spec),
        "output_schema": public_output_schema(spec),
        "structured_output_schema": spec_wire_output_schema(spec),
        "large_result_output_schema": _large_result_output_schema(),
        "large_error_output_schema": _large_error_output_schema(),
        "annotations": _annotation_payload(spec),
        "checkout_required": spec.checkout_required,
    }
    if spec.presenter == "batch":
        logical = public_output_schema(spec)
        compact = {
            **logical,
            "properties": {
                **logical["properties"],
                "truncated": {"const": True},
                "result_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                "resource_uri": {"type": "string"},
                "result_unavailable": {"const": True},
                "reason": {"type": "string"},
                "retrieval": {"type": "object"},
                "metadata_truncated": {"type": "boolean"},
                "item_summaries_omitted": {"type": "boolean"},
            },
            "required": [*logical["required"], "truncated"],
            "oneOf": [
                {"required": ["result_id", "resource_uri", "retrieval"]},
                {"required": ["result_unavailable", "reason"]},
            ],
        }
        detail["response_text_schema"] = {"oneOf": [logical, compact]}
        detail["large_result_output_schema"] = {
            "type": "object",
            "required": ["content", "isError"],
            "properties": {
                "isError": {"type": "boolean"},
                "content": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["type", "text"],
                        "properties": {
                            "type": {"const": "text"},
                            "text": {
                                "type": "string",
                                "contentMediaType": "application/json",
                                "contentSchema": compact,
                            },
                        },
                    },
                },
            },
            "description": "batch_read uses one JSON text block (response_text_schema). Full projected items share one cache entry; partial failure remains explicit in status and counts. isError=true when no reads succeeded.",
        }
    return detail


__all__ = ["tool_docs_detail", "tool_docs_index"]
