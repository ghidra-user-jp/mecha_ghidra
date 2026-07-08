"""MCP resources exposing detailed tool documentation on demand."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.presentation.tool_registry import (
    public_input_schema,
    public_output_schema,
    public_parameter_names,
    select_tool_description,
    tool_annotations_for_spec,
)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _annotation_payload(spec: ToolSpec) -> dict[str, Any] | None:
    annotations = tool_annotations_for_spec(spec)
    if annotations is None:
        return None
    return annotations.model_dump(exclude_none=True)


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
    return {
        "name": spec.name,
        "description": spec.description,
        "short_description": select_tool_description(spec, "short"),
        "category": _enum_value(spec.category_tag),
        "safety_tag": _enum_value(spec.safety_tag),
        "operation_level": _enum_value(spec.operation_level),
        "public_signature": public_parameter_names(spec),
        "input_schema": public_input_schema(spec),
        "output_schema": public_output_schema(spec),
        "annotations": _annotation_payload(spec),
        "checkout_required": spec.checkout_required,
    }


def register_tool_doc_resources(mcp, *, specs: dict[str, ToolSpec]) -> None:
    @mcp.resource(
        "ghidra://docs/tools",
        name="ghidra_tool_docs",
        description="Index of currently exposed Ghidra MCP tools.",
        mime_type="application/json",
    )
    def _list_tool_docs() -> dict[str, Any]:
        return tool_docs_index(specs)

    @mcp.resource(
        "ghidra://docs/tools/{tool_name}",
        name="ghidra_tool_doc",
        description="Detailed documentation for one exposed Ghidra MCP tool.",
        mime_type="application/json",
    )
    def _get_tool_doc(tool_name: str) -> dict[str, Any]:
        try:
            spec = specs[tool_name]
        except KeyError as exc:
            raise ValueError(f"Unknown or unpublished tool: {tool_name}") from exc
        return tool_docs_detail(spec)


__all__ = ["register_tool_doc_resources", "tool_docs_detail", "tool_docs_index"]
