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


def _large_result_output_schema() -> dict[str, Any]:
    """Describe the MCP wrapper returned when a logical result is compacted.

    ``output_schema`` intentionally remains the schema of the tool's logical
    value.  Large values may instead cross the MCP boundary as a
    ``CallToolResult`` whose ``structuredContent`` is compaction metadata, so
    expose that transport variant separately without changing existing schema
    consumers' interpretation of ``output_schema``.
    """
    item_count_schema = {
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "null"},
        ]
    }
    text_content_schema = {
        "type": "object",
        "required": ["type", "text"],
        "properties": {
            "type": {"const": "text", "type": "string"},
            "text": {"type": "string"},
        },
        "additionalProperties": True,
    }
    resource_link_schema = {
        "type": "object",
        "required": ["type", "name", "uri"],
        "properties": {
            "type": {"const": "resource_link", "type": "string"},
            "name": {"type": "string"},
            "uri": {
                "type": "string",
                "pattern": "^ghidra://results/[0-9a-f]{16}$",
            },
            "description": {
                "anyOf": [{"type": "string"}, {"type": "null"}]
            },
            "mimeType": {
                "anyOf": [{"type": "string"}, {"type": "null"}]
            },
            "size": {
                "anyOf": [
                    {"type": "integer", "minimum": 0},
                    {"type": "null"},
                ]
            },
        },
        "additionalProperties": True,
    }
    stored_metadata_schema = {
        "type": "object",
        "required": [
            "tool",
            "target",
            "truncated",
            "result_id",
            "resource_uri",
            "size_chars",
            "preview_chars",
            "mime_type",
            "result_type",
            "item_count",
            "metadata_truncated",
        ],
        "properties": {
            "tool": {"type": "string"},
            "target": {"type": "string"},
            "truncated": {"const": True, "type": "boolean"},
            "result_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
            "resource_uri": {
                "type": "string",
                "pattern": "^ghidra://results/[0-9a-f]{16}$",
            },
            "size_chars": {"type": "integer", "minimum": 0},
            "preview_chars": {"type": "integer", "minimum": 0},
            "mime_type": {"type": "string"},
            "result_type": {"type": "string"},
            "item_count": item_count_schema,
            "metadata_truncated": {"type": "boolean"},
        },
        # Permit additive metadata without invalidating doc-driven clients.
        "additionalProperties": True,
    }
    unavailable_metadata_schema = {
        "type": "object",
        "required": [
            "tool",
            "target",
            "truncated",
            "result_unavailable",
            "operation_succeeded",
            "size_chars",
            "size_bytes",
            "cache_max_bytes",
            "mime_type",
            "result_type",
            "item_count",
            "metadata_truncated",
        ],
        "properties": {
            "tool": {"type": "string"},
            "target": {"type": "string"},
            "truncated": {"const": True, "type": "boolean"},
            "result_unavailable": {"const": True, "type": "boolean"},
            "operation_succeeded": {"const": True, "type": "boolean"},
            "size_chars": {"type": "integer", "minimum": 0},
            "size_bytes": {"type": "integer", "minimum": 0},
            "cache_max_bytes": {"type": "integer", "minimum": 1},
            "mime_type": {"type": "string"},
            "result_type": {"type": "string"},
            "item_count": item_count_schema,
            "metadata_truncated": {"type": "boolean"},
        },
        "additionalProperties": True,
    }
    stored_result_schema = {
        "type": "object",
        "required": ["content", "structuredContent", "isError"],
        "properties": {
            "content": {
                "type": "array",
                "minItems": 2,
                "maxItems": 2,
                "prefixItems": [text_content_schema, resource_link_schema],
            },
            "structuredContent": stored_metadata_schema,
            "isError": {"const": False, "type": "boolean"},
        },
        "additionalProperties": True,
    }
    unavailable_result_schema = {
        "type": "object",
        "required": ["content", "structuredContent", "isError"],
        "properties": {
            "content": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "prefixItems": [text_content_schema],
            },
            "structuredContent": unavailable_metadata_schema,
            "isError": {"const": False, "type": "boolean"},
        },
        "additionalProperties": True,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CompactedLargeResultCallToolResult",
        "description": (
            "CallToolResult transport shapes used when resource-mode large-result "
            "compaction is enabled. A cacheable logical output is represented by "
            "retrieval metadata and a resource link; a result entry larger than "
            "the whole cache is represented by a successful RESULT_TOO_LARGE notice "
            "only when that notice is smaller than the inline result. Otherwise the "
            "logical output remains inline. The notice explicitly reports the "
            "unavailable output without marking the already-completed operation as "
            "failed. output_schema "
            "continues to describe the logical tool result."
        ),
        "type": "object",
        "oneOf": [stored_result_schema, unavailable_result_schema],
    }


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
        "large_result_output_schema": _large_result_output_schema(),
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
