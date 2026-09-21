"""Schemas for the values carried by MCP structuredContent."""

from typing import Any


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
            "description": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "mimeType": {"anyOf": [{"type": "string"}, {"type": "null"}]},
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
            "continue_offset_chars": {"type": "integer", "minimum": 0},
            "preview_kind": {"enum": ["prefix", "summary"]},
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


def _large_error_output_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["content", "structuredContent", "isError"],
        "properties": {
            "isError": {"const": True},
            "content": {"type": "array", "minItems": 1, "maxItems": 2},
            "structuredContent": {
                "type": "object",
                "required": ["error", "truncated", "read_hint"],
                "properties": {
                    "error": {"type": "object", "required": ["code"]},
                    "truncated": {"const": True},
                    "read_hint": {"type": "string"},
                    "result_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                    "resource_uri": {"type": "string"},
                    "result_unavailable": {"const": True},
                },
                "oneOf": [{"required": ["result_id", "resource_uri"]}, {"required": ["result_unavailable"]}],
            },
        },
        "description": "Large anticipated failures retain isError and status fields; full error details use the result cache.",
    }


def wire_output_schema(logical: dict[str, Any], *, batch: bool = False) -> dict[str, Any]:
    """Cover logical data, retrieval notices and anticipated tool failures.

    $defs stay at the document root because Pydantic references are absolute
    JSON pointers. Moving only the logical schema into anyOf would break them.
    """
    logical = dict(logical)
    definitions = logical.pop("$defs", None)
    variants = [logical]
    if batch:
        variants.append(
            {
                "type": "object",
                "required": ["status", "items", "succeeded_count", "failed_count", "not_run_count", "truncated"],
                "properties": {
                    "status": {"enum": ["ok", "partial", "error"]},
                    "items": {"type": "array", "items": {"type": "object", "required": ["id", "status"]}},
                    "succeeded_count": {"type": "integer", "minimum": 0},
                    "failed_count": {"type": "integer", "minimum": 0},
                    "not_run_count": {"type": "integer", "minimum": 0},
                    "truncated": {"const": True},
                    "result_id": {"type": "string", "pattern": "^[0-9a-f]{16}$"},
                    "resource_uri": {"type": "string"},
                    "result_unavailable": {"const": True},
                },
                "oneOf": [{"required": ["result_id", "resource_uri"]}, {"required": ["result_unavailable"]}],
            }
        )
    else:
        variants.extend(branch["properties"]["structuredContent"] for branch in _large_result_output_schema()["oneOf"])
    # Ordinary values and batch manifests share an explicit result envelope.
    logical_count = 2 if batch else 1
    variants[:logical_count] = [
        {"type": "object", "required": ["result"], "properties": {"result": variant}, "additionalProperties": False}
        for variant in variants[:logical_count]
    ]
    variants.extend(
        [
            {
                "type": "object",
                "required": ["tool", "target", "operation_succeeded", "result_unavailable", "presentation_failed"],
                "properties": {
                    "tool": {"type": "string"},
                    "target": {"type": "string"},
                    "operation_succeeded": {"const": True},
                    "result_unavailable": {"const": True},
                    "presentation_failed": {"const": True},
                },
            },
            {
                "type": "object",
                "required": ["error"],
                "properties": {
                    "error": {
                        "type": "object",
                        "properties": {"message": {"type": "string"}, "code": {"type": "string"}},
                        "anyOf": [{"required": ["message"]}, {"required": ["code"]}],
                    }
                },
            },
        ]
    )
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "anyOf": variants}
    if definitions:
        schema["$defs"] = definitions
    return schema
