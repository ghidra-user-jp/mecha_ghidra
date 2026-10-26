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
            "read_hint",
            "preview",
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
            "read_hint": {"type": "string"},
            "preview": {"type": "string"},
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
            "notice",
        ],
        "properties": {
            "tool": {"type": "string"},
            "target": {"type": "string"},
            "truncated": {"const": True, "type": "boolean"},
            "result_unavailable": {"const": True, "type": "boolean"},
            "operation_succeeded": {"const": True, "type": "boolean"},
            "notice": {"type": "string"},
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
            "retrieval metadata (with the preview and read_hint, which the text "
            "block repeats) and a resource link; a result entry larger than "
            "the whole cache is represented by a successful RESULT_TOO_LARGE notice "
            "(also in text) only when that notice is smaller than the inline result. "
            "Otherwise the logical output remains inline. The notice explicitly "
            "reports the unavailable output without marking the already-completed "
            "operation as failed. output_schema "
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


# tools/list gives every tool the envelopes below in these short forms: they
# only tell the replies apart, and repeated in full for every tool they made
# up four fifths of tools/list.  The docs resources (ghidra://docs/tools/{name})
# keep the full forms.
_SHORT_NOTICE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["truncated"],
    "properties": {"truncated": {"const": True}},
}
_SHORT_DEFERRED_REPLY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["deferred", "operation"],
    "properties": {"deferred": {"const": True}, "operation": {"type": "object", "required": ["operation_id"]}},
}
_SHORT_PRESENTATION_FAILURE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["presentation_failed"],
    "properties": {"presentation_failed": {"const": True}},
}
_SHORT_ERROR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["error"],
    "properties": {"error": {"type": "object"}},
}
_SHORT_SOURCE_SCHEMA: dict[str, Any] = {"type": "object", "required": ["target", "program", "revision"]}

# The program state a core command's result came from (GhidraMCPServer).
_SOURCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target", "program", "revision"],
    "properties": {
        "target": {"type": "string"},
        "program": {"type": ["string", "null"]},
        "revision": {"type": "string"},
    },
    "additionalProperties": False,
}

# A call still running after the deferral wait: get_operation returns its outcome.
_DEFERRED_REPLY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["deferred", "tool", "target", "operation"],
    "properties": {
        "deferred": {"const": True},
        "tool": {"type": "string"},
        "target": {"type": "string"},
        "operation": {
            "type": "object",
            "required": ["operation_id", "kind", "state"],
            "properties": {
                "operation_id": {"type": "string"},
                "kind": {"type": "string"},
                "state": {"type": "string"},
                "poll_after_ms": {"type": "integer"},
            },
        },
        "message": {"type": "string"},
    },
}


def wire_output_schema(
    logical: dict[str, Any],
    *,
    batch: bool = False,
    compactable: bool = True,
    deferrable: bool = False,
    sourced: bool = False,
    replayable: bool = False,
    detailed: bool = True,
) -> dict[str, Any]:
    """Cover logical data, retrieval notices, deferred replies and anticipated tool failures.

    ``compactable=False`` omits the stored-result variants for tools whose
    results are never replaced by a result_id (background-job records).
    ``deferrable`` adds the reply of a call that outlived the deferral wait.
    ``sourced`` lets a result carry the program state it came from, beside
    ``result`` (stored-result notices accept it as additional metadata).
    ``replayable`` lets a resend's reply say ``replayed: true`` beside it:
    the first call's reply, returned again because it carried the same request_id.
    ``detailed=False`` gives every envelope but the logical data its short
    form, which tools/list publishes; the docs resources publish the full one.

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
    elif compactable and detailed:
        variants.extend(branch["properties"]["structuredContent"] for branch in _large_result_output_schema()["oneOf"])
    elif compactable:
        variants.append(_SHORT_NOTICE_SCHEMA)
    # Ordinary values and batch manifests share an explicit result envelope.
    logical_count = 2 if batch else 1
    envelope_properties = {"source": _SOURCE_SCHEMA if detailed else _SHORT_SOURCE_SCHEMA} if sourced else {}
    if replayable:
        envelope_properties["replayed"] = {"const": True}
    variants[:logical_count] = [
        {
            "type": "object",
            "required": ["result"],
            "properties": {"result": variant, **envelope_properties},
            "additionalProperties": False,
        }
        for variant in variants[:logical_count]
    ]
    if deferrable:
        variants.append(_DEFERRED_REPLY_SCHEMA if detailed else _SHORT_DEFERRED_REPLY_SCHEMA)
    if not detailed:
        variants.extend([_SHORT_PRESENTATION_FAILURE_SCHEMA, _SHORT_ERROR_SCHEMA])
        return _schema_document(variants, definitions)
    variants.extend(
        [
            {
                "type": "object",
                "required": [
                    "tool",
                    "target",
                    "operation_succeeded",
                    "result_unavailable",
                    "presentation_failed",
                    "notice",
                ],
                "properties": {
                    "tool": {"type": "string"},
                    "target": {"type": "string"},
                    "operation_succeeded": {"const": True},
                    "result_unavailable": {"const": True},
                    "presentation_failed": {"const": True},
                    "notice": {"type": "string"},
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
    return _schema_document(variants, definitions)


def _schema_document(variants: list[dict[str, Any]], definitions: dict[str, Any] | None) -> dict[str, Any]:
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "anyOf": variants}
    if definitions:
        schema["$defs"] = definitions
    return schema
