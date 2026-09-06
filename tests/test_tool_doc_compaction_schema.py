from __future__ import annotations

from jsonschema import Draft202012Validator
from mcp.types import CallToolResult, ResourceLink, TextContent

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.doc_resources import tool_docs_detail
from ghidra_mcp.presentation.result_resources import (
    ResultResourceStore,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.tool_registry import public_output_schema


def test_tool_docs_keep_logical_schema_and_publish_large_result_transport_schema():
    spec = get_tool_spec("decompile_function")

    detail = tool_docs_detail(spec)

    assert detail["output_schema"] == public_output_schema(spec)
    transport_schema = detail["large_result_output_schema"]
    assert transport_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert transport_schema["type"] == "object"
    assert "only when that notice is smaller" in transport_schema["description"]
    assert "Otherwise the logical output remains inline" in transport_schema["description"]
    Draft202012Validator.check_schema(transport_schema)
    assert len(transport_schema["oneOf"]) == 2
    assert all(
        "metadata_truncated" in variant["properties"]["structuredContent"]["required"]
        for variant in transport_schema["oneOf"]
    )
    unavailable_schema = next(
        variant
        for variant in transport_schema["oneOf"]
        if "result_unavailable" in variant["properties"]["structuredContent"]["required"]
    )
    unavailable_metadata = unavailable_schema["properties"]["structuredContent"]
    assert "operation_succeeded" in unavailable_metadata["required"]
    assert unavailable_metadata["properties"]["operation_succeeded"]["const"] is True
    assert unavailable_schema["properties"]["isError"]["const"] is False

    stored_schema = next(
        schema
        for schema in transport_schema["oneOf"]
        if "result_id" in schema["properties"]["structuredContent"]["required"]
    )
    content_schema = stored_schema["properties"]["content"]
    assert content_schema["minItems"] == content_schema["maxItems"] == 2
    assert [item["properties"]["type"]["const"] for item in content_schema["prefixItems"]] == ["text", "resource_link"]

    metadata_schema = stored_schema["properties"]["structuredContent"]
    assert metadata_schema["properties"]["truncated"]["const"] is True
    assert metadata_schema["properties"]["item_count"]["anyOf"] == [
        {"type": "integer", "minimum": 0},
        {"type": "null"},
    ]


def test_large_result_transport_schema_matches_compacted_runtime_result():
    spec = get_tool_spec("decompile_function")
    store = ResultResourceStore(max_entries=2, max_bytes=50_000)
    result = maybe_compact_tool_result(
        tool_name=spec.name,
        target="firmware",
        result="x" * 20_000,
        config=ToolPresentationConfig(),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert isinstance(result.content[0], TextContent)
    assert isinstance(result.content[1], ResourceLink)

    schema = tool_docs_detail(spec)["large_result_output_schema"]
    Draft202012Validator(schema).validate(result.model_dump(mode="json", by_alias=True))
    stored_schema = next(
        variant for variant in schema["oneOf"] if "result_id" in variant["properties"]["structuredContent"]["required"]
    )
    metadata_schema = stored_schema["properties"]["structuredContent"]
    metadata = result.structured_content
    assert metadata is not None
    assert set(metadata_schema["required"]) <= set(metadata)
    assert metadata["truncated"] is metadata_schema["properties"]["truncated"]["const"]
    assert metadata["resource_uri"] == str(result.content[1].uri)
    assert metadata["mime_type"] == result.content[1].mime_type
    assert metadata["item_count"] is None


def test_large_result_transport_schema_matches_uncacheable_runtime_notice():
    spec = get_tool_spec("decompile_function")
    result = maybe_compact_tool_result(
        tool_name=spec.name,
        target="firmware",
        result="x" * 20_000,
        config=ToolPresentationConfig(result_cache_max_bytes=100),
        store=ResultResourceStore(max_entries=2, max_bytes=100),
    )

    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    assert len(result.content) == 1
    assert result.structured_content["result_unavailable"] is True
    assert result.structured_content["operation_succeeded"] is True

    schema = tool_docs_detail(spec)["large_result_output_schema"]
    Draft202012Validator(schema).validate(result.model_dump(mode="json", by_alias=True))
