"""Every presentation envelope must satisfy the output schema the tool publishes.

``GhidraMCPServer.call_tool`` validates structured output against the
advertised schema after presentation.  If an envelope builder drifts from
``wire_output_schema`` the runtime silently swaps a successful result for a
RESULT_PRESENTATION_FAILED notice, so each builder is checked here directly,
before that runtime fallback can hide the mismatch.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from mcp.types import CallToolResult, TextContent

from ghidra_headless.handlers.commands.batch_read import batch_read
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.batch_results import present_batch_result
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.response_schemas import _large_result_output_schema, wire_output_schema
from ghidra_mcp.presentation.result_compaction import (
    _build_compacted_result,
    _presentation_failure_result,
    _uncacheable_result,
    structured_result,
)
from ghidra_mcp.presentation.result_errors import present_tool_error
from ghidra_mcp.presentation.result_store import ResultResourceStore
from ghidra_mcp.presentation.result_tools import build_result_tools
from ghidra_mcp.presentation.tool_binding import complete_tool_result, error_result
from ghidra_mcp.presentation.tool_registry import build_tool_object


def published_schema(tool_name: str) -> dict:
    return build_tool_object(get_tool_spec(tool_name)).output_schema


def validate(schema: dict, result: CallToolResult) -> None:
    assert result.structured_content is not None
    Draft202012Validator(schema).validate(result.structured_content)


def stored_entry(store: ResultResourceStore, *, text="int main(void) { return 0; }\n" * 500, tool="decompile_function"):
    entry = store.add(tool=tool, target="fw", text=text, mime_type="text/x-c", result_type="string", item_count=None)
    assert entry is not None
    return entry


# --- result_compaction -------------------------------------------------------


@pytest.mark.parametrize("continue_offset", [0, 40])
def test_compacted_stored_result_matches_published_schema(continue_offset):
    entry = stored_entry(ResultResourceStore())
    result = _build_compacted_result(
        entry, preview=entry.text[:40], preview_desc="first 40 chars", continue_offset=continue_offset
    )

    validate(published_schema("decompile_function"), result)
    Draft202012Validator(_large_result_output_schema()).validate(result.model_dump(mode="json", by_alias=True))


def test_uncacheable_result_matches_published_schema():
    result = _uncacheable_result(
        tool_name="list_functions",
        target="fw",
        text="[]" * 4000,
        size_bytes=8000,
        mime_type="application/json",
        result_type="list",
        item_count=4000,
        cache_max_bytes=100,
        cache_max_memory_bytes=None,
    )

    validate(published_schema("list_functions"), result)
    Draft202012Validator(_large_result_output_schema()).validate(result.model_dump(mode="json", by_alias=True))


@pytest.mark.parametrize("tool", ["decompile_function", "batch_read", "run_script"])
def test_presentation_failure_result_matches_published_schema(tool):
    validate(published_schema(tool), _presentation_failure_result(tool, "fw"))


# --- result_errors -----------------------------------------------------------


def _large_error():
    return {
        "code": "SCRIPT_FAILED",
        "message": "failed",
        "retryable": False,
        "details": {"stdout": {"text": "normal output\n" * 4000}, "execution_state": "invalid"},
    }


def _original(error):
    text = json.dumps({"error": error})
    return CallToolResult(
        is_error=True, content=[TextContent(type="text", text=text)], structured_content={"error": error}
    )


def test_inline_tool_error_matches_published_schema():
    error = _large_error()
    result = present_tool_error(
        tool="run_script",
        target="fw",
        error=error,
        original=_original(error),
        config=ToolPresentationConfig(large_result_mode="inline"),
        store=ResultResourceStore(),
    )

    assert result.is_error
    validate(published_schema("run_script"), result)


@pytest.mark.parametrize("cache_max_bytes", [None, 100])
def test_compacted_tool_error_matches_published_schema(cache_max_bytes):
    error = _large_error()
    store = ResultResourceStore() if cache_max_bytes is None else ResultResourceStore(max_bytes=cache_max_bytes)
    result = present_tool_error(
        tool="run_script",
        target="fw",
        error=error,
        original=_original(error),
        config=ToolPresentationConfig(),
        store=store,
    )

    assert result.is_error and result.structured_content["truncated"]
    if cache_max_bytes is None:
        assert "result_id" in result.structured_content
    else:
        assert result.structured_content["result_unavailable"]
    validate(published_schema("run_script"), result)


# --- batch_results -----------------------------------------------------------


def _batch_context():
    program = SimpleNamespace(revision=0)
    program.getModificationNumber = lambda: program.revision
    program.getDomainFile = lambda: SimpleNamespace(getPathname=lambda: "/tiny.bin")
    return SimpleNamespace(generation="generation", program=program)


def _batch(execute, *, count=1):
    requests = [
        {"id": str(index).zfill(32), "tool": "get_function", "arguments": {"address": "0x1000"}}
        for index in range(count)
    ]
    ctx = _batch_context()
    return batch_read({"requests": requests}, ensure_context=lambda: ctx, execute_read=execute)


def _present(result, *, max_output_chars, store=None):
    return present_batch_result(
        result,
        target="fw",
        max_output_chars=max_output_chars,
        config=ToolPresentationConfig(),
        store=store or ResultResourceStore(),
    )


def _raise(*_):
    raise LookupError("x" * 30000)


def test_inline_batch_result_matches_published_schema():
    result = _present(_batch(lambda *_: {"name": "main"}), max_output_chars=8192)

    payload = result.structured_content["result"]
    assert "truncated" not in payload and payload["items"][0]["data"] == {"name": "main"}
    validate(published_schema("batch_read"), result)


def test_compacted_batch_result_with_entry_matches_published_schema():
    result = _present(_batch(lambda *_: {"comment": "x" * 30000}), max_output_chars=2048)

    payload = result.structured_content["result"]
    assert payload["truncated"] and "result_id" in payload
    validate(published_schema("batch_read"), result)


def test_compacted_batch_result_without_entry_matches_published_schema():
    result = _present(
        _batch(lambda *_: {"comment": "x" * 30000}), max_output_chars=2048, store=ResultResourceStore(max_bytes=1)
    )

    payload = result.structured_content["result"]
    assert payload["result_unavailable"] and "result_id" not in payload
    validate(published_schema("batch_read"), result)


@pytest.mark.parametrize("cache_max_bytes", [None, 1])
def test_batch_result_with_omitted_summaries_matches_published_schema(cache_max_bytes):
    store = ResultResourceStore() if cache_max_bytes is None else ResultResourceStore(max_bytes=cache_max_bytes)
    result = _present(_batch(_raise, count=20), max_output_chars=2048, store=store)

    payload = result.structured_content["result"]
    assert result.is_error and payload["item_summaries_omitted"] and payload["items"] == []
    validate(published_schema("batch_read"), result)


# --- tool_binding ------------------------------------------------------------


@pytest.mark.parametrize("tool", ["list_targets", "batch_read", "run_script"])
def test_error_result_matches_published_schema(tool):
    validate(published_schema(tool), error_result(f"Unknown or unpublished tool: {tool}"))


def test_error_result_matches_result_tool_schemas():
    for binding in build_result_tools(store=ResultResourceStore(), config=ToolPresentationConfig()):
        validate(binding.definition.output_schema, error_result("read_result: unknown result_id"))


@pytest.mark.parametrize(
    ("tool", "value"),
    [
        ("list_functions", []),
        ("list_functions", [{"name": "main", "entry": "0x1000"}]),
        ("get_function", {"name": "main", "entry": "0x1000"}),
        ("decompile_function", "int main(void) { return 0; }\n"),
        ("decompile_function", ""),
    ],
)
def test_structured_result_matches_published_schema(tool, value):
    validate(published_schema(tool), structured_result(value))
    validate(published_schema(tool), complete_tool_result(value))


def test_structured_result_for_none_keeps_explicit_envelope():
    # No published tool admits null, so the envelope is checked against the
    # same wrapper the tools use, built over a null-permitting logical schema.
    schema = wire_output_schema({"type": "null"})
    Draft202012Validator.check_schema(schema)
    result = structured_result(None)

    assert result.structured_content == {"result": None}
    validate(schema, result)


def test_normalized_empty_list_result_matches_published_schema():
    raw = CallToolResult(content=[TextContent(type="text", text="[]")])

    validate(published_schema("list_functions"), complete_tool_result(raw))


# --- result_tools ------------------------------------------------------------


def _result_tool_bindings(store):
    read, search = build_result_tools(store=store, config=ToolPresentationConfig())
    assert (read.definition.name, search.definition.name) == ("read_result", "search_result")
    return read, search


def test_read_result_text_payload_matches_its_published_schema():
    store = ResultResourceStore()
    entry = stored_entry(store)
    read, _ = _result_tool_bindings(store)

    for arguments in (
        {"result_id": entry.result_id},
        {"result_id": entry.result_id, "offset_chars": 40, "limit_chars": 8},
    ):
        value = read.function(**arguments)
        result = complete_tool_result(value, compact_json=read.compact_json)
        assert result.structured_content == {"result": json.loads(result.content[0].text)}
        validate(read.definition.output_schema, result)


def test_read_result_json_payload_matches_its_published_schema():
    store = ResultResourceStore()
    items = [{"name": f"function_{index}", "entry": hex(index)} for index in range(5)]
    entry = store.add(
        tool="list_functions",
        target="fw",
        text=json.dumps(items),
        mime_type="application/json",
        result_type="list",
        item_count=len(items),
    )
    read, _ = _result_tool_bindings(store)

    value = read.function(result_id=entry.result_id, mode="json", limit_items=2, fields=["name"])
    result = complete_tool_result(value, compact_json=read.compact_json)

    assert result.structured_content["result"]["items"] == [{"name": "function_0"}, {"name": "function_1"}]
    validate(read.definition.output_schema, result)


@pytest.mark.parametrize("arguments", [{"max_matches": 20}, {"max_matches": 0}, {"merge_context": True}])
def test_search_result_payload_matches_its_published_schema(arguments):
    store = ResultResourceStore()
    entry = stored_entry(store)
    _, search = _result_tool_bindings(store)

    value = asyncio.run(search.function(result_id=entry.result_id, pattern="return", **arguments))
    result = complete_tool_result(value, compact_json=search.compact_json)

    assert result.structured_content["result"]["match_count"] > 0
    validate(search.definition.output_schema, result)
