from __future__ import annotations

import asyncio
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

import pytest
from mcp.server.fastmcp import Audio, Image
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, ResourceLink, TextContent
from pydantic import BaseModel

from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_tool_spec
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.result_resources import (
    ResultResourceStore,
    _call_tool_result_wire_chars,
    _delivered_inline_size,
    _preview_slice,
    _search_stored_result,
    _serialize_result,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import (
    public_input_schema,
    public_parameter_names,
    select_tool_description,
)


def _run(coro):
    return asyncio.run(coro)


class LargeResultRegistry:
    def call(self, command, params, target):  # noqa: ARG002
        if command == "decompile_function":
            return (
                "int main(void) {\n"
                + ("  return 0;\n" * 20)
                + "}\n/* "
                + ("x" * 2000)
                + " */\n"
            )
        if command == "list_functions":
            return [{"name": f"function_{idx}", "entry": f"0x{idx:x}"} for idx in range(50)]
        return {"status": "ok"}

    def get_project_sync_status(self, target, **kwargs):
        return {
            "target": target,
            "program": kwargs.get("domain_path") or "/main",
            "is_versioned": True,
            "is_checked_out": False,
            "is_checked_out_exclusive": False,
            "is_latest_version": True,
            "modified_since_checkout": False,
            "can_add_to_repository": False,
            "can_checkout": True,
            "can_checkin": False,
            "can_merge": False,
            "is_hijacked": False,
            "version": 1,
            "latest_version": 1,
            "checkout_status": None,
            "checkouts": [{"user": "alice", "note": "x" * 80} for _ in range(10)],
            "shared_project_url": None,
        }


def _store_entry_kwargs(text: str) -> dict:
    return {
        "tool": "custom_tool",
        "target": "fw",
        "text": text,
        "mime_type": "text/plain",
        "result_type": "string",
        "item_count": None,
    }


def _runtime_for_specs(specs, *, config: ToolPresentationConfig | None = None, registry=None):
    effective_registry = registry or LargeResultRegistry()
    return create_mcp_server(
        specs=specs,
        registry_provider=lambda: effective_registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=config,
    )


def _compacted_decompile_runtime():
    return _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=40,
            large_result_preview_chars=25,
        ),
    )


def test_tool_description_mode_short_uses_explicit_short_description():
    base_spec = get_tool_spec("create_session")
    short_spec = replace(base_spec, short_description="Open one Ghidra target session.")
    runtime = _runtime_for_specs(
        {"create_session": short_spec},
        config=ToolPresentationConfig(description_mode="short"),
    )

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    assert tools["create_session"].description == "Open one Ghidra target session."
    assert tools["create_session"].description != base_spec.description


def test_short_description_caps_long_single_sentence():
    from ghidra_mcp.presentation.tool_registry import (
        _SHORT_DESCRIPTION_MAX_CHARS,
        _first_sentence_or_truncate,
    )

    # One sentence (terminator only at the very end), well over the cap.
    long_sentence = "Do the thing " * 30 + "now."
    out = _first_sentence_or_truncate(long_sentence)

    assert len(out) <= _SHORT_DESCRIPTION_MAX_CHARS
    assert out.endswith("...")


def test_short_description_skips_abbreviations():
    from ghidra_mcp.presentation.tool_registry import _first_sentence_or_truncate

    text = "Set bytes at addr, e.g. 0x401000, using a hex string. Destructive."
    out = _first_sentence_or_truncate(text)

    assert out == "Set bytes at addr, e.g. 0x401000, using a hex string."


def test_short_description_abbreviation_needs_word_boundary():
    from ghidra_mcp.presentation.tool_registry import _first_sentence_or_truncate

    # "transactional." merely ends with the "al." suffix — it is a real
    # sentence boundary, not an abbreviation like "et al.".
    text = "The operation is transactional. Later sentences must not leak in."
    assert _first_sentence_or_truncate(text) == "The operation is transactional."

    text = "See Smith et al. for details on the algorithm. Second sentence."
    assert (
        _first_sentence_or_truncate(text)
        == "See Smith et al. for details on the algorithm."
    )


def test_short_description_handles_cjk_sentences_without_trailing_space():
    from ghidra_mcp.presentation.tool_registry import _first_sentence_or_truncate

    # Japanese never puts a space after 。so the terminator alone must end the
    # sentence instead of falling through to a 180-char hard cut.
    text = "指定した関数を逆コンパイルします。大きな出力はresult_idとして保存されます。" * 5
    assert _first_sentence_or_truncate(text) == "指定した関数を逆コンパイルします。"


def test_short_mode_never_exceeds_cap_for_any_spec():
    from ghidra_mcp.presentation.tool_registry import _SHORT_DESCRIPTION_MAX_CHARS

    for name in cli._ALL_TOOL_SPECS:
        short = select_tool_description(get_tool_spec(name), "short")
        if short is not None:
            assert len(short) <= _SHORT_DESCRIPTION_MAX_CHARS, name


def test_tool_description_mode_full_uses_existing_description():
    spec = get_tool_spec("create_session")
    runtime = _runtime_for_specs(
        {"create_session": spec},
        config=ToolPresentationConfig(description_mode="full"),
    )

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    assert tools["create_session"].description == spec.description


def test_default_description_mode_is_full_without_filler():
    assert ToolPresentationConfig().description_mode == "full"

    bare_spec = replace(get_tool_spec("create_session"), description=None, short_description=None)
    assert select_tool_description(bare_spec, "short") is None
    assert select_tool_description(bare_spec, "full") is None

    runtime = _runtime_for_specs({"create_session": bare_spec})
    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    assert tools["create_session"].description is None


def test_tool_description_mode_none_omits_description_but_keeps_annotations():
    specs = {
        "list_targets": get_tool_spec("list_targets"),
        "close_session_and_remove_program": get_tool_spec("close_session_and_remove_program"),
    }
    runtime = _runtime_for_specs(specs, config=ToolPresentationConfig(description_mode="none"))

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    assert tools["list_targets"].description is None
    assert tools["list_targets"].annotations.readOnlyHint is True
    assert tools["list_targets"].annotations.idempotentHint is True
    assert tools["close_session_and_remove_program"].annotations.destructiveHint is True


@pytest.mark.parametrize("mode", ["short", "full", "none"])
def test_annotations_survive_all_description_modes(mode):
    specs = {
        "list_targets": get_tool_spec("list_targets"),
        "create_session": get_tool_spec("create_session"),
        "close_session_and_remove_program": get_tool_spec("close_session_and_remove_program"),
    }
    runtime = _runtime_for_specs(specs, config=ToolPresentationConfig(description_mode=mode))

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    assert tools["list_targets"].annotations.readOnlyHint is True
    assert tools["list_targets"].annotations.idempotentHint is True
    assert tools["create_session"].annotations.idempotentHint is False
    assert tools["close_session_and_remove_program"].annotations.destructiveHint is True


def test_tool_docs_resources_only_include_exposed_specs():
    specs = {"list_targets": get_tool_spec("list_targets")}
    runtime = _runtime_for_specs(specs)

    index_contents = _run(runtime.mcp.read_resource("ghidra://docs/tools"))
    index = json.loads(index_contents[0].content)
    detail_contents = _run(runtime.mcp.read_resource("ghidra://docs/tools/list_targets"))
    detail = json.loads(detail_contents[0].content)

    assert index_contents[0].mime_type == "application/json"
    assert [tool["name"] for tool in index["tools"]] == ["list_targets"]
    assert "create_session" not in {tool["name"] for tool in index["tools"]}
    assert detail["name"] == "list_targets"
    assert detail["description"] == get_tool_spec("list_targets").description
    assert detail["short_description"] == select_tool_description(get_tool_spec("list_targets"), "short")
    assert detail["input_schema"]
    assert detail["output_schema"]
    assert detail["annotations"]["readOnlyHint"] is True
    assert detail["checkout_required"] is False


def test_server_instructions_advertise_docs_and_result_tools():
    specs = {"list_targets": get_tool_spec("list_targets")}

    resource_runtime = _runtime_for_specs(specs)
    assert "ghidra://docs/tools" in resource_runtime.mcp.instructions
    assert "read_result" in resource_runtime.mcp.instructions
    assert "search_result" in resource_runtime.mcp.instructions

    inline_runtime = _runtime_for_specs(
        specs, config=ToolPresentationConfig(large_result_mode="inline")
    )
    assert "ghidra://docs/tools" in inline_runtime.mcp.instructions
    assert "read_result" not in inline_runtime.mcp.instructions


def test_result_tools_registered_only_in_resource_mode():
    specs = {"list_targets": get_tool_spec("list_targets")}

    resource_names = {tool.name for tool in _run(_runtime_for_specs(specs).mcp.list_tools())}
    assert {"read_result", "search_result"} <= resource_names

    inline_runtime = _runtime_for_specs(
        specs, config=ToolPresentationConfig(large_result_mode="inline")
    )
    inline_names = {tool.name for tool in _run(inline_runtime.mcp.list_tools())}
    assert "read_result" not in inline_names
    assert "search_result" not in inline_names


def test_search_result_schema_publishes_pattern_length_limit():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    for tool_name in ("read_result", "search_result"):
        result_id_schema = tools[tool_name].inputSchema["properties"]["result_id"]
        assert result_id_schema["minLength"] == 16
        assert result_id_schema["maxLength"] == 16
        assert result_id_schema["pattern"] == "^[0-9a-f]{16}$"
    properties = tools["search_result"].inputSchema["properties"]
    assert properties["pattern"]["maxLength"] == 512
    assert properties["context_chars"]["minimum"] == 0
    assert properties["context_chars"]["maximum"] == 2000
    assert properties["max_matches"]["minimum"] == 0
    assert properties["max_matches"]["maximum"] == 100


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("read_result", {"result_id": "not-a-result-id"}),
        (
            "search_result",
            {"result_id": "not-a-result-id", "pattern": "text"},
        ),
    ],
)
def test_result_tools_reject_unbounded_or_malformed_result_ids(tool_name, arguments):
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})

    with pytest.raises(ToolError):
        _run(runtime.mcp.call_tool(tool_name, arguments))


def test_search_result_description_discloses_count_scan_cap():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})

    tools = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}
    description = tools["search_result"].description

    assert "10,000-match scan cap" in description
    assert "scan_truncated" in description


@pytest.mark.parametrize(
    "arguments",
    [
        {"context_chars": 2001},
        {"context_chars": -1},
        {"max_matches": 101},
        {"max_matches": -1},
    ],
)
def test_search_result_rejects_values_outside_published_limits(arguments):
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    entry = runtime.result_store.add(**_store_entry_kwargs("plain text"))

    with pytest.raises(ToolError):
        _run(
            runtime.mcp.call_tool(
                "search_result",
                {"result_id": entry.result_id, "pattern": "text", **arguments},
            )
        )


def test_large_string_result_returns_preview_resource_link_and_readable_resource():
    runtime = _compacted_decompile_runtime()

    result = runtime.tools["decompile_function"](name="main", target="fw")

    assert isinstance(result, CallToolResult)
    assert isinstance(result.content[0], TextContent)
    assert isinstance(result.content[1], ResourceLink)
    meta = result.structuredContent
    assert meta["truncated"] is True
    assert meta["tool"] == "decompile_function"
    assert meta["target"] == "fw"
    assert meta["mime_type"] == "text/x-c"
    assert "preview" not in meta
    assert meta["resource_uri"].endswith(meta["result_id"])
    assert result.content[1].mimeType == "text/x-c"

    resource_contents = _run(runtime.mcp.read_resource(meta["resource_uri"]))
    full_text = resource_contents[0].content
    assert resource_contents[0].mime_type == "text/x-c"
    assert "int main(void)" in full_text
    assert full_text.count("return 0;") == 20
    assert result.content[1].size == len(full_text.encode("utf-8"))

    notice = result.content[0].text
    assert f"read_result(result_id='{meta['result_id']}', offset_chars={meta['preview_chars']})" in notice
    assert f"search_result(result_id='{meta['result_id']}'" in notice
    preview = notice.split("----- preview -----\n", 1)[1]
    assert preview == full_text[: meta["preview_chars"]]


def test_unicode_payload_round_trips_with_utf8_cache_accounting():
    payload = ("解析🔐e\u0301\n" * 2_000) + "終端"
    store = ResultResourceStore(max_entries=4, max_bytes=1_000_000)

    first = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="ファームウェア🔒",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=200,
            large_result_preview_chars=80,
        ),
        store=store,
    )
    second = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="ファームウェア🔒",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=200,
            large_result_preview_chars=80,
        ),
        store=store,
    )

    assert isinstance(first, CallToolResult)
    assert isinstance(second, CallToolResult)
    assert first.structuredContent["result_id"] == second.structuredContent["result_id"]
    entry = store.get(first.structuredContent["result_id"])
    assert entry.text == payload
    assert entry.size_chars == len(payload)
    assert entry.size_bytes == len(payload.encode("utf-8"))
    assert first.structuredContent["size_chars"] == len(payload)


def test_large_list_result_is_stored_as_json_resource():
    runtime = _runtime_for_specs(
        {"list_functions": get_tool_spec("list_functions")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=80,
            large_result_preview_chars=30,
        ),
    )

    result = runtime.tools["list_functions"](target="fw")

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["result_type"] == "list"
    assert result.structuredContent["item_count"] == 50
    assert result.structuredContent["mime_type"] == "application/json"
    resource_contents = _run(runtime.mcp.read_resource(result.structuredContent["resource_uri"]))
    assert resource_contents[0].mime_type == "application/json"
    payload = json.loads(resource_contents[0].content)
    assert payload[0]["name"] == "function_0"
    assert payload[-1]["name"] == "function_49"


def test_call_tool_end_to_end_preserves_resource_link():
    runtime = _compacted_decompile_runtime()

    result = _run(runtime.mcp.call_tool("decompile_function", {"name": "main", "target": "fw"}))

    assert isinstance(result, CallToolResult)
    assert isinstance(result.content[0], TextContent)
    assert isinstance(result.content[1], ResourceLink)
    assert result.structuredContent["truncated"] is True


def _call_result_tool(runtime, name, arguments):
    # read_result/search_result are registered with structured_output=False so
    # each response is delivered once, as JSON text; parse that single copy.
    content = _run(runtime.mcp.call_tool(name, arguments))
    assert len(content) == 1
    return content, json.loads(content[0].text)


def test_read_result_pages_through_stored_result():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent
    full_text = _run(runtime.mcp.read_resource(meta["resource_uri"]))[0].content

    content, first = _call_result_tool(
        runtime, "read_result", {"result_id": meta["result_id"], "limit_chars": 10}
    )
    assert first["chunk"] == full_text[:10]
    assert first["chunk_chars"] == 10
    assert first["total_chars"] == len(full_text)
    assert first["has_more"] is True
    assert first["next_offset_chars"] == 10
    assert first["mime_type"] == "text/x-c"

    _, second = _call_result_tool(
        runtime,
        "read_result",
        {"result_id": meta["result_id"], "offset_chars": 10, "limit_chars": 10},
    )
    assert second["chunk"] == full_text[10:20]

    _, tail = _call_result_tool(
        runtime,
        "read_result",
        {"result_id": meta["result_id"], "offset_chars": len(full_text)},
    )
    assert tail["chunk"] == ""
    assert tail["has_more"] is False
    assert tail["next_offset_chars"] is None


def test_read_result_clamps_limit_to_threshold():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent

    content, sliced = _call_result_tool(
        runtime,
        "read_result",
        {"result_id": meta["result_id"], "limit_chars": 500_000},
    )

    # The raw request is capped at the configured threshold. Infrastructure
    # responses use a 1024-char minimum so metadata remains usable when tests or
    # operators choose an impractically small threshold.
    assert 0 < sliced["chunk_chars"] <= 40
    assert len(content[0].text) <= 1024
    assert sliced["has_more"] is True


def test_read_result_default_page_tracks_threshold():
    runtime = _compacted_decompile_runtime()  # threshold 40 -> default page 13
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent
    full_text = _run(runtime.mcp.read_resource(meta["resource_uri"]))[0].content

    _, page = _call_result_tool(runtime, "read_result", {"result_id": meta["result_id"]})

    assert page["chunk_chars"] == 13
    assert page["chunk"] == full_text[:13]


def test_read_result_unknown_id_is_actionable_error():
    runtime = _compacted_decompile_runtime()

    with pytest.raises(ToolError, match="Do not automatically re-run"):
        _run(runtime.mcp.call_tool("read_result", {"result_id": "deadbeefdeadbeef"}))


def test_store_rejects_malformed_result_id_without_echoing_it():
    store = ResultResourceStore(max_entries=4)
    attacker_controlled = "SECRET-" + ("x" * 10_000)

    with pytest.raises(KeyError) as exc_info:
        store.get(attacker_controlled)

    assert "16 lowercase hexadecimal" in str(exc_info.value)
    assert attacker_controlled not in str(exc_info.value)


def test_search_result_returns_matches_with_usable_offsets():
    # Threshold above the snippet budget needed for 5 matches, below the payload size.
    runtime = _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=1500,
            large_result_preview_chars=25,
        ),
    )
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent
    full_text = _run(runtime.mcp.read_resource(meta["resource_uri"]))[0].content

    content, found = _call_result_tool(
        runtime,
        "search_result",
        {
            "result_id": meta["result_id"],
            "pattern": r"return 0;",
            "context_chars": 10,
            "max_matches": 5,
        },
    )

    assert found["match_count"] == 20
    assert found["matches_shown"] == 5
    assert found["scan_truncated"] is False
    offsets = [match["offset_chars"] for match in found["matches"]]
    assert offsets == sorted(offsets)
    first = found["matches"][0]
    assert full_text[first["offset_chars"] : first["offset_chars"] + len("return 0;")] == "return 0;"
    assert first["end_offset"] == first["offset_chars"] + len("return 0;")
    assert first["match_chars"] == len("return 0;")
    assert first["match_truncated"] is False
    assert "return 0;" in first["context"]
    assert first["context"] == full_text[
        first["context_offset_chars"] : first["context_offset_chars"] + len(first["context"])
    ]


def test_search_result_caps_snippets_at_response_budget():
    runtime = _compacted_decompile_runtime()  # threshold (= response budget) of 40 chars
    compacted = runtime.tools["decompile_function"](name="main", target="fw")

    content, found = _call_result_tool(
        runtime,
        "search_result",
        {
            "result_id": compacted.structuredContent["result_id"],
            "pattern": r"return 0;",
            "context_chars": 10,
            "max_matches": 20,
        },
    )

    assert found["match_count"] == 20
    assert 0 < found["matches_shown"] < 20
    assert len(content[0].text) <= 1024


def test_search_result_count_only_with_zero_max_matches():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")

    content, found = _call_result_tool(
        runtime,
        "search_result",
        {
            "result_id": compacted.structuredContent["result_id"],
            "pattern": r"return 0;",
            "max_matches": 0,
        },
    )

    assert found["match_count"] == 20
    assert found["matches_shown"] == 0
    assert found["matches"] == []
    # A count-only query costs a small constant, not snippet budget.
    assert len(content[0].text) < 400


def test_search_result_count_only_reports_when_scan_cap_is_reached():
    store = ResultResourceStore(max_entries=4)
    entry = store.add(**_store_entry_kwargs("x" * 10_001))

    found = _search_stored_result(
        entry,
        pattern="x",
        context_chars=0,
        max_matches=0,
        configured_budget=12_000,
    )

    assert found["match_count"] == 10_000
    assert found["matches"] == []
    assert found["scan_truncated"] is True


def test_search_result_invalid_regex_is_error():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")

    with pytest.raises(ToolError, match="Invalid regex pattern"):
        _run(
            runtime.mcp.call_tool(
                "search_result",
                {"result_id": compacted.structuredContent["result_id"], "pattern": "("},
            )
        )


def test_small_result_is_not_resourceized():
    runtime = _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(large_result_threshold_chars=10000),
        registry=LargeResultRegistry(),
    )

    result = runtime.tools["decompile_function"](name="main", target="fw")

    assert isinstance(result, str)
    assert "int main(void)" in result


def test_large_result_inline_mode_returns_original_payload():
    runtime = _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(
            large_result_mode="inline",
            large_result_threshold_chars=40,
            large_result_preview_chars=25,
        ),
    )

    result = runtime.tools["decompile_function"](name="main", target="fw")

    assert isinstance(result, str)
    assert result.count("return 0;") == 20


def test_error_call_tool_result_is_not_resourceized():
    store = ResultResourceStore(max_entries=4)
    error_result = CallToolResult(
        isError=True,
        content=[TextContent(type="text", text="x" * 100)],
    )

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=error_result,
        config=ToolPresentationConfig(large_result_threshold_chars=10, large_result_preview_chars=5),
        store=store,
    )

    assert result is error_result


def test_large_successful_call_tool_result_is_resourceized():
    store = ResultResourceStore(max_entries=4)
    full_text = "success\n" + ("payload\n" * 300)
    call_result = CallToolResult(
        content=[TextContent(type="text", text=full_text)],
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=call_result,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result is not call_result
    meta = result.structuredContent
    assert meta["result_type"] == "call_tool_result_text"
    preview = result.content[0].text.split("----- preview -----\n", 1)[1]
    assert preview == full_text[: meta["preview_chars"]]
    assert store.read_text(meta["result_id"]) == full_text


def test_call_tool_result_with_structured_content_is_fully_serialized():
    store = ResultResourceStore(max_entries=4)
    call_result = CallToolResult(
        content=[TextContent(type="text", text="x" * 3000)],
        structuredContent={"answer": 42},
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=call_result,
        config=ToolPresentationConfig(large_result_threshold_chars=20, large_result_preview_chars=12),
        store=store,
    )

    meta = result.structuredContent
    assert meta["result_type"] == "call_tool_result"
    stored = json.loads(store.read_text(meta["result_id"]))
    assert stored["structuredContent"] == {"answer": 42}


def test_call_tool_result_metadata_and_content_annotations_are_preserved():
    store = ResultResourceStore(max_entries=4)
    call_result = CallToolResult(
        content=[
            TextContent(
                type="text",
                text="x" * 4000,
                annotations={"audience": ["user"], "priority": 0.5},
                _meta={"block": "preserve"},
            )
        ],
        _meta={"result": "preserve"},
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=call_result,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["result_type"] == "call_tool_result"
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["_meta"] == {"result": "preserve"}
    assert stored["content"][0]["_meta"] == {"block": "preserve"}
    assert stored["content"][0]["annotations"] == {
        "audience": ["user"],
        "priority": 0.5,
    }


def test_single_text_content_is_stored_as_fastmcp_visible_text():
    store = ResultResourceStore(max_entries=4)
    content = TextContent(type="text", text="payload\n" * 500)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=content,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["result_type"] == "text_content"
    assert store.read_text(result.structuredContent["result_id"]) == content.text


def test_annotated_text_content_is_stored_structurally():
    store = ResultResourceStore(max_entries=4)
    content = TextContent(
        type="text",
        text="payload\n" * 500,
        annotations={"audience": ["assistant"]},
        _meta={"source": "analysis"},
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=content,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert result.structuredContent["result_type"] == "text_content_block"
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["text"] == content.text
    assert stored["annotations"]["audience"] == ["assistant"]
    assert stored["_meta"] == {"source": "analysis"}


def test_forward_compatible_text_content_fields_are_preserved():
    store = ResultResourceStore(max_entries=4)
    content = TextContent(type="text", text="x" * 4000, future_field="preserve")

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=content,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["text"] == content.text
    assert stored["future_field"] == "preserve"


def test_forward_compatible_call_result_fields_are_preserved():
    store = ResultResourceStore(max_entries=4)
    original = CallToolResult(
        content=[TextContent(type="text", text="x" * 4000)],
        future_outer="preserve",
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=original,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["future_outer"] == "preserve"
    assert stored["content"][0]["text"] == "x" * 4000


@pytest.mark.parametrize(
    ("helper", "block_type", "mime_type"),
    [
        (Image(data=b"i" * 4096, format="png"), "image", "image/png"),
        (Audio(data=b"a" * 4096, format="wav"), "audio", "audio/wav"),
    ],
)
def test_fastmcp_binary_helpers_are_compacted_as_content_blocks(
    helper, block_type, mime_type
):
    store = ResultResourceStore(max_entries=4)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=helper,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["type"] == block_type
    assert stored["mimeType"] == mime_type
    expected_byte = b"i" if block_type == "image" else b"a"
    assert base64.b64decode(stored["data"]) == expected_byte * 4096


def test_fastmcp_binary_helper_is_converted_exactly_once():
    class OneShotImage(Image):
        calls = 0

        def to_image_content(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("image helper converted more than once")
            return super().to_image_content()

    helper = OneShotImage(data=b"x" * 4096)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=helper,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=ResultResourceStore(max_entries=4),
    )

    assert isinstance(result, CallToolResult)
    assert helper.calls == 1


def test_compaction_fault_after_binary_conversion_returns_prepared_block(monkeypatch):
    from ghidra_mcp.presentation import result_resources

    class OneShotImage(Image):
        calls = 0

        def to_image_content(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("image helper converted more than once")
            return super().to_image_content()

    helper = OneShotImage(data=b"x" * 4096)

    def fail_after_preparation(*_args, **_kwargs):
        raise RuntimeError("presentation fault")

    monkeypatch.setattr(result_resources, "_serialize_result", fail_after_preparation)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=helper,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=ResultResourceStore(max_entries=4),
    )

    # FastMCP can pass this block through directly. Returning the original
    # helper here would make FastMCP call its one-shot adapter a second time.
    assert result is not helper
    assert result.type == "image"
    assert helper.calls == 1


def test_partial_binary_preparation_failure_returns_safe_completed_notice():
    class OneShotImage(Image):
        calls = 0

        def to_image_content(self):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("image helper converted more than once")
            return super().to_image_content()

    class BrokenImage(Image):
        calls = 0

        def to_image_content(self):
            self.calls += 1
            raise RuntimeError("image conversion failed")

    prepared = OneShotImage(data=b"x" * 4096)
    broken = BrokenImage(data=b"y" * 4096)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=[prepared, broken],
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=ResultResourceStore(max_entries=4),
    )

    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert result.structuredContent["operation_succeeded"] is True
    assert result.structuredContent["result_unavailable"] is True
    assert result.structuredContent["presentation_failed"] is True
    assert prepared.calls == 1
    assert broken.calls == 1


def test_compaction_normalizes_unpaired_unicode_surrogates():
    store = ResultResourceStore(max_entries=4)
    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result={"bad": "\ud800" * 5000},
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    result.model_dump_json(by_alias=True, exclude_none=True)
    stored = store.read_text(result.structuredContent["result_id"])
    assert "\ud800" not in stored
    assert "\ufffd" in stored


def test_compaction_normalizes_surrogates_inside_call_tool_result():
    raw = CallToolResult(
        content=[TextContent(type="text", text="bad:\ud800 pair:\ud83d\ude00")],
        structuredContent={"nested": ["\udfff"]},
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=raw,
        config=ToolPresentationConfig(large_result_threshold_chars=10_000),
        store=ResultResourceStore(max_entries=4),
    )

    assert isinstance(result, CallToolResult)
    assert result is not raw
    assert result.content[0].text == "bad:\ufffd pair:\U0001f600"
    assert result.structuredContent == {"nested": ["\ufffd"]}
    result.model_dump_json(by_alias=True, exclude_none=True)


def test_mixed_content_list_is_stored_as_fastmcp_wire_blocks():
    store = ResultResourceStore(max_entries=4)
    result_value = [{"status": "ok"}, Image(data=b"x" * 4096)]

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=result_value,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=20,
        ),
        store=store,
    )

    assert result.structuredContent["result_type"] == "content_blocks"
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert [block["type"] for block in stored] == ["text", "image"]
    assert json.loads(stored[0]["text"]) == {"status": "ok"}
    assert base64.b64decode(stored[1]["data"]) == b"x" * 4096


def test_pydantic_model_is_stored_as_structural_json_not_repr():
    class ResultModel(BaseModel):
        status: str
        payload: str

    store = ResultResourceStore(max_entries=4)
    model = ResultModel(status="ok", payload="x" * 4000)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=model,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["result_type"] == "pydantic_model"
    assert json.loads(store.read_text(result.structuredContent["result_id"])) == {
        "status": "ok",
        "payload": "x" * 4000,
    }


def test_dataclass_is_stored_as_structural_json_not_repr():
    @dataclass
    class ResultRecord:
        status: str
        payload: str

    store = ResultResourceStore(max_entries=4)
    record = ResultRecord(status="ok", payload="x" * 4000)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=record,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=12,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["result_type"] == "ResultRecord"
    assert json.loads(store.read_text(result.structuredContent["result_id"])) == {
        "status": "ok",
        "payload": "x" * 4000,
    }


def test_preview_budget_scales_by_result_type():
    from ghidra_mcp.presentation.result_resources import _preview_budget

    # Text payloads front-load meaning and keep the full configured budget;
    # JSON containers only need a few example items/entries; full
    # CallToolResult dumps sit between.
    assert _preview_budget("string", 4000) == 4000
    assert _preview_budget("call_tool_result_text", 4000) == 4000
    assert _preview_budget("list", 4000) == 1000
    assert _preview_budget("dict", 4000) == 1000
    assert _preview_budget("call_tool_result", 4000) == 2000


def test_list_preview_shows_complete_items_as_valid_json():
    store = ResultResourceStore(max_entries=4)
    data = [{"name": f"fn_{i:04d}", "entry": f"0x{i:06x}"} for i in range(3000)]

    result = maybe_compact_tool_result(
        tool_name="list_functions",
        target="fw",
        result=data,
        config=ToolPresentationConfig(),  # preview 4000 -> list budget 1000
        store=store,
    )

    notice = result.content[0].text
    preview = notice.split("----- preview -----\n", 1)[1]
    items = json.loads(preview)  # complete items, parseable as-is
    assert 0 < len(items) < len(data)
    assert items == data[: len(items)]
    assert len(preview) <= 1000
    assert f"showing the first {len(items)} of 3000 items" in notice

    # The advertised continuation offset resumes exactly after the previewed
    # items in the stored compact JSON.
    stored = store.read_text(result.structuredContent["result_id"])
    offset = int(notice.split("offset_chars=", 1)[1].split(")", 1)[0])
    assert stored[:offset] + "]" == preview


def test_dict_preview_shows_complete_entries_as_valid_json():
    store = ResultResourceStore(max_entries=4)
    data = {f"segment_{i:03d}": {"start": f"0x{i:06x}", "perms": "rwx"} for i in range(400)}

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=data,
        config=ToolPresentationConfig(),  # preview 4000 -> dict budget 1000
        store=store,
    )

    notice = result.content[0].text
    preview = notice.split("----- preview -----\n", 1)[1]
    entries = json.loads(preview)  # complete entries, parseable as-is
    assert 0 < len(entries) < len(data)
    assert all(data[key] == value for key, value in entries.items())
    assert len(preview) <= 1000
    assert f"showing the first {len(entries)} of 400 entries" in notice
    assert result.structuredContent["item_count"] == 400

    stored = store.read_text(result.structuredContent["result_id"])
    offset = int(notice.split("offset_chars=", 1)[1].split(")", 1)[0])
    assert stored[:offset] + "}" == preview


def test_dict_subclass_preview_uses_the_same_order_as_stored_payload():
    class ReverseItemsDict(dict):
        def items(self):
            return reversed(tuple(super().items()))

    data = ReverseItemsDict(
        (f"k{index:03d}", "value") for index in range(200)
    )
    store = ResultResourceStore(max_entries=4)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=100,
        ),
        store=store,
    )

    notice = result.content[0].text
    preview = notice.split("----- preview -----\n", 1)[1]
    stored = store.read_text(result.structuredContent["result_id"])
    offset = int(notice.split("offset_chars=", 1)[1].split(")", 1)[0])
    assert list(json.loads(preview)) == ["k000"]
    assert stored[:offset] + "}" == preview


def test_list_subclass_is_materialized_once_for_storage_and_preview():
    class ReverseList(list):
        def __iter__(self):
            return reversed(self)

    data = ReverseList({"name": f"item_{index:03d}"} for index in range(200))
    store = ResultResourceStore(max_entries=4)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=100,
        ),
        store=store,
    )

    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    notice = result.content[0].text
    preview = json.loads(notice.split("----- preview -----\n", 1)[1])
    assert stored[0] == {"name": "item_199"}
    assert preview == stored[: len(preview)]


def test_list_preview_falls_back_to_prefix_when_one_item_exceeds_budget():
    store = ResultResourceStore(max_entries=4)
    data = [{"blob": "x" * 500} for _ in range(40)]

    result = maybe_compact_tool_result(
        tool_name="list_functions",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=1000, large_result_preview_chars=100
        ),
        store=store,
    )

    notice = result.content[0].text
    preview = notice.split("----- preview -----\n", 1)[1]
    stored = store.read_text(result.structuredContent["result_id"])
    assert len(preview) <= 25  # list budget: a quarter of 100
    assert preview == stored[: len(preview)]


def test_preview_prefers_line_boundary():
    text = "line one\nline two\nline three\n"

    assert _preview_slice(text, 20) == "line one\nline two"
    assert _preview_slice("x" * 30, 20) == "x" * 20
    assert _preview_slice(text, len(text)) == text
    assert _preview_slice(text, 0) == ""


def test_store_deduplicates_identical_payloads():
    store = ResultResourceStore(max_entries=8, max_bytes=10_000)

    first = store.add(**_store_entry_kwargs("a" * 50))
    second = store.add(**_store_entry_kwargs("a" * 50))

    assert first.result_id == second.result_id
    assert store.get(first.result_id).text == "a" * 50


def test_store_identity_includes_result_metadata():
    store = ResultResourceStore(max_entries=8, max_bytes=10_000)
    common = _store_entry_kwargs('[{"name":"main"}]')

    as_list = store.add(**{**common, "result_type": "list", "item_count": 1})
    as_call_result = store.add(
        **{**common, "result_type": "call_tool_result", "item_count": 2}
    )

    assert as_list.result_id != as_call_result.result_id
    assert store.get(as_list.result_id).result_type == "list"
    assert store.get(as_call_result.result_id).result_type == "call_tool_result"


def test_store_byte_budget_evicts_oldest_but_keeps_newest():
    store = ResultResourceStore(max_entries=8, max_bytes=400)

    first = store.add(**_store_entry_kwargs("a" * 100))
    second = store.add(**_store_entry_kwargs("b" * 100))

    assert store.get(second.result_id).text == "b" * 100
    with pytest.raises(KeyError, match="Do not automatically re-run"):
        store.get(first.result_id)

    # A single payload larger than the whole budget is refused outright —
    # caching it would exceed the operator-configured memory cap — and the
    # existing entries stay untouched.
    assert store.add(**_store_entry_kwargs("c" * 500)) is None
    assert store.get(second.result_id).text == "b" * 100


def test_store_byte_budget_includes_retained_metadata_but_reports_payload_size():
    store = ResultResourceStore(max_entries=8, max_bytes=512)
    kwargs = _store_entry_kwargs("x")
    kwargs["target"] = "target" * 1000

    assert store.add(**kwargs) is None

    entry = store.add(**_store_entry_kwargs("x"))
    assert entry.size_bytes == 1
    assert entry.cache_size_bytes > entry.size_bytes
    assert store._total_bytes == entry.cache_size_bytes


def test_store_concurrent_add_and_get_keeps_lru_accounting_consistent():
    store = ResultResourceStore(max_entries=256, max_bytes=1_000_000)

    def round_trip(index: int) -> str:
        entry = store.add(**_store_entry_kwargs(f"payload-{index}" * 10))
        assert entry is not None
        return store.get(entry.result_id).text

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(round_trip, range(200)))

    assert len(results) == 200
    assert len(store._entries) == 200
    assert store._total_bytes == sum(
        entry.cache_size_bytes for entry in store._entries.values()
    )


def test_payload_over_cache_budget_returns_successful_unavailable_result():
    store = ResultResourceStore(max_entries=8, max_bytes=100)
    payload = "x" * 5000

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(large_result_threshold_chars=50, large_result_preview_chars=25),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert result.structuredContent["result_unavailable"] is True
    assert result.structuredContent["operation_succeeded"] is True
    assert result.structuredContent["size_chars"] == len(payload)
    assert payload not in result.content[0].text
    assert "RESULT_TOO_LARGE" in result.content[0].text
    assert "Do not re-run a non-idempotent tool" in result.content[0].text


def test_uncacheable_output_does_not_report_a_completed_mutation_as_failed():
    calls = 0

    def mutating_dispatcher(name, args, target, *, registry):  # noqa: ARG001
        nonlocal calls
        calls += 1
        return "mutation completed\n" + ("x" * 5_000)

    runtime = create_mcp_server(
        specs={"set_bytes": get_tool_spec("set_bytes")},
        registry_provider=lambda: object(),
        dispatcher_provider=lambda: mutating_dispatcher,
        presentation_config=ToolPresentationConfig(
            large_result_threshold_chars=50,
            large_result_preview_chars=25,
            result_cache_max_bytes=100,
        ),
    )

    result = runtime.tools["set_bytes"](
        address="0x1000",
        bytes_hex="90",
        target="fw",
    )

    assert calls == 1
    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert result.structuredContent["operation_succeeded"] is True
    assert "Do not re-run a non-idempotent tool" in result.content[0].text


def test_compaction_exception_returns_completed_result_without_logging_payload(
    monkeypatch,
    caplog,
):
    from ghidra_mcp.presentation import result_resources

    calls = 0
    original = "mutation completed\n" + ("x" * 5_000)
    secret_in_exception = "SECRET_RESULT_FRAGMENT"

    def mutating_dispatcher(name, args, target, *, registry):  # noqa: ARG001
        nonlocal calls
        calls += 1
        return original

    def fail_serialization(*_args, **_kwargs):
        raise RuntimeError(secret_in_exception)

    monkeypatch.setattr(result_resources, "_serialize_result", fail_serialization)
    runtime = create_mcp_server(
        specs={"set_bytes": get_tool_spec("set_bytes")},
        registry_provider=lambda: object(),
        dispatcher_provider=lambda: mutating_dispatcher,
        presentation_config=ToolPresentationConfig(
            large_result_threshold_chars=50,
            large_result_preview_chars=25,
        ),
    )

    with caplog.at_level("WARNING"):
        result = runtime.tools["set_bytes"](
            address="0x1000",
            bytes_hex="90",
            target="fw",
        )

    assert calls == 1
    assert result is original
    assert "RuntimeError" in caplog.text
    assert secret_in_exception not in caplog.text


def test_compaction_does_not_expand_a_small_result():
    store = ResultResourceStore(max_entries=4)
    payload = "x" * 11

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=10,
            large_result_preview_chars=5,
        ),
        store=store,
    )

    assert result is payload


def test_uncacheable_notice_does_not_expand_a_small_result():
    store = ResultResourceStore(max_entries=4, max_bytes=5)
    payload = "x" * 11

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=10,
            large_result_preview_chars=5,
        ),
        store=store,
    )

    assert result is payload


def test_initial_compaction_caps_the_complete_escape_heavy_response():
    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result="\0" * 50_000,
        config=ToolPresentationConfig(),
        store=ResultResourceStore(max_bytes=1_000_000),
    )

    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert _call_tool_result_wire_chars(result) <= 12_000
    assert result.structuredContent["preview_chars"] < 4_000


def test_compaction_compares_inline_and_compact_results_in_wire_units():
    payload = "\0" * 2_000

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=1_000,
            large_result_preview_chars=1_000,
        ),
        store=ResultResourceStore(max_bytes=1_000_000),
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["truncated"] is True
    assert _call_tool_result_wire_chars(result) < _call_tool_result_wire_chars(
        CallToolResult(content=[TextContent(type="text", text=payload)])
    )


def test_large_string_uses_wire_lower_bound_and_encodes_payload_once(monkeypatch):
    from ghidra_mcp.presentation import result_resources

    class CountingString(str):
        encode_calls = 0

        def encode(self, *args, **kwargs):
            self.encode_calls += 1
            return super().encode(*args, **kwargs)

    payload = CountingString("x" * 50_000)

    def fail_full_wire_serialization(_result):
        raise AssertionError("large inline result was fully serialized")

    monkeypatch.setattr(
        result_resources,
        "_inline_result_wire_chars",
        fail_full_wire_serialization,
    )

    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(
            large_result_threshold_chars=1_000,
            large_result_preview_chars=200,
        ),
        store=ResultResourceStore(max_bytes=100_000),
    )

    assert isinstance(result, CallToolResult)
    assert result.structuredContent["truncated"] is True
    assert payload.encode_calls == 1


def test_delivered_inline_size_stops_after_threshold():
    class CountingList(list):
        yielded = 0

        def __iter__(self):
            for item in super().__iter__():
                self.yielded += 1
                yield item

    payload = CountingList(["x" * 100 for _ in range(10_000)])

    measured = _delivered_inline_size(
        payload,
        tool_name="list_functions",
        stop_after=150,
    )

    assert measured == 200
    assert payload.yielded == 2


def test_call_tool_result_wire_size_matches_mcp_transport_serialization():
    result = CallToolResult(
        content=[TextContent(type="text", text="payload")],
        structuredContent={"answer": 42},
    )

    expected = len(result.model_dump_json(by_alias=True, exclude_none=True))

    assert _call_tool_result_wire_chars(result) == expected


def test_compaction_never_replaces_content_blocks_with_a_larger_wire_result():
    blocks = [TextContent(type="text", text="x") for _ in range(20)]
    inline_wire = _call_tool_result_wire_chars(CallToolResult(content=blocks))

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=blocks,
        config=ToolPresentationConfig(
            large_result_threshold_chars=10,
            large_result_preview_chars=1,
        ),
        store=ResultResourceStore(max_entries=4),
    )

    assert result is blocks
    assert _call_tool_result_wire_chars(CallToolResult(content=blocks)) == inline_wire


def test_threshold_metric_is_identical_for_raw_and_wrapped_content_blocks():
    blocks = [TextContent(type="text", text="x" * 9) for _ in range(1200)]
    wrapped = CallToolResult(content=blocks)

    raw_chars = _delivered_inline_size(blocks, tool_name="custom_tool")
    wrapped_chars = _delivered_inline_size(wrapped, tool_name="custom_tool")
    assert raw_chars == wrapped_chars == 10_800

    config = ToolPresentationConfig()
    store = ResultResourceStore(max_entries=4)
    raw_result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=blocks,
        config=config,
        store=store,
    )
    wrapped_result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=wrapped,
        config=config,
        store=store,
    )

    assert raw_result is blocks
    assert wrapped_result is wrapped


@pytest.mark.parametrize(
    "cache_max_bytes,result_unavailable",
    [(1_000_000, False), (100, True)],
)
def test_initial_large_result_response_bounds_escape_heavy_target_metadata(
    cache_max_bytes,
    result_unavailable,
):
    result = maybe_compact_tool_result(
        tool_name="decompile_function",
        target="\0" * 20_000,
        result="x" * 50_000,
        config=ToolPresentationConfig(),
        store=ResultResourceStore(max_bytes=cache_max_bytes),
    )

    assert isinstance(result, CallToolResult)
    assert result.isError is False
    assert result.structuredContent.get("result_unavailable", False) is result_unavailable
    assert _call_tool_result_wire_chars(result) <= 12_000
    assert result.structuredContent["metadata_truncated"] is True
    assert len(result.structuredContent["target"]) < 20_000


def test_read_result_fits_escape_heavy_text_without_collapsing_to_one_char():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    entry = runtime.result_store.add(**_store_entry_kwargs("\n" * 20_000))

    content, page = _call_result_tool(
        runtime,
        "read_result",
        {"result_id": entry.result_id, "limit_chars": 12_000},
    )

    assert 5_000 <= page["chunk_chars"] <= 6_000
    assert len(content[0].text) <= 12_000
    assert page["has_more"] is True


def test_read_result_bounds_escape_heavy_metadata_and_still_makes_progress():
    runtime = _runtime_for_specs(
        {"list_targets": get_tool_spec("list_targets")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=1,
            large_result_preview_chars=1,
        ),
    )
    kwargs = _store_entry_kwargs("payload")
    kwargs["target"] = "\0" * 20_000
    entry = runtime.result_store.add(**kwargs)

    content, page = _call_result_tool(
        runtime,
        "read_result",
        {"result_id": entry.result_id, "limit_chars": 1},
    )

    assert len(content[0].text) <= 1024
    assert page["metadata_truncated"] is True
    assert page["chunk"] == "p"
    assert page["next_offset_chars"] == 1


def test_search_result_caps_the_complete_escaped_response():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    text = "".join('"' * 200 + "MATCH" + '"' * 200 + "z" * 700 for _ in range(20))
    entry = runtime.result_store.add(**_store_entry_kwargs(text))

    content, found = _call_result_tool(
        runtime,
        "search_result",
        {
            "result_id": entry.result_id,
            "pattern": "MATCH",
            "context_chars": 200,
            "max_matches": 20,
        },
    )

    assert found["match_count"] == 20
    assert found["matches_shown"] > 0
    assert len(content[0].text) <= 12_000


def test_search_result_bounds_the_echoed_pattern_at_the_minimum_budget():
    runtime = _runtime_for_specs(
        {"list_targets": get_tool_spec("list_targets")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=1,
            large_result_preview_chars=1,
        ),
    )
    entry = runtime.result_store.add(**_store_entry_kwargs("plain text"))
    pattern = "\0" * 512

    content, found = _call_result_tool(
        runtime,
        "search_result",
        {"result_id": entry.result_id, "pattern": pattern},
    )

    assert len(content[0].text) <= 1024
    assert found["pattern_truncated"] is True
    assert pattern.startswith(found["pattern"])
    assert found["pattern"] != pattern


def test_search_result_preserves_the_full_pattern_when_it_fits():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    entry = runtime.result_store.add(**_store_entry_kwargs("plain text"))
    pattern = "a" * 512

    _, found = _call_result_tool(
        runtime,
        "search_result",
        {"result_id": entry.result_id, "pattern": pattern},
    )

    assert found["pattern"] == pattern
    assert found["pattern_truncated"] is False


def test_search_result_does_not_block_the_event_loop(monkeypatch):
    from ghidra_mcp.presentation import result_resources

    class Compiled:
        @staticmethod
        def finditer(_text, **_kwargs):
            return iter(())

    def slow_compile(_pattern):
        time.sleep(0.25)
        return Compiled()

    monkeypatch.setattr(result_resources.regex, "compile", slow_compile)
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    entry = runtime.result_store.add(**_store_entry_kwargs("plain text"))

    async def call_and_measure_timer():
        call = asyncio.create_task(
            runtime.mcp.call_tool(
                "search_result",
                {"result_id": entry.result_id, "pattern": "text"},
            )
        )
        started = time.perf_counter()
        await asyncio.sleep(0.02)
        timer_elapsed = time.perf_counter() - started
        await call
        return timer_elapsed

    assert _run(call_and_measure_timer()) < 0.15


def test_search_result_does_not_copy_the_full_match(monkeypatch):
    from ghidra_mcp.presentation import result_resources

    class Found:
        @staticmethod
        def span():
            return 0, 10_000_000

        @staticmethod
        def group(_index=0):
            raise AssertionError("group() must not be called")

    class Compiled:
        @staticmethod
        def finditer(_text, **_kwargs):
            yield Found()

    monkeypatch.setattr(result_resources.regex, "compile", lambda _pattern: Compiled())
    store = ResultResourceStore()
    entry = store.add(**_store_entry_kwargs("x" * 10_000_000))

    result = _search_stored_result(
        entry,
        pattern=".*",
        context_chars=0,
        max_matches=1,
        configured_budget=12_000,
    )

    assert result["matches_shown"] == 1
    match = result["matches"][0]
    assert len(match["match"]) == 500
    assert match["end_offset"] == 10_000_000
    assert match["match_chars"] == 10_000_000
    assert match["match_truncated"] is True


def test_result_resource_template_does_not_advertise_the_wrong_mime_type():
    runtime = _runtime_for_specs({"list_targets": get_tool_spec("list_targets")})
    templates = _run(runtime.mcp.list_resource_templates())
    result_template = next(
        template
        for template in templates
        if str(template.uriTemplate) == "ghidra://results/{result_id}"
    )
    assert result_template.mimeType is None

    entry = runtime.result_store.add(
        tool="list_functions",
        target="fw",
        text='[{"name":"main"}]',
        mime_type="application/json",
        result_type="list",
        item_count=1,
    )
    contents = _run(runtime.mcp.read_resource(entry.uri))
    assert contents[0].mime_type == "application/json"


def test_empty_list_normalization_is_not_resourceized():
    runtime = _runtime_for_specs(
        {"list_functions": get_tool_spec("list_functions")},
        config=ToolPresentationConfig(large_result_threshold_chars=1, large_result_preview_chars=1),
        registry=type("EmptyRegistry", (), {"call": lambda self, command, params, target: []})(),
    )

    result = runtime.tools["list_functions"](target="fw")

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"
    assert result.structuredContent is None


def test_empty_list_text_with_result_metadata_is_not_treated_as_plain_sentinel():
    original = CallToolResult(
        content=[TextContent(type="text", text="[]")],
        _meta={"blob": "x" * 5000},
    )
    store = ResultResourceStore(max_entries=4)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=original,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=5,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result is not original
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["content"][0]["text"] == "[]"
    assert stored["_meta"] == {"blob": "x" * 5000}


def test_empty_list_text_with_extension_field_is_not_treated_as_plain_sentinel():
    original = CallToolResult(
        content=[TextContent(type="text", text="[]", future_field="x" * 5000)],
    )
    store = ResultResourceStore(max_entries=4)

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=original,
        config=ToolPresentationConfig(
            large_result_threshold_chars=20,
            large_result_preview_chars=5,
        ),
        store=store,
    )

    assert isinstance(result, CallToolResult)
    assert result is not original
    stored = json.loads(store.read_text(result.structuredContent["result_id"]))
    assert stored["content"][0]["future_field"] == "x" * 5000


def test_cli_parses_presentation_config_options():
    args = cli.parse_args(
        [
            "--tool-description-mode",
            "short",
            "--large-result-mode",
            "inline",
            "--large-result-threshold-chars",
            "42",
            "--large-result-preview-chars",
            "12",
            "--result-cache-max-entries",
            "8",
            "--result-cache-max-bytes",
            "1024",
        ]
    )

    config = cli.presentation_config_from_args(args)

    assert config == ToolPresentationConfig(
        description_mode="short",
        large_result_mode="inline",
        large_result_threshold_chars=42,
        large_result_preview_chars=12,
        result_cache_max_entries=8,
        result_cache_max_bytes=1024,
    )


def test_cli_help_describes_conditional_compaction_and_safe_retry(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.parse_args(["--help"])

    assert exc_info.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "only when the complete response becomes smaller" in help_text
    assert "bounded first-sentence fallback" in help_text
    assert "Initial preview character upper bound" in help_text
    assert "successful result-unavailable notice" in help_text
    assert "otherwise the inline result is preserved" in help_text
    assert "do not automatically retry side-effecting calls" in help_text.lower()


def test_cli_defaults_match_config_defaults():
    args = cli.parse_args([])

    assert cli.presentation_config_from_args(args) == ToolPresentationConfig()


def test_docs_resource_respects_profile_filtering():
    specs = filter_tool_specs(profile=ToolProfile.READONLY, disable_tools=["list_targets"])
    runtime = _runtime_for_specs(specs)

    index = json.loads(_run(runtime.mcp.read_resource("ghidra://docs/tools"))[0].content)
    names = {tool["name"] for tool in index["tools"]}

    assert "list_targets" not in names
    assert all(get_tool_spec(name).safety_tag.value == "read_only" for name in names)


# --- #1: doc resources must describe the public (registered) tool interface ---


def test_tool_docs_publish_public_param_names_matching_registered_tools():
    specs = {
        name: get_tool_spec(name)
        for name in ("rename_function", "search_bytes", "list_functions", "set_bytes")
    }
    runtime = _runtime_for_specs(specs)
    registered = {tool.name: tool for tool in _run(runtime.mcp.list_tools())}

    for name in specs:
        detail = json.loads(
            _run(runtime.mcp.read_resource(f"ghidra://docs/tools/{name}"))[0].content
        )
        doc_props = set(detail["input_schema"]["properties"])
        real_props = set(registered[name].inputSchema["properties"])
        # The documented schema and signature must match what the tool accepts.
        assert doc_props == real_props, name
        assert set(detail["public_signature"]) == real_props, name
        assert "target" in doc_props, name


def test_tool_docs_apply_public_name_overrides_no_raw_names_leak():
    specs = {name: get_tool_spec(name) for name in ("rename_function", "search_bytes", "set_bytes")}
    runtime = _runtime_for_specs(specs)

    rf = json.loads(_run(runtime.mcp.read_resource("ghidra://docs/tools/rename_function"))[0].content)
    rf_props = rf["input_schema"]["properties"]
    assert {"new_name", "old_name"} <= set(rf_props)
    assert "newName" not in rf_props and "oldName" not in rf_props
    assert "new_name" in rf["input_schema"]["required"]

    sb = json.loads(_run(runtime.mcp.read_resource("ghidra://docs/tools/search_bytes"))[0].content)
    assert "pattern" in sb["input_schema"]["properties"]
    assert "bytes" not in sb["input_schema"]["properties"]

    xb = json.loads(_run(runtime.mcp.read_resource("ghidra://docs/tools/set_bytes"))[0].content)
    assert "bytes_hex" in xb["input_schema"]["properties"]
    assert "bytes" not in xb["input_schema"]["properties"]


def test_tool_docs_output_schema_matches_client_visible_shape():
    from ghidra_mcp.presentation.tool_registry import public_output_schema

    # list tools deliver a bare JSON array — the {"payload": ...} validation
    # wrapper must not leak into the published schema.
    list_schema = public_output_schema(get_tool_spec("list_functions"))
    assert list_schema.get("type") == "array"
    assert "payload" not in list_schema.get("properties", {})

    # scalar tools deliver the bare value (str, or [] normalized upstream).
    scalar_schema = public_output_schema(get_tool_spec("decompile_function"))
    assert "payload" not in scalar_schema.get("properties", {})
    assert "anyOf" in scalar_schema or scalar_schema.get("type") == "string"

    # typed output models are delivered as-is and keep their object schema.
    typed_schema = public_output_schema(get_tool_spec("create_session"))
    assert typed_schema["type"] == "object"
    assert "status" in typed_schema["properties"]

    runtime = _runtime_for_specs({"list_functions": get_tool_spec("list_functions")})
    detail = json.loads(
        _run(runtime.mcp.read_resource("ghidra://docs/tools/list_functions"))[0].content
    )
    assert detail["output_schema"] == list_schema


def test_public_input_schema_target_semantics_match_signature():
    # CORE_COMMAND: target optional with a default; REGISTRY/SHARED_SYNC: target required.
    core_schema = public_input_schema(get_tool_spec("rename_function"))
    assert core_schema["properties"]["target"]["default"] == "default"
    assert "target" not in core_schema.get("required", [])

    sync_spec = get_tool_spec("get_project_sync_status")
    sync_schema = public_input_schema(sync_spec)
    assert "target" in sync_schema["properties"]
    assert "target" in sync_schema["required"]
    assert public_parameter_names(sync_spec)[0] == "target"


# --- #3: preview must not exceed threshold (else compaction can inflate) ---


def test_preview_larger_than_threshold_is_rejected():
    with pytest.raises(ValueError, match="large_result_preview_chars must be <="):
        ToolPresentationConfig(
            large_result_threshold_chars=12000, large_result_preview_chars=20000
        )
    # Equal is allowed; the shipped defaults are internally consistent.
    ToolPresentationConfig(large_result_threshold_chars=100, large_result_preview_chars=100)
    defaults = ToolPresentationConfig()
    assert defaults.large_result_preview_chars <= defaults.large_result_threshold_chars


def test_cli_exits_on_preview_larger_than_threshold(capsys):
    # #7: config errors surface as an argparse usage error (exit 2), not a traceback.
    with pytest.raises(SystemExit) as excinfo:
        cli.parse_args(
            ["--large-result-threshold-chars", "100", "--large-result-preview-chars", "200"]
        )
    assert excinfo.value.code == 2
    assert "large_result_preview_chars must be <=" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--large-result-threshold-chars", "0"),
        ("--large-result-preview-chars", "-1"),
        ("--result-cache-max-entries", "0"),
        ("--result-cache-max-bytes", "0"),
    ],
)
def test_cli_exits_on_out_of_range_numeric_flag(flag, value):
    with pytest.raises(SystemExit) as excinfo:
        cli.parse_args([flag, value])
    assert excinfo.value.code == 2


# --- #4: compaction decision must use the delivered (indent=2) size ---


def test_compaction_decision_uses_delivered_indent2_size():
    data = [{"name": f"func_{i}", "addr": f"0x{i:08x}", "note": "n" * 20} for i in range(30)]
    compact_len = len(json.dumps(data, ensure_ascii=False, default=str))
    delivered = _delivered_inline_size(data, tool_name="list_functions")
    # The gap is the whole point: FastMCP delivers indent=2, which is larger.
    assert compact_len < delivered

    store = ResultResourceStore(max_entries=4)
    # Threshold sits above the compact size but below the delivered size. Measuring
    # compact (the old bug) would send this inline over-cap; measuring delivered compacts it.
    threshold = (compact_len + delivered) // 2
    result = maybe_compact_tool_result(
        tool_name="list_functions",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=threshold,
            large_result_preview_chars=min(200, threshold),
        ),
        store=store,
    )
    assert isinstance(result, CallToolResult)
    assert result.structuredContent["truncated"] is True

    # Above the delivered size: returned inline, untouched.
    inline = maybe_compact_tool_result(
        tool_name="list_functions",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=delivered + 100,
            large_result_preview_chars=200,
        ),
        store=store,
    )
    assert inline is data


def test_compaction_decision_uses_raw_string_item_size_for_lists():
    # FastMCP emits each top-level string as raw text, without the quotes and
    # escapes used by the compact JSON stored for resource reads. The compact
    # representation therefore cannot short-circuit the delivered-size probe.
    data = [f"{idx:09d}" for idx in range(1200)]
    threshold = 12000
    delivered = _delivered_inline_size(data, tool_name="search_bytes")

    compact_text, *_ = _serialize_result(data, tool_name="search_bytes")
    old_probe = len(compact_text) - (len(data) + 1)
    assert delivered == 10800
    assert old_probe == 13200

    result = maybe_compact_tool_result(
        tool_name="search_bytes",
        target="fw",
        result=data,
        config=ToolPresentationConfig(
            large_result_threshold_chars=threshold,
            large_result_preview_chars=4000,
        ),
        store=ResultResourceStore(max_entries=4),
    )

    assert result is data


def test_nested_call_tool_results_use_fastmcp_list_conversion_size():
    data = [
        CallToolResult(
            content=[TextContent(type="text", text="x" * 100)],
        )
        for _ in range(100)
    ]

    delivered = _delivered_inline_size(data, tool_name="custom_tool")
    assert delivered > 12_000

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=data,
        config=ToolPresentationConfig(),
        store=ResultResourceStore(max_entries=4),
    )

    assert isinstance(result, CallToolResult)
    assert result is not data
    assert result.structuredContent["result_type"] == "list"


def test_tuple_result_is_stored_as_json_like_a_list():
    store = ResultResourceStore(max_entries=4)
    payload = tuple({"name": f"f_{i}", "addr": f"0x{i:x}"} for i in range(50))

    result = maybe_compact_tool_result(
        tool_name="list_functions",
        target="fw",
        result=payload,
        config=ToolPresentationConfig(large_result_threshold_chars=80, large_result_preview_chars=30),
        store=store,
    )

    meta = result.structuredContent
    assert meta["result_type"] == "list"
    assert meta["mime_type"] == "application/json"
    assert meta["item_count"] == 50
    # The stored payload must be parseable JSON, not a Python repr.
    stored = json.loads(store.read_text(meta["result_id"]))
    assert stored[0]["name"] == "f_0"


def test_non_string_dict_keys_do_not_fail_the_tool_call():
    import enum

    class Color(enum.Enum):
        RED = "red"

    store = ResultResourceStore(max_entries=4)
    small = {Color.RED: 1}

    # Small results stay inline; the size probe must not raise TypeError.
    inline = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=small,
        config=ToolPresentationConfig(large_result_threshold_chars=12000),
        store=store,
    )
    assert inline is small

    big = {Color.RED: ["x" * 40 for _ in range(200)]}
    compacted = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=big,
        config=ToolPresentationConfig(large_result_threshold_chars=50, large_result_preview_chars=25),
        store=store,
    )
    stored = json.loads(store.read_text(compacted.structuredContent["result_id"]))
    assert set(stored) == {"red"}


# --- #2: search_result must guard against ReDoS / event-loop hangs ---


def _decompile_result_id(runtime):
    return runtime.tools["decompile_function"](name="main", target="fw").structuredContent["result_id"]


def test_search_result_times_out_on_catastrophic_pattern(monkeypatch):
    from ghidra_mcp.presentation import result_resources

    monkeypatch.setattr(result_resources, "_SEARCH_TIMEOUT_SECONDS", 0.05)

    class LongRunRegistry:
        def call(self, command, params, target):  # noqa: ARG002
            # Long alphanumeric runs occur naturally in decompiled output and are
            # exactly what catastrophic patterns blow up on.
            return "int main(void) {\n" + ("a" * 64 + "\n") * 4 + ("z" * 2000) + "}\n"

    runtime = _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=40, large_result_preview_chars=25
        ),
        registry=LongRunRegistry(),
    )
    rid = _decompile_result_id(runtime)
    # (a+)+x is deliberately absent: the regex engine optimizes single-char-class
    # nesting and finishes it instantly, so only genuinely exponential patterns
    # exercise the timeout.
    for bad in [r"(a|a)+x", r"((a|a)+)+$"]:
        with pytest.raises(ToolError, match="timed out"):
            _run(runtime.mcp.call_tool("search_result", {"result_id": rid, "pattern": bad}))


def test_search_result_rejects_overlong_pattern():
    runtime = _compacted_decompile_runtime()
    rid = _decompile_result_id(runtime)
    with pytest.raises(ToolError, match="too long"):
        _run(runtime.mcp.call_tool("search_result", {"result_id": rid, "pattern": "a" * 600}))


def test_search_result_allows_normal_patterns_after_hardening():
    runtime = _compacted_decompile_runtime()
    rid = _decompile_result_id(runtime)
    for good in [r"return 0;", r"return \d+;", r"int \w+\(", r"\bvoid\b"]:
        _, found = _call_result_tool(
            runtime, "search_result", {"result_id": rid, "pattern": good}
        )
        assert found["match_count"] >= 1, good


def test_search_result_allows_quantifier_patterns_on_benign_text():
    # Safe-but-quantifier-heavy patterns (including ones a static ReDoS screen
    # would reject, like a group quantifier followed by a whitespace quantifier)
    # must run: the timeout, not pattern shape, is the safety boundary.
    runtime = _compacted_decompile_runtime()
    rid = _decompile_result_id(runtime)
    for pattern in [r"(0x[0-9a-f]+) *=", r"(\w+) +\+=", r"(\w+\s*)+", r"(a+)+"]:
        _, found = _call_result_tool(
            runtime, "search_result", {"result_id": rid, "pattern": pattern}
        )
        assert found["match_count"] >= 0, pattern
