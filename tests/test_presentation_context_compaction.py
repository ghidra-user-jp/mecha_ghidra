from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import CallToolResult, ResourceLink, TextContent

from ghidra_mcp.contracts.tool_spec import ToolProfile, filter_tool_specs, get_tool_spec
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.result_resources import (
    ResultResourceStore,
    _preview_slice,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import select_tool_description


def _run(coro):
    return asyncio.run(coro)


class LargeResultRegistry:
    def call(self, command, params, target):  # noqa: ARG002
        if command == "decompile_function":
            return "int main(void) {\n" + ("  return 0;\n" * 20) + "}\n"
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


def test_read_result_pages_through_stored_result():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent
    full_text = _run(runtime.mcp.read_resource(meta["resource_uri"]))[0].content

    content, first = _run(
        runtime.mcp.call_tool("read_result", {"result_id": meta["result_id"], "limit_chars": 10})
    )
    assert first["chunk"] == full_text[:10]
    assert first["chunk_chars"] == 10
    assert first["total_chars"] == len(full_text)
    assert first["has_more"] is True
    assert first["next_offset_chars"] == 10
    assert first["mime_type"] == "text/x-c"
    # Tools-only clients read the same payload from the text mirror.
    assert json.loads(content[0].text) == first

    _, second = _run(
        runtime.mcp.call_tool(
            "read_result",
            {"result_id": meta["result_id"], "offset_chars": 10, "limit_chars": 10},
        )
    )
    assert second["chunk"] == full_text[10:20]

    _, tail = _run(
        runtime.mcp.call_tool(
            "read_result",
            {"result_id": meta["result_id"], "offset_chars": len(full_text)},
        )
    )
    assert tail["chunk"] == ""
    assert tail["has_more"] is False
    assert tail["next_offset_chars"] is None


def test_read_result_clamps_limit_to_threshold():
    runtime = _compacted_decompile_runtime()
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent

    _, sliced = _run(
        runtime.mcp.call_tool(
            "read_result",
            {"result_id": meta["result_id"], "limit_chars": 500_000},
        )
    )

    assert sliced["chunk_chars"] == 40
    assert sliced["has_more"] is True


def test_read_result_unknown_id_is_actionable_error():
    runtime = _compacted_decompile_runtime()

    with pytest.raises(ToolError, match="re-run the original tool"):
        _run(runtime.mcp.call_tool("read_result", {"result_id": "deadbeefdeadbeef"}))


def test_search_result_returns_matches_with_usable_offsets():
    # Threshold above the snippet budget needed for 5 matches, below the payload size.
    runtime = _runtime_for_specs(
        {"decompile_function": get_tool_spec("decompile_function")},
        config=ToolPresentationConfig(
            large_result_threshold_chars=200,
            large_result_preview_chars=25,
        ),
    )
    compacted = runtime.tools["decompile_function"](name="main", target="fw")
    meta = compacted.structuredContent
    full_text = _run(runtime.mcp.read_resource(meta["resource_uri"]))[0].content

    _, found = _run(
        runtime.mcp.call_tool(
            "search_result",
            {
                "result_id": meta["result_id"],
                "pattern": r"return 0;",
                "context_chars": 10,
                "max_matches": 5,
            },
        )
    )

    assert found["match_count"] == 20
    assert found["matches_shown"] == 5
    assert found["scan_truncated"] is False
    offsets = [match["offset_chars"] for match in found["matches"]]
    assert offsets == sorted(offsets)
    first = found["matches"][0]
    assert full_text[first["offset_chars"] : first["offset_chars"] + len("return 0;")] == "return 0;"
    assert "return 0;" in first["context"]
    assert first["context"] == full_text[
        first["context_offset_chars"] : first["context_offset_chars"] + len(first["context"])
    ]


def test_search_result_caps_snippets_at_response_budget():
    runtime = _compacted_decompile_runtime()  # threshold (= response budget) of 40 chars
    compacted = runtime.tools["decompile_function"](name="main", target="fw")

    _, found = _run(
        runtime.mcp.call_tool(
            "search_result",
            {
                "result_id": compacted.structuredContent["result_id"],
                "pattern": r"return 0;",
                "context_chars": 10,
                "max_matches": 20,
            },
        )
    )

    assert found["match_count"] == 20
    assert 0 < found["matches_shown"] < 20


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
        config=ToolPresentationConfig(large_result_threshold_chars=10),
        store=store,
    )

    assert result is error_result


def test_large_successful_call_tool_result_is_resourceized():
    store = ResultResourceStore(max_entries=4)
    full_text = "success\n" + ("payload\n" * 20)
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
        content=[TextContent(type="text", text="x" * 100)],
        structuredContent={"answer": 42},
    )

    result = maybe_compact_tool_result(
        tool_name="custom_tool",
        target="fw",
        result=call_result,
        config=ToolPresentationConfig(large_result_threshold_chars=20),
        store=store,
    )

    meta = result.structuredContent
    assert meta["result_type"] == "call_tool_result"
    stored = json.loads(store.read_text(meta["result_id"]))
    assert stored["structuredContent"] == {"answer": 42}


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


def test_store_byte_budget_evicts_oldest_but_keeps_newest():
    store = ResultResourceStore(max_entries=8, max_bytes=100)

    first = store.add(**_store_entry_kwargs("a" * 60))
    second = store.add(**_store_entry_kwargs("b" * 60))

    assert store.get(second.result_id).text == "b" * 60
    with pytest.raises(KeyError, match="re-run the original tool"):
        store.get(first.result_id)

    oversized = store.add(**_store_entry_kwargs("c" * 500))
    assert store.get(oversized.result_id).size_chars == 500


def test_empty_list_normalization_is_not_resourceized():
    runtime = _runtime_for_specs(
        {"list_functions": get_tool_spec("list_functions")},
        config=ToolPresentationConfig(large_result_threshold_chars=1),
        registry=type("EmptyRegistry", (), {"call": lambda self, command, params, target: []})(),
    )

    result = runtime.tools["list_functions"](target="fw")

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"
    assert result.structuredContent is None


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
