"""Validate the public low-level SDK and both channels of tool results."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from mcp import Client, MCPError, StdioServerParameters
from mcp.server import Server

from ghidra_mcp.contracts.tool_spec import filter_tool_specs, get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.result_compaction import _call_tool_result_wire_chars
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


class Registry:
    def __init__(self):
        self.calls = []

    def list_targets(self):
        self.calls.append("list_targets")
        return [{"target": "sample"}]

    def call(self, command, params, target):
        self.calls.append(command)
        if command == "list_functions":
            return []
        if command == "decompile_function":
            return "int main(void) { return 0; }\n" * (1000 if params["name"] == "large" else 1)
        raise AssertionError(command)


def runtime(registry, *, config=None):
    return create_mcp_server(
        specs=filter_tool_specs(),
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=config,
    )


def validate_result(tools, name, result):
    assert result.structured_content is not None
    Draft202012Validator(tools[name].output_schema).validate(result.structured_content)


def test_public_sdk_catalog_and_inline_structured_results():
    async def check():
        server = runtime(Registry()).mcp
        assert isinstance(server, Server)
        async with Client(server) as client:
            catalog = await client.list_tools()
            tools = {tool.name: tool for tool in catalog.tools}
            assert len(tools) == len(filter_tool_specs()) + 2
            for tool in tools.values():
                assert tool.output_schema
                Draft202012Validator.check_schema(tool.input_schema)
                Draft202012Validator.check_schema(tool.output_schema)
            for name, arguments, expected in (
                ("list_targets", {}, [{"target": "sample"}]),
                ("list_functions", {"target": "sample"}, []),
                ("decompile_function", {"target": "sample", "name": "main"}, "int main(void) { return 0; }\n"),
            ):
                result = await client.call_tool(name, arguments)
                assert not result.is_error
                assert result.structured_content == {"result": expected}
                validate_result(tools, name, result)
                assert result.meta["io.modelcontextprotocol/serverInfo"]["version"]

    asyncio.run(check())


@pytest.mark.parametrize("cache_bytes", [100, 134_217_728])
def test_compaction_and_cache_refusal_match_advertised_schema(cache_bytes):
    async def check():
        config = ToolPresentationConfig(result_cache_max_bytes=cache_bytes)
        async with Client(runtime(Registry(), config=config).mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            result = await client.call_tool("decompile_function", {"name": "large", "target": "sample"})
            assert not result.is_error
            validate_result(tools, "decompile_function", result)
            data = result.structured_content
            assert data["truncated"]
            if cache_bytes == 100:
                assert data["result_unavailable"] and data["operation_succeeded"]
            else:
                page = await client.call_tool("read_result", {"result_id": data["result_id"], "limit_chars": 20})
                validate_result(tools, "read_result", page)
                assert page.structured_content["result"] == json.loads(page.content[0].text)
                assert page.structured_content["result"]["chunk"] == "int main(void) { return 0; }\n"[:20]
                resource = await client.read_resource(data["resource_uri"])
                assert resource.contents[0].mime_type == "text/x-c"
                assert resource.contents[0].text.startswith("int main")

    asyncio.run(check())


def test_protocol_errors_are_structured_and_do_not_execute_tools():
    async def check():
        registry = Registry()
        async with Client(runtime(registry).mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            for name, arguments in (
                ("list_functions", {"limit": "2"}),
                ("list_targets", {"unexpected": True}),
                ("read_result", {"result_id": "deadbeefdeadbeef"}),
            ):
                result = await client.call_tool(name, arguments)
                assert result.is_error
                validate_result(tools, name, result)
                assert result.structured_content["error"]["message"]
            result = await client.call_tool("run_script", {"source": "pass"})
            assert result.is_error and "unpublished" in result.content[0].text
        assert registry.calls == []

    asyncio.run(check())


@pytest.mark.parametrize("threshold", [40, 12000])
def test_retrieval_budget_includes_text_and_structured_data(threshold):
    async def check():
        config = ToolPresentationConfig(large_result_threshold_chars=threshold, large_result_preview_chars=0)
        bundle = runtime(Registry(), config=config)
        text = '日本語 "quoted" \\ line\n' * 3000
        entry = bundle.result_store.add(
            tool="decompile_function",
            target="sample",
            text=text,
            mime_type="text/x-c",
            result_type="string",
            item_count=None,
        )
        async with Client(bundle.mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            for name, arguments in (
                ("read_result", {"result_id": entry.result_id}),
                ("search_result", {"result_id": entry.result_id, "pattern": "quoted", "max_matches": 20}),
            ):
                result = await client.call_tool(name, arguments)
                assert not result.is_error
                validate_result(tools, name, result)
                # SDK serverInfo and JSON-RPC framing are transport metadata.
                payload = result.model_copy(update={"meta": None})
                assert _call_tool_result_wire_chars(payload) <= max(threshold, 1024)
                assert result.structured_content["result"] == json.loads(result.content[0].text)

    asyncio.run(check())


@pytest.mark.parametrize("threshold", [1, 1024, 12000])
@pytest.mark.parametrize("count_mode", ["bounded", "none"])
@pytest.mark.parametrize("merge_context", [False, True])
@pytest.mark.parametrize(
    "pattern,match_text", [("a" * 400, "a" * 400), ("\0" * 512, "\0" * 512), ("(?=a)(?#" + "x" * 400 + ")", "a")]
)
def test_search_keeps_matches_and_continuation_at_small_budgets(
    threshold, count_mode, merge_context, pattern, match_text
):
    async def check():
        config = ToolPresentationConfig(large_result_threshold_chars=threshold, large_result_preview_chars=0)
        bundle = runtime(Registry(), config=config)
        text = ("prefix " + match_text + " suffix\n") * 3
        entry = bundle.result_store.add(
            tool="decompile_function",
            target="sample",
            text=text,
            mime_type="text/x-c",
            result_type="string",
            item_count=None,
        )
        expected = [(i * (len(match_text) + 15) + 7) for i in range(3)]
        match_chars = 0 if pattern.startswith("(?=") else len(match_text)
        offsets = []
        cursor = None
        async with Client(bundle.mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            for _ in range(4):
                result = await client.call_tool(
                    "search_result",
                    {
                        "result_id": entry.result_id,
                        "pattern": pattern,
                        "max_matches": 1,
                        "context_chars": 0,
                        "count_mode": count_mode,
                        "merge_context": merge_context,
                        "cursor": cursor,
                    },
                )
                assert not result.is_error
                validate_result(tools, "search_result", result)
                assert _call_tool_result_wire_chars(result.model_copy(update={"meta": None})) <= max(threshold, 1024)
                data = result.structured_content["result"]
                assert data == json.loads(result.content[0].text)
                assert pattern.startswith(data["pattern"])
                assert data["pattern_truncated"] == (data["pattern"] != pattern)
                assert data["matches_shown"] == (1 if len(offsets) < 3 else 0)
                for match in data["matches"]:
                    offsets.append(match["offset_chars"])
                    assert match["end_offset"] == match["offset_chars"] + match_chars
                    assert match["match_chars"] == match_chars
                    assert match["match"] == text[match["offset_chars"] : match["offset_chars"] + len(match["match"])]
                    assert match["match_truncated"] == (len(match["match"]) < match_chars)
                cursor = data["next_cursor"]
                if cursor is None:
                    break
            else:
                pytest.fail("search did not terminate")
        assert offsets == expected

    asyncio.run(check())


@pytest.mark.parametrize("threshold", [1024, 12000])
@pytest.mark.parametrize("count_mode", ["bounded", "none"])
@pytest.mark.parametrize(
    "pattern,expected",
    [
        (r"a\K", [(1, 1), (2, 2), (3, 3)]),
        (r"(?=a)", [(0, 0), (1, 1), (2, 2)]),
        (r"|a", [(0, 0), (0, 1), (1, 1), (1, 2), (2, 2), (2, 3), (3, 3)]),
    ],
)
def test_search_cursor_preserves_consuming_and_nonconsuming_empty_matches(threshold, count_mode, pattern, expected):
    async def check():
        config = ToolPresentationConfig(large_result_threshold_chars=threshold, large_result_preview_chars=0)
        bundle = runtime(Registry(), config=config)
        entry = bundle.result_store.add(
            tool="decompile_function",
            target="sample",
            text="aaa",
            mime_type="text/x-c",
            result_type="string",
            item_count=None,
        )
        actual = []
        cursor = None
        async with Client(bundle.mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            for _ in range(len(expected) + 1):
                result = await client.call_tool(
                    "search_result",
                    {
                        "result_id": entry.result_id,
                        "pattern": pattern,
                        "max_matches": 1,
                        "context_chars": 0,
                        "count_mode": count_mode,
                        "cursor": cursor,
                    },
                )
                assert not result.is_error
                validate_result(tools, "search_result", result)
                assert _call_tool_result_wire_chars(result.model_copy(update={"meta": None})) <= threshold
                data = result.structured_content["result"]
                assert data == json.loads(result.content[0].text)
                if count_mode == "bounded":
                    assert data["count_complete"]
                    assert data["match_count"] == len(expected) - len(actual)
                actual.extend((m["offset_chars"], m["end_offset"]) for m in data["matches"])
                cursor = data["next_cursor"]
                if cursor is None:
                    break
            else:
                pytest.fail("search did not terminate")
        assert actual == expected

    asyncio.run(check())


def test_invalid_output_preserves_completed_execution_without_leaking_payload():
    async def check():
        calls = []

        def dispatcher(*args, **kwargs):
            calls.append(args)
            return {"private": "DO_NOT_LEAK"}  # decompile_function promises a string

        bundle = create_mcp_server(
            specs={"decompile_function": get_tool_spec("decompile_function")},
            registry_provider=lambda: None,
            dispatcher_provider=lambda: dispatcher,
        )
        async with Client(bundle.mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            result = await client.call_tool("decompile_function", {"name": "main"})
            validate_result(tools, "decompile_function", result)
            assert not result.is_error
            assert result.structured_content["operation_succeeded"]
            assert result.structured_content["presentation_failed"]
            assert "DO_NOT_LEAK" not in result.model_dump_json()
        assert len(calls) == 1

    asyncio.run(check())


def test_stdio_public_sdk_round_trip_without_a_jvm(tmp_path):
    worker = tmp_path / "server.py"
    worker.write_text("""
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.transport import run_mcp_server
class Registry:
    def list_targets(self):
        return [{"target": "stdio"}]
runtime = create_mcp_server(
    specs={"list_targets": get_tool_spec("list_targets")},
    registry_provider=lambda: Registry(), dispatcher_provider=lambda: dispatch_tool,
)
run_mcp_server(runtime.mcp, transport="stdio")
""")

    async def check():
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(worker)],
            env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        )
        async with Client(params, read_timeout_seconds=10) as client:
            for uri in ("ghidra://docs/tools/unpublished_tool", "ghidra://results/deadbeefdeadbeef"):
                with pytest.raises(MCPError) as caught:
                    await client.read_resource(uri)
                assert caught.value.code == -32602
                assert caught.value.data == {"uri": uri}
            tools = {t.name: t for t in (await client.list_tools()).tools}
            result = await client.call_tool("list_targets", {})
            validate_result(tools, "list_targets", result)
            assert result.structured_content == {"result": [{"target": "stdio"}]}

    asyncio.run(check())
