"""Heavy reads retain batch isolation, budgets and decoded-text retrieval."""

import asyncio
import threading

import pytest

from ghidra_headless.contracts.batch_read import validate_requests
from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.commands import batch_read as batch_module
from ghidra_headless.handlers.commands.query_support import page
from ghidra_headless.handlers.read_budget import ReadBudget
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.result_compaction import _call_tool_result_wire_chars
from ghidra_mcp.presentation.tool_errors import ToolError
from test_batch_read import Registry, call, context, request, server


@pytest.mark.parametrize(
    "requests",
    [
        [request(str(i), tool="decompile_function") for i in range(6)],
        [request(tool="decompile_function", fields=["x"])],
        [request(tool="decompile_function", item_timeout_seconds=0)],
        [request(tool="decompile_function", item_timeout_seconds=61)],
        [request(tool="decompile_function", item_timeout_seconds=True)],
        [request(tool="get_function", item_timeout_seconds=1)],
        [request(tool="disassemble", arguments={"start_address": "0x1000"})],
        [request(tool="disassemble", arguments={"address": "0x1000", "length": 4})],
        [request(tool="disassemble", arguments={"start_address": "0x1000", "length": 0})],
        [
            request(tool="disassemble", arguments={"address": "0x1000", "limit": 1500}),
            request("b", tool="get_xrefs", arguments={"address": "0x1000", "limit": 501}),
        ],
    ],
)
def test_invalid_heavy_batch_is_rejected_before_execution(requests):
    with pytest.raises(ValueError):
        validate_requests(requests)
    registry = Registry()
    with pytest.raises(ToolError):
        call(server(registry), requests=requests)
    assert not registry.calls


def test_timeout_control_is_only_on_decompile_variant():
    from ghidra_mcp.contracts.tool_spec import get_tool_spec

    model = get_tool_spec("batch_read").input_model
    value = model.model_validate({"requests": [request(tool="decompile_function")]})
    assert value.requests[0].item_timeout_seconds == 15
    assert "item_timeout_seconds" not in get_tool_spec("decompile_function").input_model.model_fields


def test_heavy_budget_uses_item_limit_and_remaining_batch_time():
    now = [0]
    deadlines = []
    ctx = context()

    def read(tool, args, *, budget):
        deadlines.append(budget.deadline)
        now[0] += 2
        return "int f(void) {}"

    result = batch_module.batch_read(
        {
            "requests": [
                request("a", tool="decompile_function", item_timeout_seconds=3),
                request("b", tool="decompile_function"),
            ]
        },
        ensure_context=lambda: ctx,
        execute_read=read,
        clock=lambda: now[0],
    )
    assert deadlines == [3, 10]
    assert result["succeeded_count"] == 2


def test_too_little_time_skips_native_call_but_allows_a_light_read():
    ctx = context()
    now = [0]
    calls = []

    def read(tool, args):
        calls.append(tool)
        now[0] = 9.5
        return {}

    result = batch_module.batch_read(
        {"requests": [request("a"), request("b", tool="decompile_function"), request("c")]},
        ensure_context=lambda: ctx,
        execute_read=read,
        clock=lambda: now[0],
    )
    assert calls == ["get_function", "get_function"]
    assert result["items"][1]["status"] == "not_run"


@pytest.mark.parametrize("code", ["DECOMPILE_TIMEOUT", "DECOMPILE_FAILED", "READ_TIMEOUT"])
def test_stopped_heavy_read_failure_allows_next_item(code):
    ctx = context()

    def read(tool, args, **kwargs):
        if tool != "get_function":
            raise HeadlessError(code + ": stopped")
        return {"name": "f"}

    result = batch_module.batch_read(
        {"requests": [request("a", tool="decompile_function"), request("b")]},
        ensure_context=lambda: ctx,
        execute_read=read,
    )
    assert result["status"] == "partial"
    assert result["items"][0]["error"]["code"] == code


def test_disassembly_checks_deadline_while_iterating_and_converting():
    for conversion in (False, True):
        now = [0]
        budget = ReadBudget(1, clock=lambda: now[0])

        def rows():
            yield 1
            if not conversion:
                now[0] = 2
            yield 2

        def convert(row):
            now[0] = 2
            return row

        with pytest.raises(HeadlessError, match="READ_TIMEOUT"):
            page(context(), "disassemble", {}, rows(), convert=convert if conversion else None, check=budget.check)


def test_monitor_cancels_and_joins_without_affecting_the_next_read():
    class Monitor:
        def __init__(self):
            self.cancelled = threading.Event()

        def cancel(self):
            self.cancelled.set()

    import time

    expired = Monitor()
    with ReadBudget(time.monotonic() + 0.1).monitor(lambda: expired):
        assert expired.cancelled.wait(2)
    fresh = Monitor()
    with ReadBudget(time.monotonic() + 30).monitor(lambda: fresh):
        assert not fresh.cancelled.is_set()
    assert not fresh.cancelled.is_set()
    assert ReadBudget(0.25, clock=lambda: 0).native_timeout() == 1
    with pytest.raises(HeadlessError, match="DECOMPILE_TIMEOUT"):
        ReadBudget(0, clock=lambda: 0).native_timeout()


@pytest.mark.parametrize("text", ["日本語" * 1000, "\ud800" * 2000])
def test_oversized_item_is_not_returned_as_truncated_success(monkeypatch, text):
    monkeypatch.setattr(batch_module, "MAX_BATCH_RESULT_BYTES", 4096)
    registry = Registry(lambda tool, args: text if tool == "decompile_function" else {"name": "f"})
    _, result = call(server(registry), requests=[request("a", tool="decompile_function"), request("b")])
    assert result["status"] == "partial"
    assert result["items"][0]["error"]["code"] == "ITEM_RESULT_TOO_LARGE"
    assert "data" not in result["items"][0]
    assert result["items"][1]["status"] == "ok"


def test_aggregate_payload_budget_stops_unstarted_reads(monkeypatch):
    monkeypatch.setattr(batch_module, "MAX_BATCH_RESULT_BYTES", 8192)
    registry = Registry(lambda *_: "x" * 3500)
    _, result = call(server(registry), requests=[request(str(i), tool="decompile_function") for i in range(3)])
    assert len(registry.reads) == 2
    assert result["items"][1]["error"]["code"] == "RESULT_BUDGET_EXHAUSTED"
    assert result["items"][2]["reason"] == "result_budget_exhausted"


def test_disassembly_projection_preserves_page_metadata():
    data = {
        "program": "/tiny.bin",
        "revision": "generation:0",
        "items": [{"address": "1000", "mnemonic": "RET", "operands": "", "comment": "comment"}],
        "has_more": True,
        "next_cursor": "next",
    }
    _, result = call(server(Registry(lambda *_: data)), requests=[request(tool="disassemble", fields=["mnemonic"])])
    assert result["items"][0]["data"] == {**data, "items": [{"mnemonic": "RET"}]}


def test_decoded_c_can_be_paged_searched_and_resumed_with_bound_paths():
    text = '日本語 😀 "quoted" \\ code\n' * 600
    runtime = server(Registry(lambda *_: text))
    _, result = call(
        runtime,
        requests=[request("a", tool="decompile_function"), request("b", tool="decompile_function")],
        max_output_chars=2048,
    )
    path = result["items"][0]["text_path"]
    common = {"result_id": result["result_id"], "path": path}
    chunks, offset = [], 0
    while True:
        response = asyncio.run(runtime.mcp.call_tool("read_result", {**common, "offset_chars": offset}))
        payload = response.structured_content["result"]
        assert _call_tool_result_wire_chars(response) <= 12000
        assert payload["path"] == path and payload["total_chars"] == len(text)
        chunks.append(payload["chunk"])
        if not payload["has_more"]:
            break
        assert payload["next_offset_chars"] > offset
        offset = payload["next_offset_chars"]
    assert "".join(chunks) == text
    query = {**common, "pattern": '"quoted"', "max_matches": 1, "count_mode": "none"}
    first = asyncio.run(runtime.mcp.call_tool("search_result", query)).structured_content["result"]
    found = first["matches"][0]
    assert text[found["offset_chars"] : found["end_offset"]] == '"quoted"'
    second = asyncio.run(
        runtime.mcp.call_tool("search_result", {**query, "cursor": first["next_cursor"]})
    ).structured_content["result"]
    assert second["matches"][0]["offset_chars"] > found["offset_chars"]
    for different_path in ("", "/items/1/data"):
        with pytest.raises(ToolError, match="cursor"):
            asyncio.run(
                runtime.mcp.call_tool(
                    "search_result", {**query, "path": different_path, "cursor": first["next_cursor"]}
                )
            )


@pytest.mark.parametrize("path", ["/items/0/data", "/items/9/data"])
def test_text_path_rejects_nonstring_or_missing_item(path):
    runtime = server(Registry(lambda *_: {"comment": "x" * 5000}))
    _, result = call(runtime, requests=[request()], max_output_chars=2048)
    with pytest.raises(ToolError, match="not a JSON string|does not exist"):
        asyncio.run(runtime.mcp.call_tool("read_result", {"result_id": result["result_id"], "path": path}))


def test_decoded_path_respects_smallest_complete_response_budget():
    runtime = server(
        Registry(lambda *_: "\x00" * 10000),
        config=ToolPresentationConfig(large_result_threshold_chars=100, large_result_preview_chars=100),
    )
    _, result = call(runtime, requests=[request(tool="decompile_function")], max_output_chars=2048)
    common = {"result_id": result["result_id"], "path": "/items/0/data"}
    for tool, args in [
        ("read_result", {}),
        ("search_result", {"pattern": "\x00", "max_matches": 1, "count_mode": "none"}),
    ]:
        response = asyncio.run(runtime.mcp.call_tool(tool, {**common, **args}))
        assert _call_tool_result_wire_chars(response) <= 1024


def test_decoded_item_size_is_bounded_before_loading(monkeypatch):
    from ghidra_mcp.presentation import result_json

    runtime = server(Registry(lambda *_: "x" * 5000))
    _, result = call(runtime, requests=[request(tool="decompile_function")], max_output_chars=2048)
    monkeypatch.setattr(result_json, "_MAX_TEXT_ITEM_CHARS", 1024)
    with pytest.raises(ToolError, match="decode budget"):
        asyncio.run(runtime.mcp.call_tool("read_result", {"result_id": result["result_id"], "path": "/items/0/data"}))
