"""Batch contracts, runtime invariants and real SDK response/retrieval paths."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from mcp.types import CallToolRequestParams

from ghidra_headless.contracts.batch_read import BATCH_READ_TOOLS
from ghidra_headless.handlers.commands.batch_read import batch_read
from ghidra_mcp.contracts.tool_spec import filter_tool_specs, get_all_tool_specs
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.doc_resources import tool_docs_detail
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_errors import ToolError


def request(id="a", tool="get_function", arguments=None, **extra):
    return {"id": id, "tool": tool, "arguments": {"address": "0x1000"} if arguments is None else arguments, **extra}


def context():
    program = SimpleNamespace(revision=0)
    program.getModificationNumber = lambda: program.revision
    program.getDomainFile = lambda: SimpleNamespace(getPathname=lambda: "/tiny.bin")
    return SimpleNamespace(generation="generation", program=program)


class Registry:
    def __init__(self, execute=None):
        self.ctx = context()
        self.calls = []
        self.reads = []
        self.execute = execute or (lambda _tool, _args: {"name": "main", "entry": "00001000"})

    def read(self, tool, args):
        self.reads.append((tool, args))
        return self.execute(tool, args)

    def call(self, tool, params, target):
        self.calls.append((tool, params, target))
        if tool == "batch_read":
            return batch_read(params, ensure_context=lambda: self.ctx, execute_read=self.read)
        return self.read(tool, params)


def server(registry=None, *, specs=None, config=None):
    return create_mcp_server(
        specs=get_all_tool_specs() if specs is None else specs,
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=config,
    )


def call(runtime, **arguments):
    result = asyncio.run(runtime.mcp.call_tool("batch_read", arguments))
    return result, json.loads(result.content[0].text)


def test_one_core_call_preserves_order_and_projects_fields():
    registry = Registry()
    result, payload = call(server(registry), requests=[request(), request("b", fields=["name"])])
    assert not result.is_error
    assert payload["status"] == "ok" and payload["succeeded_count"] == 2
    assert [item["id"] for item in payload["items"]] == ["a", "b"]
    assert payload["items"][0]["data"] == {"name": "main", "entry": "00001000"}
    assert payload["items"][1]["data"] == {"name": "main"}
    assert len(registry.calls) == 1 and registry.calls[0][0] == "batch_read"
    assert len(registry.reads) == 2


@pytest.mark.parametrize(
    "requests",
    [
        [],
        [request(str(i)) for i in range(21)],
        [request(), request()],
        [request(tool="run_script")],
        [request(tool="batch_read")],
        [request(arguments={})],
        [request(arguments={"address": "0x1", "target": "other"})],
        [request(arguments={"address": 123})],
        [request(id="bad\nid")],
        [request(), request("b", tool="get_xrefs", arguments={"address": "x", "limit": "2"})],
        [request(tool="get_xrefs", arguments={"address": "x", "direction": "bad"})],
        [request(tool="get_call_edges", arguments={"address": "x", "limit": 2001})],
        [request(fields=[])],
        [request(fields=["x"] * 33)],
    ],
)
def test_invalid_batch_never_reaches_runtime(requests):
    registry = Registry()
    with pytest.raises(ToolError):
        call(server(registry), requests=requests)
    assert registry.calls == []


def test_filtered_tool_cannot_be_called_through_batch():
    specs = get_all_tool_specs()
    del specs["get_function"]
    registry = Registry()
    with pytest.raises(ToolError, match="not enabled"):
        call(server(registry, specs=specs), requests=[request()])
    assert registry.calls == []


def test_readonly_profile_exposes_batch_and_allowed_children():
    specs = filter_tool_specs(profile="readonly")
    assert {"batch_read", *BATCH_READ_TOOLS} <= set(specs)
    assert "run_script" not in specs


def test_contract_and_core_guard_share_one_rule_set():
    """The MCP input model re-exports the core's allowlist and calls its validator: no second copy to drift."""
    from ghidra_headless.contracts.batch_read import validate_requests
    from ghidra_mcp.contracts import batch_models

    assert batch_models.BATCH_READ_TOOLS is BATCH_READ_TOOLS
    assert batch_models.validate_requests is validate_requests


def test_item_errors_continue_and_all_failed_sets_mcp_error():
    def execute(_tool, args):
        if args["address"] == "missing":
            raise LookupError("Function not found")
        return {"name": "main"}

    registry = Registry(execute)
    runtime = server(registry)
    missing = request("missing", arguments={"address": "missing"})
    result, payload = call(runtime, requests=[missing, request()])
    assert not result.is_error and payload["status"] == "partial"
    assert payload["failed_count"] == payload["succeeded_count"] == 1
    assert payload["items"][0]["error"]["code"] == "NOT_FOUND"
    result, payload = call(runtime, requests=[missing])
    assert result.is_error and payload["status"] == "error"


def test_unexpected_backend_failure_is_not_silently_an_item_error():
    def execute(_tool, _args):
        raise RuntimeError("backend is broken")

    registry = Registry(execute)
    with pytest.raises(RuntimeError, match="backend is broken"):
        dispatch_tool("batch_read", {"requests": [request(), request("b")]}, "default", registry=registry)
    assert len(registry.reads) == 1


@pytest.mark.parametrize("during", [False, True])
def test_revision_change_fails_whole_batch(during):
    registry = Registry()

    def execute(_tool, _args):
        registry.ctx.program.revision += 1
        return {"name": "main"}

    if during:
        registry.execute = execute
    result = asyncio.run(
        server(registry).mcp.handle_call_tool(
            None,
            CallToolRequestParams(
                name="batch_read",
                arguments={"requests": [request()], "expected_revision": "generation:0" if during else "old"},
            ),
        )
    )
    assert result.is_error and "SESSION_CHANGED" in result.content[0].text
    assert len(registry.reads) == (1 if during else 0)


def test_deadline_returns_unstarted_ids_without_running_them():
    ctx = context()
    ticks = iter([0, 0, 11, 11])
    reads = []
    result = batch_read(
        {"requests": [request(), request("b"), request("c")]},
        ensure_context=lambda: ctx,
        execute_read=lambda tool, args: reads.append((tool, args)) or {},
        clock=lambda: next(ticks),
    )
    assert len(reads) == 1
    assert result["status"] == "partial" and result["not_run_count"] == 2
    assert [item["status"] for item in result["items"]] == ["ok", "not_run", "not_run"]


def test_core_guard_rejects_unsupported_command_before_any_read():
    with pytest.raises(ValueError, match="unsupported"):
        batch_read(
            {"requests": [request(), request("b", tool="run_script")]},
            ensure_context=context,
            execute_read=lambda *_: pytest.fail("executed"),
        )


def test_paged_projection_preserves_metadata_and_cursor():
    data = {
        "program": "/tiny.bin",
        "revision": "generation:0",
        "items": [{"from": "a", "to": "b"}],
        "has_more": True,
        "next_cursor": "cursor",
    }
    _, payload = call(server(Registry(lambda *_: data)), requests=[request(tool="get_xrefs", fields=["from"])])
    projected = payload["items"][0]["data"]
    assert projected == {**data, "items": [{"from": "a"}]}
    assert data["items"][0] == {"from": "a", "to": "b"}


def test_large_batch_is_bounded_and_retrieved_from_one_entry():
    large = '日本語\n"\\' * 2000
    registry = Registry(lambda *_: {"name": "main", "comment": large})
    runtime = server(registry)
    result, payload = call(runtime, requests=[request(), request("b", fields=["name"])], max_output_chars=2048)
    assert not result.is_error and len(result.content[0].text) <= 2048
    assert payload["truncated"] and payload["succeeded_count"] == 2
    assert payload["items"][0]["offset_items"] == 0
    assert payload["items"][1]["data"] == {"name": "main"}
    assert len(runtime.result_store._entries) == 1
    read = asyncio.run(
        runtime.mcp.call_tool(
            "read_result",
            {
                "result_id": payload["result_id"],
                "mode": "json",
                "path": "/items",
                "offset_items": 1,
                "limit_items": 1,
            },
        )
    )
    assert json.loads(read.content[0].text)["items"][0]["data"] == {"name": "main"}
    stored = json.loads(runtime.result_store.read_text(payload["result_id"]))
    assert stored["items"][0]["data"]["comment"] == large


def test_large_early_success_does_not_hide_later_error():
    def execute(_tool, args):
        if args["address"] == "missing":
            raise LookupError("long diagnostic" * 5000)
        return {"comment": "x" * 30000}

    runtime = server(Registry(execute))
    result, payload = call(
        runtime, requests=[request(), request("b", arguments={"address": "missing"})], max_output_chars=2048
    )
    assert not result.is_error and len(result.content[0].text) <= 2048
    assert payload["status"] == "partial" and payload["failed_count"] == 1
    assert payload["items"][1]["error_code"] == "NOT_FOUND"
    stored = json.loads(runtime.result_store.read_text(payload["result_id"]))
    assert stored["items"][1]["error"]["message"] == "long diagnostic" * 5000


def test_cache_refusal_is_explicit_and_has_no_dangling_id():
    runtime = server(
        Registry(lambda *_: {"comment": "x" * 30000}), config=ToolPresentationConfig(result_cache_max_bytes=1)
    )
    result, payload = call(runtime, requests=[request()], max_output_chars=2048)
    assert not result.is_error
    assert payload["result_unavailable"] and "result_id" not in payload
    assert payload["succeeded_count"] == 1


def test_inline_mode_rejects_oversized_output_with_actionable_error():
    runtime = server(
        Registry(lambda *_: {"comment": "x" * 30000}), config=ToolPresentationConfig(large_result_mode="inline")
    )
    with pytest.raises(ToolError, match="narrow fields"):
        call(runtime, requests=[request()], max_output_chars=2048)


def test_smallest_budget_handles_twenty_errors_and_long_metadata():
    def execute(*_):
        raise LookupError("x" * 30000)

    registry = Registry(execute)
    registry.ctx.program.getDomainFile = lambda: SimpleNamespace(getPathname=lambda: '"' * 10000)
    runtime = server(registry)
    result, payload = call(runtime, requests=[request(str(i).zfill(32)) for i in range(20)], max_output_chars=2048)
    assert result.is_error and len(result.content[0].text) <= 2048
    assert payload["failed_count"] == 20 and payload["item_summaries_omitted"]
    assert payload["metadata_truncated"]
    retrieval = {**payload["retrieval"], "result_id": payload["result_id"]}
    tool = retrieval.pop("tool")
    read = asyncio.run(runtime.mcp.call_tool(tool, retrieval))
    statuses = json.loads(read.content[0].text)["items"]
    assert len(statuses) == 20 and all(item["status"] == "error" for item in statuses)


@pytest.mark.parametrize("kind", ["small", "large", "unavailable"])
def test_documented_batch_schema_matches_actual_response(kind):
    config = ToolPresentationConfig(result_cache_max_bytes=1 if kind == "unavailable" else 1_000_000)
    runtime = server(Registry(lambda *_: {"comment": "x" * (10 if kind == "small" else 30000)}), config=config)
    result, payload = call(runtime, requests=[request()], max_output_chars=2048)
    docs = tool_docs_detail(get_all_tool_specs()["batch_read"])
    Draft202012Validator.check_schema(docs["response_text_schema"])
    Draft202012Validator(docs["response_text_schema"]).validate(payload)
    Draft202012Validator(docs["large_result_output_schema"]).validate(result.model_dump(mode="json", by_alias=True))
    advertised = next(tool for tool in asyncio.run(runtime.mcp.list_tools()) if tool.name == "batch_read")
    assert advertised.output_schema == docs["structured_output_schema"]
    Draft202012Validator(advertised.output_schema).validate(result.structured_content)
    assert result.structured_content == {"result": payload}
    assert len(result.content[0].text) <= 2048


def test_max_output_chars_bounds_the_response_json_text_not_the_mcp_envelope():
    from ghidra_mcp.presentation.result_compaction import _call_tool_result_wire_chars

    runtime = server(Registry(lambda *_: {"comment": "x" * 6000}))
    result, payload = call(runtime, requests=[request()])
    json_chars = len(result.content[0].text)
    assert 6000 < json_chars < 12000 and "truncated" not in payload

    # structuredContent duplicates the text block, so the wire size is roughly
    # double: a budget equal to the JSON text must still deliver the result inline.
    inline, inline_payload = call(runtime, requests=[request()], max_output_chars=json_chars)
    assert inline_payload == payload and not runtime.result_store._entries
    assert _call_tool_result_wire_chars(inline) > json_chars

    compacted, compacted_payload = call(runtime, requests=[request()], max_output_chars=json_chars - 1)
    assert compacted_payload["truncated"] and "result_id" in compacted_payload
    assert len(compacted.content[0].text) <= json_chars - 1
    assert compacted_payload["items"] == [{"id": "a", "status": "ok", "offset_items": 0}]


def test_ambiguous_query_preserves_candidates_and_continues():
    from ghidra_headless.errors import HeadlessError

    def execute(_tool, args):
        if args.get("name"):
            raise HeadlessError("AMBIGUOUS_FUNCTION: select a qualified name", details={"candidates": ["A::f", "B::f"]})
        return {"name": "main"}

    _, payload = call(server(Registry(execute)), requests=[request(arguments={"name": "f"}), request("b")])
    assert payload["status"] == "partial"
    assert payload["items"][0]["error"]["details"]["candidates"] == ["A::f", "B::f"]


def test_lone_surrogate_is_normalized_on_batch_response_path():
    result, payload = call(server(Registry(lambda *_: {"comment": "text\ud800"})), requests=[request()])
    assert not result.is_error
    assert payload["items"][0]["data"]["comment"] == "text\ufffd"


@pytest.mark.parametrize(
    "extra", [{"timeout_seconds": 0}, {"timeout_seconds": True}, {"max_output_chars": 2047}, {"typo": 1}]
)
def test_invalid_global_limits_fail_before_execution(extra):
    registry = Registry()
    with pytest.raises(ToolError):
        call(server(registry), requests=[request()], **extra)
    assert registry.calls == []
