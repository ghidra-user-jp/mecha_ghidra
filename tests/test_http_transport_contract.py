"""Exercise the production HTTP settings without sockets, a JVM or a live project."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from types import SimpleNamespace

import pytest

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.transport import run_kwargs_for_transport, run_mcp_server

_VERSION = "2026-07-28"


class Registry:
    def __init__(self):
        self.calls = []
        self.payload = "int main(void) { return 42; }\n" + "/* analysis detail */\n" * 1000

    def list_targets(self):
        return [{"target": "sample"}]

    def call(self, command, params, target):
        self.calls.append((command, params, target))
        assert command == "decompile_function"
        return self.payload


def runtime_and_app(transport="http", *, result_cache_max_entries=512):
    registry = Registry()
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("list_targets", "decompile_function", "list_functions")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=ToolPresentationConfig(
            large_result_threshold_chars=1500,
            large_result_preview_chars=100,
            result_cache_max_entries=result_cache_max_entries,
        ),
    )
    args = SimpleNamespace(log_level="WARNING", mcp_host="127.0.0.1", mcp_port=None, mcp_path="/mcp")
    kwargs = run_kwargs_for_transport(transport=transport, args=args, logger=logging.getLogger(__name__))
    kwargs.pop("port")  # ASGI has no listening socket; all other production settings apply.
    return runtime, registry, runtime.mcp.streamable_http_app(**kwargs)


async def request(app, method="tools/list", params=None, *, modern=True, headers=None, http_method="POST"):
    """One independent HTTP exchange; deliberately keep no cookies/session headers."""
    params = dict(params or {})
    request_headers = {
        "host": "localhost",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
    }
    if modern:
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": _VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "offline-contract-test", "version": "1"},
        }
        request_headers.update({"mcp-protocol-version": _VERSION, "mcp-method": method})
        if "name" in params or "uri" in params:
            request_headers["mcp-name"] = params.get("name", params.get("uri"))
    request_headers.update(headers or {})
    wire = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    messages = []
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": wire, "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": http_method,
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "root_path": "",
        "query_string": b"",
        "headers": [(key.encode(), value.encode()) for key, value in request_headers.items()],
        "server": ("localhost", 80),
        "client": ("127.0.0.1", 1234),
    }
    await asyncio.wait_for(app(scope, receive, send), timeout=5)
    start = next(item for item in messages if item["type"] == "http.response.start")
    response_headers = dict(start["headers"])
    assert b"mcp-session-id" not in response_headers
    body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
    if b"application/json" in response_headers.get(b"content-type", b""):
        return start["status"], json.loads(body)
    return start["status"], body


def successful_result(response):
    status, data = response
    assert status == 200
    assert "error" not in data, data
    return data["result"]


def tool_json(result):
    assert result["isError"] is False
    return json.loads(result["content"][0]["text"])


@pytest.mark.parametrize("transport", ["http", "streamable-http"])
def test_direct_tool_calls_and_result_reads_are_sessionless_json(transport):
    async def check():
        runtime, registry, app = runtime_and_app(transport)
        async with app.router.lifespan_context(app):
            # The very first request calls a tool; no initialize/discover is needed.
            call = successful_result(
                await request(
                    app, "tools/call", {"name": "decompile_function", "arguments": {"name": "main", "target": "sample"}}
                )
            )
            assert call["isError"] is False
            metadata = call["structuredContent"]
            assert metadata["target"] == "sample"
            assert metadata["truncated"] is True
            assert registry.calls == [("decompile_function", {"name": "main"}, "sample")]

            targets = successful_result(await request(app, "tools/call", {"name": "list_targets", "arguments": {}}))
            assert targets["isError"] is False
            assert [json.loads(item["text"]) for item in targets["content"]] == [{"target": "sample"}]
            read = successful_result(
                await request(
                    app,
                    "tools/call",
                    {"name": "read_result", "arguments": {"result_id": metadata["result_id"], "limit_chars": 40}},
                )
            )
            assert tool_json(read)["chunk"] == registry.payload[:40]
            search = successful_result(
                await request(
                    app,
                    "tools/call",
                    {
                        "name": "search_result",
                        "arguments": {"result_id": metadata["result_id"], "pattern": "return 42"},
                    },
                )
            )
            assert tool_json(search)["matches"]
            resource = successful_result(await request(app, "resources/read", {"uri": metadata["resource_uri"]}))
            assert resource["contents"][0]["text"] == registry.payload
            assert runtime.result_store.get(metadata["result_id"]).text == registry.payload
            assert len(registry.calls) == 1  # Follow-up reads never re-execute the analysis.

    asyncio.run(check())


def test_pending_analysis_does_not_require_a_session_or_block_target_discovery():
    async def check():
        _, registry, app = runtime_and_app()
        started = threading.Event()
        release = threading.Event()
        original_call = registry.call

        def blocking_call(*args):
            started.set()
            assert release.wait(3), "test did not release analysis"
            return original_call(*args)

        registry.call = blocking_call
        async with app.router.lifespan_context(app):
            pending = asyncio.create_task(
                request(
                    app, "tools/call", {"name": "decompile_function", "arguments": {"name": "main", "target": "sample"}}
                )
            )
            try:
                assert await asyncio.to_thread(started.wait, 2)
                assert not pending.done()
                targets = successful_result(await request(app, "tools/call", {"name": "list_targets", "arguments": {}}))
                assert targets["isError"] is False
                assert not pending.done()
            finally:
                release.set()
                result = successful_result(await pending)
            assert result["isError"] is False
            assert result["structuredContent"]["target"] == "sample"
            assert len(registry.calls) == 1

    asyncio.run(check())


def test_discovery_exposes_filtered_instructions_and_tools():
    async def check():
        runtime, _, app = runtime_and_app()
        async with app.router.lifespan_context(app):
            discovery = successful_result(await request(app, "server/discover"))
            assert discovery["instructions"] == runtime.mcp.instructions
            assert "decompilation" in discovery["instructions"]
            assert "type edits" not in discovery["instructions"]
            catalog = successful_result(await request(app))
            assert {tool["name"] for tool in catalog["tools"]} == {
                "list_targets",
                "decompile_function",
                "list_functions",
                "read_result",
                "search_result",
            }

    asyncio.run(check())


def test_initialize_cannot_create_an_http_session():
    async def check():
        runtime, _, app = runtime_and_app()
        async with app.router.lifespan_context(app):
            result = successful_result(
                await request(
                    app,
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "session-test", "version": "1"},
                    },
                    modern=False,
                )
            )
            assert result["instructions"] == runtime.mcp.instructions
            assert successful_result(await request(app, modern=False, headers={"mcp-protocol-version": "2025-11-25"}))[
                "tools"
            ]

    asyncio.run(check())


@pytest.mark.parametrize(
    ("headers", "status"), [({"origin": "https://example.invalid"}, 403), ({"host": "example.invalid"}, 421)]
)
def test_stateless_http_preserves_host_and_origin_restrictions(headers, status):
    async def check():
        _, registry, app = runtime_and_app()
        async with app.router.lifespan_context(app):
            actual_status, _ = await request(app, headers=headers)
            assert actual_status == status
            assert not registry.calls

    asyncio.run(check())


def test_invalid_tool_arguments_do_not_execute_backend():
    async def check():
        _, registry, app = runtime_and_app()
        async with app.router.lifespan_context(app):
            result = successful_result(
                await request(app, "tools/call", {"name": "list_functions", "arguments": {"limit": "2"}})
            )
            assert result["isError"] is True
            assert not registry.calls

    asyncio.run(check())


@pytest.mark.parametrize("missing", ["tool_doc", "result", "evicted_result"])
def test_missing_resource_returns_invalid_params_with_uri_without_reexecuting(missing):
    async def check():
        runtime, registry, app = runtime_and_app(result_cache_max_entries=1)
        uri = "ghidra://docs/tools/unpublished_tool" if missing == "tool_doc" else "ghidra://results/deadbeefdeadbeef"
        if missing == "evicted_result":
            for text in ("evicted", "retained"):
                entry = runtime.result_store.add(
                    tool="decompile_function",
                    target="sample",
                    text=text,
                    mime_type="text/x-c",
                    result_type="string",
                    item_count=None,
                )
                if text == "evicted":
                    uri = entry.uri
        async with app.router.lifespan_context(app):
            status, response = await request(app, "resources/read", {"uri": uri})
            assert response["error"]["code"] == -32602
            assert status == 400  # The modern transport maps INVALID_PARAMS to HTTP 400.
            assert response["error"]["data"] == {"uri": uri}
            assert response["error"]["message"] != "Internal server error"
            if missing != "tool_doc":
                assert "Do not automatically re-run" in response["error"]["message"]
            # A rejected read leaves the server usable and never repeats analysis.
            docs = successful_result(await request(app, "resources/read", {"uri": "ghidra://docs/tools"}))
            assert docs["contents"]
            assert registry.calls == []

    asyncio.run(check())


@pytest.mark.parametrize(("raw", "expected"), [("warn", "warning"), ("FATAL", "critical"), ("Debug", "debug")])
def test_run_mcp_server_normalises_cli_log_level_aliases_for_uvicorn(monkeypatch, raw, expected):
    """uvicorn only knows its own level names: WARN/FATAL raised KeyError before serving."""
    import uvicorn
    from starlette.applications import Starlette

    served = []

    async def serve(self):
        served.append(self.config)

    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    apps = []

    def streamable_http_app(**kwargs):
        apps.append(kwargs)
        return Starlette()

    server = SimpleNamespace(streamable_http_app=streamable_http_app)
    run_mcp_server(server, transport="http", log_level=raw, host="127.0.0.1", port=0, stateless_http=True)
    assert apps == [{"host": "127.0.0.1", "stateless_http": True}]
    assert len(served) == 1 and served[0].log_level == expected
    assert (served[0].host, served[0].port) == ("127.0.0.1", 0)
