"""A relay passes a reply that arrives as an event stream on message by message (progress), without a JVM."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import httpx2
import pytest
import uvicorn

from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.gui_relay import (
    KEEPALIVE,
    Answer,
    BadReply,
    Fallback,
    Relay,
    RuntimeEndpoint,
    RuntimeGone,
    _event_messages,
    _http_relay_app,
)
from http_support import product_app
from test_gui_relay import GUI_SPECS, INIT, call, error_of
from test_progress import DECOMPILE, PSEUDOCODE, Registry, build_server

PROGRESS = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "t", "progress": 1}}


def reply_to(message_id, **result):
    return {"jsonrpc": "2.0", "id": message_id, "result": {"content": [], "structuredContent": result}}


async def lines(*text: str):
    for line in text:
        yield line


async def collect(stream):
    return [item async for item in stream]


class TestEventParser:
    def parse(self, *text: str):
        return asyncio.run(collect(_event_messages(lines(*text))))

    def test_an_event_is_its_data_lines_joined_up_to_the_blank_line(self):
        assert self.parse('data: {"a":', "data: 1}", "", 'data: {"b": 2}', "") == [{"a": 1}, {"b": 2}]

    def test_the_space_after_the_colon_is_optional_and_other_fields_are_ignored(self):
        assert self.parse("event: message", 'data:{"a":1}', "id: 7", "retry: 10", "") == [{"a": 1}]

    def test_a_comment_is_a_keepalive_and_reaches_the_client_as_one(self):
        assert self.parse(": ping", "", 'data: {"a": 1}', "") == [KEEPALIVE, {"a": 1}]

    def test_a_stream_that_ends_inside_an_event_still_delivers_it(self):
        assert self.parse('data: {"a": 1}') == [{"a": 1}]

    def test_an_event_without_data_is_nothing(self):
        assert self.parse("event: message", "") == []

    def test_data_that_is_no_json_is_a_bad_reply(self):
        with pytest.raises(BadReply):
            self.parse("data: not json", "")


class Scripted:
    """A runtime whose reply is a scripted sequence: each item is sent on, raised (an exception) or waited for."""

    def __init__(self, *script, status: int = 200) -> None:
        self.record = SimpleNamespace(runtime_id="r1", token="t")
        self.script = script
        self.status = status
        self.closed = threading.Event()
        self.messages_closed = threading.Event()

    @contextlib.asynccontextmanager
    async def post(self, body: bytes, routing):
        async def messages():
            try:
                for step in self.script:
                    if isinstance(step, BaseException):
                        raise step
                    if step == "wait":
                        await asyncio.Event().wait()
                    yield step
            finally:
                self.messages_closed.set()

        try:
            yield Answer(self.status, messages())
        finally:
            self.closed.set()


def run_relay(scenario, runtime, *, specs=GUI_SPECS):
    async def main():
        fallback = Fallback(specs, ToolPresentationConfig())
        async with fallback.running():
            return await scenario(Relay(specs=specs, fallback=fallback, runtime=runtime, refusal=None))

    return asyncio.run(main())


async def replies(relay, message):
    async with relay.open(message) as reply:
        return reply.status, [item async for item in reply.messages]


class TestRelay:
    def test_notifications_come_first_and_then_the_reply(self):
        runtime = Scripted(PROGRESS, KEEPALIVE, PROGRESS, reply_to(7, result="done"))

        async def scenario(relay):
            return await replies(relay, call("get_program_info"))

        status, items = run_relay(scenario, runtime)
        assert status == 200 and items[:3] == [PROGRESS, KEEPALIVE, PROGRESS]
        assert items[3]["id"] == 7 and items[3]["result"]["structuredContent"] == {"result": "done"}
        assert runtime.closed.is_set() and runtime.messages_closed.is_set()

    def test_one_json_body_has_no_room_for_them(self):
        runtime = Scripted(PROGRESS, KEEPALIVE, reply_to(7, result="done"))

        async def scenario(relay):
            return await relay.exchange(call("get_program_info"))

        status, reply = run_relay(scenario, runtime)
        assert status == 200 and reply["id"] == 7 and reply["result"]["structuredContent"] == {"result": "done"}

    def test_a_notification_of_the_client_has_no_reply(self):
        async def scenario(relay):
            return await replies(relay, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        assert run_relay(scenario, Scripted(status=202)) == (202, [])

    def test_a_reply_that_is_no_json_rpc_becomes_an_error_with_the_request_id(self):
        runtime = Scripted(BadReply("Expecting value"), status=502)

        async def scenario(relay):
            return await replies(relay, call("get_program_info", 9))

        status, (reply,) = run_relay(scenario, runtime)
        assert status == 502 and reply["id"] == 9 and reply["error"]["code"] == -32603
        assert "HTTP 502" in reply["error"]["message"]

    def test_a_runtime_that_goes_while_it_reports_leaves_an_uncertain_write_and_the_relay_gone(self):
        runtime = Scripted(PROGRESS, RuntimeGone("reset", reached=True))

        async def scenario(relay):
            first = await replies(relay, call("create_label", address="0x1", name="ai"))
            second = await replies(relay, call("get_program_info", 8))
            return first, second

        (status, items), (_, (later,)) = run_relay(scenario, runtime)
        assert status == 200 and items[0] == PROGRESS and len(items) == 2
        assert error_of(items[1])["details"]["outcome"] == "unknown"
        assert error_of(items[1])["details"]["output_state"] == "uncertain"
        assert error_of(later)["details"]["reason"] == "runtime_gone"

    def test_a_stream_that_ends_without_a_reply_is_an_error_and_not_silence(self):
        async def scenario(relay):
            return await replies(relay, call("get_program_info", 5))

        _, items = run_relay(scenario, Scripted(PROGRESS, KEEPALIVE))
        assert items[:2] == [PROGRESS, KEEPALIVE]
        assert items[2]["id"] == 5 and error_of(items[2])["code"] == "RUNTIME_UNAVAILABLE"

    def test_a_request_other_than_a_call_that_the_runtime_drops_gets_a_json_rpc_error(self):
        runtime = Scripted(RuntimeGone("reset", reached=True))

        async def scenario(relay):
            return await replies(relay, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})

        _, (reply,) = run_relay(scenario, runtime)
        assert reply["id"] == 3 and reply["error"]["code"] == -32603


def http_call():
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "get_program_info"}}


ACCEPT = {"Accept": "application/json, text/event-stream"}


def events_in(text: str) -> list:
    frames = text.replace("\r\n", "\n").split("\n\n")
    return [
        json.loads("".join(line[5:].strip() for line in frame.splitlines() if line.startswith("data:")))
        for frame in frames
        if any(line.startswith("data:") for line in frame.splitlines())
    ]


class TestHttpRelay:
    def post(self, runtime, body=None):
        async def scenario(relay):
            app = _http_relay_app(relay, path="/mcp", host="127.0.0.1")
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
                return await c.post("/mcp", json=body or http_call(), headers=ACCEPT)

        return run_relay(scenario, runtime)

    def test_a_plain_reply_stays_plain_json(self):
        response = self.post(Scripted(reply_to(7, result="done")))
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["result"]["structuredContent"] == {"result": "done"}

    def test_a_reply_that_began_with_pings_is_still_plain_json(self):
        response = self.post(Scripted(KEEPALIVE, reply_to(7, result="done")))
        assert response.headers["content-type"].startswith("application/json")

    def test_a_reply_with_progress_is_an_event_stream_with_every_message_in_order(self):
        response = self.post(Scripted(PROGRESS, KEEPALIVE, PROGRESS, reply_to(7, result="done")))
        assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-cache, no-transform"
        assert ": ping" in response.text
        *progress, final = events_in(response.text)
        assert progress == [PROGRESS, PROGRESS]
        assert final["id"] == 7 and final["result"]["structuredContent"] == {"result": "done"}

    def test_a_notification_of_the_client_is_answered_202(self):
        response = self.post(Scripted(status=202), {"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert response.status_code == 202

    def test_a_batch_is_answered_as_one_json_body(self):
        response = self.post(Scripted(reply_to(1, a=1)), [http_call()])
        assert response.headers["content-type"].startswith("application/json")
        assert isinstance(response.json(), list)

    def test_the_runtime_is_closed_when_the_client_goes_away(self):
        runtime = Scripted(PROGRESS, "wait")

        async def scenario(relay):
            app = _http_relay_app(relay, path="/mcp", host="127.0.0.1")
            body = json.dumps(http_call()).encode()
            scope = {
                "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
                "method": "POST", "path": "/mcp", "raw_path": b"/mcp", "query_string": b"", "scheme": "http",
                "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1),
                "headers": [
                    (b"host", b"127.0.0.1"), (b"content-type", b"application/json"), (b"accept", b"text/event-stream"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }  # fmt: skip
            gone = asyncio.Event()
            delivered = []

            async def receive():
                if not delivered:
                    delivered.append(True)
                    return {"type": "http.request", "body": body, "more_body": False}
                await gone.wait()
                return {"type": "http.disconnect"}

            sent = []

            async def send(message):
                sent.append(message)
                if message["type"] == "http.response.body" and message.get("body"):
                    gone.set()  # the client leaves after the first event

            with anyio.fail_after(5):
                await app(scope, receive, send)
            return sent

        sent = run_relay(scenario, runtime)
        assert sent[0]["status"] == 200 and b"notifications/progress" in sent[1]["body"]
        assert runtime.closed.is_set() and runtime.messages_closed.is_set(), "the runtime's connection stayed open"


# ---- a real runtime: the product's HTTP app under uvicorn, reached through RuntimeEndpoint ------------------------


@contextlib.contextmanager
def serving_runtime(registry):
    """The product's MCP server on a free loopback port; yields the record a relay would read."""
    server = build_server(registry, defer_after=10)
    app = product_app(server)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    http = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=http.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not http.started:
        assert thread.is_alive() and time.monotonic() < deadline, "the runtime did not start"
        time.sleep(0.01)
    try:
        yield SimpleNamespace(runtime_id="r1", token="t", endpoint=f"http://127.0.0.1:{port}/mcp")
    finally:
        registry.release.set()
        http.should_exit = True
        thread.join(10)


MODERN = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}


class TestARealRuntime:
    def test_progress_reaches_the_client_while_the_call_runs(self, monkeypatch):
        monkeypatch.setattr("ghidra_mcp.presentation.progress.INTERVAL_SECONDS", 0.05)
        registry = Registry()
        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "decompile_function",
                "arguments": DECOMPILE,
                "_meta": {**MODERN, "progressToken": "t"},
            },
        }
        arrivals: list[tuple[float, dict]] = []

        async def scenario(relay):
            threading.Timer(0.6, registry.release.set).start()
            async with relay.open(message) as reply:
                async for item in reply.messages:
                    arrivals.append((time.monotonic(), item))

        with serving_runtime(registry) as record:
            endpoint = RuntimeEndpoint(record)

            async def main():
                fallback = Fallback(GUI_SPECS, ToolPresentationConfig())
                async with fallback.running(), endpoint.connected():
                    await scenario(Relay(specs=GUI_SPECS, fallback=fallback, runtime=endpoint, refusal=None))

            asyncio.run(main())

        *progress, (finished, final) = arrivals
        assert len(progress) >= 3 and all(item["method"] == "notifications/progress" for _, item in progress)
        assert final["id"] == 7 and final["result"]["structuredContent"] == {"result": PSEUDOCODE}
        # Each report came when it was sent, not with the reply at the end.
        assert finished - progress[0][0] > 0.3
        assert [item["params"]["progress"] for _, item in progress] == sorted(
            {i["params"]["progress"] for _, i in progress}
        )


class TestStdioRelay:
    """The relay's stdio loop, as a client reads it: one JSON-RPC message per line, progress before the reply."""

    def test_progress_lines_come_before_the_reply_and_no_ping_is_written(self):
        server = Path(__file__).with_name("relay_stdio_server.py")
        process = subprocess.Popen(
            [sys.executable, str(server)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:

            def send(message):
                process.stdin.write(json.dumps(message).encode() + b"\n")
                process.stdin.flush()

            def read():
                return json.loads(process.stdout.readline())

            send(INIT)
            assert read()["result"]["serverInfo"]["name"] == "r"
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            call_with_token = call("get_program_info") | {
                "params": {"name": "get_program_info", "arguments": {}, "_meta": {"progressToken": "p1"}}
            }
            send(call_with_token)
            *progress, reply = [read() for _ in range(4)]
            assert [item["method"] for item in progress] == ["notifications/progress"] * 3
            assert [item["params"]["progress"] for item in progress] == [1, 2, 3]
            assert {item["params"]["progressToken"] for item in progress} == {"p1"}
            assert reply["id"] == 7 and reply["result"]["structuredContent"] == {"result": {"from": "runtime"}}
            process.stdin.close()  # the client ends: the relay finishes what it has and exits
            assert process.wait(10) == 0, process.stderr.read().decode()
            assert process.stdout.read() == b"", "nothing but the messages above was written"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(5)
