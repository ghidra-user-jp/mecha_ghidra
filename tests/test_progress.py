"""Progress notifications: a call that waits tells a client that asked for them, and only that client."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import anyio
import pytest

from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation import progress as progress_module
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.progress import ProgressReporter, ticking
from ghidra_mcp.presentation.startup import StartupGate
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from http_support import VERSION, messages_in, post, serving_app

PSEUDOCODE = "int main(void) { return 0; }"
DECOMPILE = {"target": "default", "address": "0x1000"}
EDITS = [{"kind": "set_comment", "address": "0x1000", "comment": "checked", "comment_type": "eol"}]
REQUEST_ID = "0e6f1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"


class Recorder:
    """What a client would receive: every report a call sends."""

    def __init__(self) -> None:
        self.reports: list[tuple[float, float | None, str | None]] = []

    async def __call__(self, progress, total=None, message=None):
        self.reports.append((progress, total, message))

    @property
    def values(self):
        return [report[0] for report in self.reports]

    @property
    def messages(self):
        return [report[2] for report in self.reports]


def reporter(recorder, interval=0.02):
    return ProgressReporter(recorder, interval=interval)


def strictly_increasing(values):
    return all(earlier < later for earlier, later in zip(values, values[1:], strict=False))


class TestProgressReporter:
    @pytest.mark.parametrize(
        "params",
        [
            SimpleNamespace(),
            SimpleNamespace(meta=None),
            SimpleNamespace(meta={}),
            SimpleNamespace(meta={"io.modelcontextprotocol/protocolVersion": VERSION}),
        ],
        ids=["no-meta", "none", "empty", "no-token"],
    )
    def test_a_request_without_a_token_gets_no_reporter(self, params):
        assert ProgressReporter.for_request(SimpleNamespace(session=object()), params) is None

    @pytest.mark.parametrize("token", ["abc", 7, 0])
    def test_a_request_with_a_token_reports_through_its_own_session(self, token):
        recorder = Recorder()
        context = SimpleNamespace(session=SimpleNamespace(report_progress=recorder))
        found = ProgressReporter.for_request(context, SimpleNamespace(meta={"progress_token": token}))
        assert found is not None, "a falsy token such as 0 is still a token"
        asyncio.run(found.tick("working"))
        ((value, total, message),) = recorder.reports
        assert value > 0 and total is None and message == "working"

    def test_values_only_grow_even_when_the_clock_stands_still(self):
        recorder = Recorder()
        stuck = ProgressReporter(recorder, clock=lambda: 50.0)

        async def tick_often():
            for _ in range(5):
                await stuck.tick()

        asyncio.run(tick_often())
        assert len(recorder.values) == 5 and strictly_increasing(recorder.values)

    def test_a_send_that_fails_stops_the_reports_without_failing_the_call(self):
        sent = []

        async def closed(progress, total, message):
            sent.append(progress)
            raise anyio.BrokenResourceError

        closing = ProgressReporter(closed)

        async def tick_twice():
            await closing.tick()
            await closing.tick()

        asyncio.run(tick_twice())
        assert len(sent) == 1, "a client that went away is not sent to again"


class TestTicking:
    def test_without_a_reporter_the_body_just_runs(self):
        async def body():
            async with ticking(None, "working"):
                return "done"

        assert asyncio.run(body()) == "done"

    def test_a_body_that_waits_reports_each_interval_and_nothing_after_it_ends(self):
        recorder = Recorder()
        counter = iter(range(10_000))

        async def wait():
            async with ticking(reporter(recorder), lambda: f"report {next(counter)}"):
                await anyio.sleep(0.3)
            reported = len(recorder.reports)
            await anyio.sleep(0.15)
            return reported

        reported = asyncio.run(wait())
        assert reported >= 3
        assert len(recorder.reports) == reported, "nothing is sent once the body has ended"
        assert strictly_increasing(recorder.values)
        assert recorder.messages[:2] == ["report 0", "report 1"], "the message is read at each report"

    def test_a_body_shorter_than_the_interval_reports_nothing(self):
        recorder = Recorder()

        async def wait():
            async with ticking(reporter(recorder, interval=5.0), "working"):
                await anyio.sleep(0.01)

        asyncio.run(wait())
        assert recorder.reports == []

    def test_a_body_that_fails_still_stops_the_reports(self):
        recorder = Recorder()

        async def wait():
            with pytest.raises(RuntimeError):
                async with ticking(reporter(recorder), "working"):
                    await anyio.sleep(0.1)
                    raise RuntimeError("the call failed")
            reported = len(recorder.reports)
            await anyio.sleep(0.1)
            return reported

        reported = asyncio.run(wait())
        assert reported >= 1 and len(recorder.reports) == reported

    def test_a_cancelled_body_still_stops_the_reports(self):
        recorder = Recorder()

        async def wait():
            async with anyio.create_task_group() as group:

                async def body():
                    async with ticking(reporter(recorder), "working"):
                        await anyio.sleep(10)

                group.start_soon(body)
                await anyio.sleep(0.1)
                group.cancel_scope.cancel()
            reported = len(recorder.reports)
            await anyio.sleep(0.1)
            return reported

        reported = asyncio.run(wait())
        assert len(recorder.reports) == reported


class Targets:
    def project_key(self, target):
        return "/project::test"


class Registry:
    """decompile_function and apply_edits wait for ``release``; nothing else is faked."""

    def __init__(self) -> None:
        self.operations = OperationManager(Targets())
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def call(self, command, params, target):
        self.calls += 1
        self.started.set()
        assert self.release.wait(15), "the test did not release the call"
        return {"status": "applied"} if command == "apply_edits" else PSEUDOCODE

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)


@pytest.fixture
def registry():
    registry = Registry()
    yield registry
    registry.release.set()  # a worker thread still waiting must not outlive the test
    registry.operations.shutdown()


def build_server(registry, *, defer_after):
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("decompile_function", "apply_edits", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    runtime.mcp.deferred_calls.defer_after = defer_after
    return runtime.mcp


def release_in(registry, seconds):
    asyncio.get_running_loop().call_later(seconds, registry.release.set)


class TestCallsThatWait:
    def test_a_slow_call_reports_while_it_runs_and_replies_normally(self, registry):
        server = build_server(registry, defer_after=10)
        recorder = Recorder()

        async def call():
            release_in(registry, 0.4)
            reply = await server.call_tool("decompile_function", DECOMPILE, progress=reporter(recorder))
            reported = len(recorder.reports)
            await anyio.sleep(0.15)
            return reply, reported

        reply, reported = asyncio.run(call())
        assert not reply.is_error and reply.structured_content == {"result": PSEUDOCODE}
        assert reported >= 3 and strictly_increasing(recorder.values)
        assert set(recorder.messages) == {"decompile_function: running"}
        assert len(recorder.reports) == reported, "nothing follows the reply"

    def test_a_call_that_arrives_while_ghidra_starts_reports_the_wait_and_then_the_call(self, registry):
        gate = StartupGate()
        runtime = create_mcp_server(
            specs={name: get_tool_spec(name) for name in ("decompile_function", "get_operation")},
            registry_provider=lambda: registry,
            dispatcher_provider=lambda: dispatch_tool,
            startup_gate=gate,
        )
        runtime.mcp.deferred_calls.defer_after = 10
        recorder = Recorder()

        async def call():
            asyncio.get_running_loop().call_later(0.3, gate.mark_ready)
            release_in(registry, 0.6)
            return await runtime.mcp.call_tool("decompile_function", DECOMPILE, progress=reporter(recorder))

        reply = asyncio.run(call())
        assert reply.structured_content == {"result": PSEUDOCODE}
        assert strictly_increasing(recorder.values), "the two waits share one clock"
        assert recorder.messages[0] == "decompile_function: waiting for Ghidra to start"
        assert recorder.messages[-1] == "decompile_function: running"

    def test_a_call_that_finishes_before_the_first_interval_reports_nothing(self, registry):
        server = build_server(registry, defer_after=10)
        registry.release.set()
        recorder = Recorder()

        async def call():
            return await server.call_tool("decompile_function", DECOMPILE, progress=reporter(recorder, interval=5.0))

        assert not asyncio.run(call()).is_error
        assert recorder.reports == []

    def test_a_call_without_a_reporter_sends_nothing_and_still_works(self, registry):
        server = build_server(registry, defer_after=10)
        release_in_later = threading.Timer(0.1, registry.release.set)
        release_in_later.start()
        reply = asyncio.run(server.call_tool("decompile_function", DECOMPILE))
        assert reply.structured_content == {"result": PSEUDOCODE}

    def test_a_deferred_call_reports_until_it_replies_with_its_job(self, registry):
        server = build_server(registry, defer_after=0.3)
        recorder = Recorder()

        async def call():
            reply = await server.call_tool("decompile_function", DECOMPILE, progress=reporter(recorder))
            reported = len(recorder.reports)
            await anyio.sleep(0.15)
            return reply, reported

        reply, reported = asyncio.run(call())
        assert reply.structured_content["deferred"] is True
        assert reported >= 2 and strictly_increasing(recorder.values)
        assert len(recorder.reports) == reported, "the job keeps running but the request has been answered"

    def test_a_resend_waiting_for_the_first_call_reports_too(self, registry):
        server = build_server(registry, defer_after=0.3)
        arguments = {"target": "t", "edits": EDITS, "request_id": REQUEST_ID}
        recorder = Recorder()

        async def calls():
            first = await server.call_tool("apply_edits", arguments)
            assert first.structured_content["deferred"] is True
            release_in(registry, 0.15)
            again = await server.call_tool("apply_edits", arguments, progress=reporter(recorder))
            reported = len(recorder.reports)
            await anyio.sleep(0.1)
            return again, reported

        again, reported = asyncio.run(calls())
        assert again.structured_content["replayed"] is True and registry.calls == 1
        assert reported >= 1 and strictly_increasing(recorder.values)
        assert set(recorder.messages) == {"apply_edits: running"}
        assert len(recorder.reports) == reported


async def post_decompile(client, *, token=None):
    meta = {"progressToken": token} if token is not None else None
    return await post(
        client,
        "tools/call",
        {"name": "decompile_function", "arguments": DECOMPILE},
        name="decompile_function",
        meta=meta,
    )


async def after_the_call_has_waited(registry, client, *, token):
    """The reply to a decompile that runs long enough for a few reports, then finishes."""
    request = asyncio.ensure_future(post_decompile(client, token=token))
    assert await asyncio.to_thread(registry.started.wait, 5)
    await anyio.sleep(0.4)
    registry.release.set()
    return await request


@pytest.fixture
def fast_reports(monkeypatch):
    monkeypatch.setattr(progress_module, "INTERVAL_SECONDS", 0.05)


class TestOverStreamableHttp:
    @pytest.mark.parametrize("token", ["abc", 7, 0])
    def test_a_waiting_call_with_a_token_answers_as_an_event_stream(self, registry, fast_reports, token):
        async def check():
            async with serving_app(build_server(registry, defer_after=10)) as client:
                response = await after_the_call_has_waited(registry, client, token=token)
                assert response.status_code == 200
                assert response.headers["content-type"].startswith("text/event-stream")
                *reports, reply = messages_in(response)
                assert reports and all(report["method"] == "notifications/progress" for report in reports)
                assert {report["params"]["progressToken"] for report in reports} == {token}
                assert strictly_increasing([report["params"]["progress"] for report in reports])
                assert {report["params"]["message"] for report in reports} == {"decompile_function: running"}
                assert reply["id"] == 1 and reply["result"]["structuredContent"] == {"result": PSEUDOCODE}

        asyncio.run(check())

    def test_the_same_call_without_a_token_answers_plain_json(self, registry, fast_reports):
        async def check():
            async with serving_app(build_server(registry, defer_after=10)) as client:
                response = await after_the_call_has_waited(registry, client, token=None)
                assert response.headers["content-type"].startswith("application/json")
                assert response.json()["result"]["structuredContent"] == {"result": PSEUDOCODE}

        asyncio.run(check())

    def test_a_quick_call_stays_plain_json_even_with_a_token(self, registry):
        registry.release.set()

        async def check():
            async with serving_app(build_server(registry, defer_after=10)) as client:
                response = await post_decompile(client, token="abc")
                assert response.headers["content-type"].startswith("application/json")
                assert response.json()["result"]["structuredContent"] == {"result": PSEUDOCODE}

        asyncio.run(check())

    def test_json_only_mode_never_streams(self, registry, fast_reports):
        async def check():
            async with serving_app(build_server(registry, defer_after=10), streaming=False) as client:
                response = await after_the_call_has_waited(registry, client, token="abc")
                assert response.headers["content-type"].startswith("application/json")
                assert response.json()["result"]["structuredContent"] == {"result": PSEUDOCODE}

        asyncio.run(check())
