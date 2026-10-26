"""Serving before Ghidra is up: the startup gate, the background steps, and tools/call waiting."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace

import pytest
from jsonschema import Draft202012Validator
from mcp import Client

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode, configure_lock_timeout_seconds, get_lock_timeout_seconds
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.startup import (
    FAILED,
    READY,
    STARTING,
    STARTUP_THREAD_NAME,
    BackgroundStartup,
    StartupFailure,
    StartupGate,
    StartupStep,
    startup_error_result,
    startup_failed_error,
)
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool

FAILURE = StartupFailure(
    stage="default_session",
    message="Failed to initialize default session: Program not found: /missing",
    cause_type="PROGRAM_NOT_FOUND",
    cause_message="Program not found: /missing",
)


def _later(seconds, action):
    timer = threading.Timer(seconds, action)
    timer.start()
    return timer


@pytest.fixture
def lock_timeout():
    original = get_lock_timeout_seconds()
    yield configure_lock_timeout_seconds
    configure_lock_timeout_seconds(original)


# ---- gate --------------------------------------------------------------------


def test_gate_returns_the_seconds_a_call_waited_for_the_startup():
    gate = StartupGate()
    _later(0.2, gate.mark_ready)
    waited = asyncio.run(gate.wait(5))
    assert gate.state == READY
    assert 0.15 <= waited < 2
    # Once ready, nothing waits.
    assert asyncio.run(gate.wait(5)) < 0.05


def test_gate_turns_a_call_away_with_a_retryable_lock_timeout_while_starting():
    gate = StartupGate()
    with pytest.raises(DomainError) as exc_info:
        asyncio.run(gate.wait(0.1))
    error = exc_info.value
    assert (error.code, error.retryable) == (ErrorCode.LOCK_TIMEOUT, True)
    assert error.details == {"lock": "startup", "timeout": 0.1}
    assert gate.state == STARTING


def test_a_failed_startup_is_the_answer_to_every_wait():
    gate = StartupGate()
    gate.mark_failed(FAILURE)
    gate.mark_ready()  # the outcome is final
    for _ in range(2):
        with pytest.raises(DomainError) as exc_info:
            asyncio.run(gate.wait(5))
        assert exc_info.value.code is ErrorCode.STARTUP_FAILED
        assert exc_info.value.retryable is False
    assert gate.state == FAILED


def test_gate_errors_use_the_usual_domain_error_envelope():
    timeout = startup_error_result(
        DomainError(code=ErrorCode.LOCK_TIMEOUT, message="Ghidra is still starting", retryable=True)
    )
    error = timeout.structured_content["error"]
    assert timeout.is_error and error["code"] == "LOCK_TIMEOUT" and error["retryable"] is True
    assert error["message"] == "LOCK_TIMEOUT: Ghidra is still starting"

    failed = startup_error_result(startup_failed_error(FAILURE)).structured_content["error"]
    assert (failed["code"], failed["retryable"]) == ("STARTUP_FAILED", False)
    assert failed["details"]["stage"] == "default_session"
    # The public message carries the cause, as the server log does.
    assert failed["message"].startswith("STARTUP_FAILED: ")
    assert "Program not found: /missing" in failed["message"]


# ---- background steps ----------------------------------------------------------


def _step(events, name, *, error=None, main_thread=False, wait=None):
    def run():
        events.append((name, threading.current_thread().name))
        if wait is not None:
            assert wait.wait(10)
        if error is not None:
            raise error

    return StartupStep(name, run, f"{name} failed", main_thread=main_thread)


def test_steps_run_in_order_on_their_thread_and_main_thread_steps_on_the_loop():
    events = []
    gate = StartupGate()
    startup = BackgroundStartup(
        [_step(events, "jvm"), _step(events, "loop", main_thread=True), _step(events, "core")],
        gate,
        on_thread_exit=lambda: events.append(("exit", threading.current_thread().name)),
    )

    async def serve():
        startup.start(loop=asyncio.get_running_loop())
        # The loop keeps serving while the startup runs, and runs its main-thread step.
        while gate.state == STARTING:
            await asyncio.sleep(0.01)

    asyncio.run(serve())
    assert startup.join(timeout=5)
    loop_thread = threading.current_thread().name
    assert events == [
        ("jvm", STARTUP_THREAD_NAME),
        ("loop", loop_thread),
        ("core", STARTUP_THREAD_NAME),
        ("exit", STARTUP_THREAD_NAME),
    ]
    assert gate.state == READY


def test_a_failed_step_releases_what_opened_before_the_gate_reports_it():
    events = []
    gate = StartupGate()
    stops = []

    def release():
        # Waiting calls still wait: they must not see the failure before the cleanup.
        events.append(("release", gate.state))

    startup = BackgroundStartup(
        [_step(events, "jvm"), _step(events, "session", error=ValueError("boom")), _step(events, "core")],
        gate,
        on_failure=release,
        on_thread_exit=lambda: events.append(("exit", gate.state)),
    )
    startup.start(stop_serving=lambda: stops.append(gate.state))
    assert startup.join(timeout=5)
    assert [event[0] for event in events] == ["jvm", "session", "release", "exit"]
    assert events[2] == ("release", STARTING)
    assert gate.state == FAILED and stops == [FAILED]
    assert gate.failure == StartupFailure("session", "session failed: boom", "ValueError", "boom")


def test_stop_waits_for_the_step_in_progress_and_skips_the_rest():
    events = []
    release = threading.Event()
    gate = StartupGate()
    startup = BackgroundStartup([_step(events, "jvm", wait=release), _step(events, "core")], gate)
    startup.start()
    while not events:
        time.sleep(0.01)
    _later(0.2, release.set)
    began = time.monotonic()
    startup.stop()
    # The JVM step cannot be interrupted: stop returned only once it ended.
    assert time.monotonic() - began >= 0.15
    assert [name for name, _thread in events] == ["jvm"]
    assert gate.state == STARTING


def test_a_main_thread_step_after_the_loop_ended_stops_the_startup():
    events = []
    loop = asyncio.new_event_loop()
    loop.close()
    gate = StartupGate()
    startup = BackgroundStartup([_step(events, "loop", main_thread=True), _step(events, "core")], gate)
    startup.start(loop=loop)
    assert startup.join(timeout=5)
    assert events == [] and gate.state == STARTING


# ---- tools/call waits --------------------------------------------------------


class Registry:
    operations = object()

    def list_targets(self):
        return [{"target": "sample"}]


def _server(gate, *names):
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in names},
        registry_provider=Registry,
        dispatcher_provider=lambda: dispatch_tool,
        startup_gate=gate,
    )
    return runtime.mcp


def _validate(client_tools, name, result):
    Draft202012Validator(client_tools[name].output_schema).validate(result.structured_content)


def test_tools_are_listed_at_once_and_a_call_waits_for_ghidra():
    gate = StartupGate()
    server = _server(gate, "list_targets")

    async def check():
        async with Client(server) as client:
            began = time.monotonic()
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert time.monotonic() - began < 1 and "list_targets" in tools
            _later(0.3, gate.mark_ready)
            began = time.monotonic()
            result = await client.call_tool("list_targets", {})
            assert time.monotonic() - began >= 0.25
            assert not result.is_error and result.structured_content == {"result": [{"target": "sample"}]}

    asyncio.run(check())


def test_a_call_that_outwaits_the_startup_gets_a_retryable_lock_timeout(lock_timeout):
    lock_timeout(0.2)
    server = _server(StartupGate(), "list_targets")

    async def check():
        async with Client(server) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            result = await client.call_tool("list_targets", {})
            assert result.is_error
            error = result.structured_content["error"]
            assert (error["code"], error["retryable"], error["details"]["lock"]) == ("LOCK_TIMEOUT", True, "startup")
            _validate(tools, "list_targets", result)

    asyncio.run(check())


def test_a_write_turned_away_while_starting_says_it_left_nothing(lock_timeout):
    lock_timeout(0.1)
    server = _server(StartupGate(), "list_targets", "save_project_program")

    async def check():
        async with Client(server) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            write = await client.call_tool("save_project_program", {"target": "sample"})
            read = await client.call_tool("list_targets", {})
            _validate(tools, "save_project_program", write)
            return write.structured_content["error"], read.structured_content["error"]

    write, read = asyncio.run(check())
    # retryable only with absent: nothing ran.
    assert (write["code"], write["retryable"], write["details"]["output_state"]) == ("LOCK_TIMEOUT", True, "absent")
    assert "output_state" not in read["details"]


def test_a_failed_startup_answers_in_the_published_error_shape():
    gate = StartupGate()
    gate.mark_failed(FAILURE)
    server = _server(gate, "list_targets")

    async def check():
        async with Client(server) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            result = await client.call_tool("list_targets", {})
            assert result.is_error and result.structured_content["error"]["code"] == "STARTUP_FAILED"
            _validate(tools, "list_targets", result)

    asyncio.run(check())


def test_the_startup_wait_counts_against_the_deferral_and_job_waits():
    gate = StartupGate()
    server = _server(gate, "decompile_function", "get_operation")
    seen = {}

    async def deferred_run(
        name, function, kwargs, *, operations, complete, already_waited=0.0, progress=None, cancellable=False
    ):
        seen["already_waited"] = already_waited
        return "int main(void) { return 0; }\n"

    async def job_wait(**kwargs):
        seen["wait_seconds"] = kwargs["wait_seconds"]
        seen["remaining"] = kwargs["_deadline"] - time.monotonic()
        return {"operation_id": "op", "state": "succeeded"}

    server.deferred_calls.run = deferred_run
    server.bindings["get_operation"] = replace(server.bindings["get_operation"], function=job_wait)

    async def check():
        async with Client(server) as client:
            _later(0.3, gate.mark_ready)
            await client.call_tool("decompile_function", {"target": "sample", "name": "main"})
            assert seen["already_waited"] >= 0.25
            # Ready now: nothing more is subtracted.
            await client.call_tool("get_operation", {"operation_id": "op", "wait_seconds": 10})
            assert seen["wait_seconds"] == 10

    asyncio.run(check())

    gate = StartupGate()
    server = _server(gate, "get_operation")
    server.bindings["get_operation"] = replace(server.bindings["get_operation"], function=job_wait)

    async def check_job():
        async with Client(server) as client:
            _later(1.2, gate.mark_ready)
            await client.call_tool("get_operation", {"operation_id": "op", "wait_seconds": 10})
            # The reply still comes within the 10 seconds the caller asked for.
            assert seen["wait_seconds"] == 10
            assert 0 < seen["remaining"] <= 8.8

    asyncio.run(check_job())


def test_a_failed_step_names_its_cause_without_host_paths():
    gate = StartupGate()
    secret = "/Users/analyst/cases/acme/project.gpr"
    startup = BackgroundStartup(
        [
            _step([], "jvm"),
            _step([], "session", error=RuntimeError(f"cannot open {secret}")),
        ],
        gate,
    )
    startup.start()
    assert startup.join(timeout=5)
    # The server log keeps the whole line for the operator.
    assert gate.failure.message == f"session failed: cannot open {secret}"
    assert (gate.failure.cause_type, gate.failure.cause_message) == ("RuntimeError", "cannot open <path>")
    error = startup_error_result(startup_failed_error(gate.failure)).structured_content["error"]
    assert secret not in str(error) and "cannot open <path>" in error["message"]
