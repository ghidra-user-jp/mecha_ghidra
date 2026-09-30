from __future__ import annotations

import asyncio
import json
import threading
import time

import anyio
import pytest
from jsonschema import Draft202012Validator

from ghidra_mcp.application.locks import acquire_ordered_locks
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_all_tool_specs, get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.deferred_calls import DeferredCalls
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import spec_wire_output_schema

WAIT = 0.2
PROJECT = "/project::test"
TOOLS = ("decompile_function", "get_function", "get_operation", "cancel_operation", "list_targets")


class Targets:
    def project_key(self, target):
        return PROJECT


class Registry:
    """Core commands gated by an event; the job records are real."""

    def __init__(self):
        self.operations = OperationManager(Targets())
        self.gate = threading.Event()
        self.entered = threading.Event()
        self.value = "int main(void) { return 0; }"
        self.error = None
        self.calls = 0
        self.cancel_threads = []

    def call(self, command, params, target):
        if command == "get_function":
            raise DomainError(ErrorCode.LOCK_TIMEOUT, "runtime target lock timed out", details={"lock": "target"})
        self.calls += 1
        self.entered.set()
        assert self.gate.wait(5), "test did not open the gate"
        if self.error is not None:
            raise self.error
        return self.value

    def list_targets(self):
        return []

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)

    def cancel_operation(self, *, operation_id):
        self.cancel_threads.append(threading.current_thread())
        return self.operations.cancel(operation_id)


def server(registry, *, tools=TOOLS, config=None):
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in tools},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=config,
    )
    runtime.mcp.deferred_calls.defer_after = WAIT
    return runtime.mcp


def decompile(mcp, target="t"):
    return mcp.call_tool("decompile_function", {"target": target, "address": "0x1000"})


async def settle(mcp, operation_id, timeout=3):
    with anyio.fail_after(timeout):
        reply = await mcp.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 2})
    return reply.structured_content["result"]


@pytest.fixture
def registry():
    registry = Registry()
    try:
        yield registry
    finally:
        registry.gate.set()
        registry.operations.shutdown()


def test_a_call_that_finishes_in_time_replies_as_before_and_leaves_no_record(registry):
    registry.gate.set()
    reply = asyncio.run(decompile(server(registry)))
    assert not reply.is_error and reply.structured_content == {"result": registry.value}
    assert not registry.operations._records


def test_a_slow_call_replies_with_a_record_and_get_operation_returns_its_result(registry):
    mcp = server(registry)

    async def scenario():
        started = time.monotonic()
        reply = await decompile(mcp)
        assert WAIT <= time.monotonic() - started < WAIT + 1
        deferred = reply.structured_content
        assert not reply.is_error and deferred["deferred"] is True
        assert (deferred["tool"], deferred["target"]) == ("decompile_function", "t")
        operation = deferred["operation"]
        assert (operation["kind"], operation["state"]) == ("decompile_function", "running")
        # Clients that pass only text to the model still see what to do.
        assert "get_operation" in reply.content[0].text and operation["operation_id"] in reply.content[0].text
        Draft202012Validator(spec_wire_output_schema(get_tool_spec("decompile_function"))).validate(deferred)
        registry.gate.set()
        record = await settle(mcp, operation["operation_id"])
        # Exactly what the reply would have carried had the call been quick.
        assert record["state"] == "succeeded" and record["result"] == registry.value
        assert registry.calls == 1

    asyncio.run(scenario())


def test_a_slow_failure_records_the_error_the_reply_would_have_carried(registry):
    mcp = server(registry)
    registry.error = DomainError(ErrorCode.PROGRAM_NOT_FOUND, "no function at 0x1000", details={"address": "0x1000"})

    async def scenario():
        reply = await decompile(mcp)
        operation_id = reply.structured_content["operation"]["operation_id"]
        registry.gate.set()
        record = await settle(mcp, operation_id)
        assert record["state"] == "failed"
        # The same call finishing in time fails with this very error object.
        direct = await decompile(mcp)
        assert direct.is_error and record["operation_error"] == direct.structured_content["error"]
        assert record["operation_error"]["code"] == "PROGRAM_NOT_FOUND"

    asyncio.run(scenario())


def test_a_large_slow_result_is_recorded_as_a_stored_result_reference(registry):
    config = ToolPresentationConfig(large_result_threshold_chars=200, large_result_preview_chars=50)
    mcp = server(registry, config=config)
    registry.value = "x" * 5000

    async def scenario():
        reply = await decompile(mcp)
        registry.gate.set()
        record = await settle(mcp, reply.structured_content["operation"]["operation_id"])
        assert record["result"]["truncated"] is True and record["result"]["result_id"]
        assert len(json.dumps(record)) < 5000

    asyncio.run(scenario())


def test_a_lock_timeout_behind_a_deferred_call_names_it(registry, monkeypatch):
    original = registry.call

    def call(command, params, target):
        if command == "get_function":
            return original(command, params, target)
        with acquire_ordered_locks([("target", threading.RLock()), ("project", threading.RLock())]):
            return original(command, params, target)

    monkeypatch.setattr(registry, "call", call)
    mcp = server(registry)

    async def scenario():
        reply = await decompile(mcp)
        operation_id = reply.structured_content["operation"]["operation_id"]
        assert registry.operations.lock_holder("t") == operation_id
        blocked = await mcp.call_tool("get_function", {"target": "t", "address": "0x1000"})
        assert blocked.is_error
        assert blocked.structured_content["error"]["details"]["operation_id"] == operation_id
        # A deferred call cannot be cancelled; it can only be waited for.
        refused = await mcp.call_tool("cancel_operation", {"operation_id": operation_id})
        assert refused.is_error and refused.structured_content["error"]["code"] == "VALIDATION_ERROR"
        registry.gate.set()
        await settle(mcp, operation_id)
        assert registry.operations.lock_holder("t") is None

    asyncio.run(scenario())


def test_a_deferred_call_without_a_target_is_readable_and_holds_no_lock(registry):
    # bsim_load_matched_executable takes an optional target: None reaches the record.
    snapshot = registry.operations.defer_call("bsim_load_matched_executable", None, started_at="now")
    assert registry.operations.get(operation_id=snapshot["operation_id"])["target"] == ""
    assert registry.operations.lock_holder("t", any_target=True) is None
    registry.operations.finish_call(snapshot["operation_id"], result={"target": "loaded"})
    reply = asyncio.run(
        server(registry).call_tool("get_operation", {"operation_id": snapshot["operation_id"], "wait_seconds": 0})
    )
    assert not reply.is_error and reply.structured_content["result"]["result"] == {"target": "loaded"}


def test_cancel_operation_runs_on_the_event_loop_thread(registry):
    # That thread started the JVM, so cancelling a Java monitor from it attaches no
    # new JVM thread that a running script would take for its own.
    mcp = server(registry)
    record = registry.operations.defer_call("decompile_function", "t", started_at="now")
    refused = asyncio.run(mcp.call_tool("cancel_operation", {"operation_id": record["operation_id"]}))
    assert refused.is_error
    assert registry.cancel_threads == [threading.main_thread()]
    registry.operations.finish_call(record["operation_id"], result="done")


def test_every_tool_call_thread_is_prepared_before_the_call(registry):
    prepared = []
    mcp = server(registry)
    mcp.prepare_thread = mcp.deferred_calls.prepare_thread = lambda: prepared.append(threading.current_thread())
    registry.gate.set()
    asyncio.run(decompile(mcp))
    asyncio.run(mcp.call_tool("list_targets", {}))
    assert len(prepared) == 2 and threading.main_thread() not in prepared


def test_a_deferred_call_keeps_its_slot_until_it_finishes(registry):
    mcp = server(registry)
    mcp.deferred_calls = DeferredCalls(defer_after=WAIT, slots=1)

    async def scenario():
        reply = await decompile(mcp)
        assert reply.structured_content["deferred"] is True
        # The only slot is still busy after the wait: the second call does not run, and says so in time.
        with anyio.fail_after(WAIT * 5):
            refused = await decompile(mcp, "u")
        error = refused.structured_content["error"]
        assert refused.is_error and (error["code"], error["retryable"]) == ("OPERATION_QUEUE_FULL", True)
        assert error["details"]["output_state"] == "absent" and registry.calls == 1
        registry.gate.set()
        # Once the deferred call ends, its slot takes the next call.
        with anyio.fail_after(3):
            assert (await decompile(mcp, "v")).structured_content == {"result": registry.value}
        assert registry.calls == 2

    asyncio.run(scenario())


def test_shutdown_waits_for_a_deferred_call_before_closing_ghidra(registry):
    mcp = server(registry)

    async def scenario():
        return await decompile(mcp)

    assert asyncio.run(scenario()).structured_content["deferred"] is True
    closing = threading.Thread(target=registry.operations.shutdown)
    closing.start()
    closing.join(WAIT * 2)
    assert closing.is_alive(), "shutdown must wait for the call still using Ghidra"
    registry.gate.set()
    closing.join(3)
    assert not closing.is_alive()


def test_without_get_operation_no_call_is_deferred(registry):
    mcp = server(registry, tools=("decompile_function",))

    async def scenario():
        call = asyncio.ensure_future(decompile(mcp))
        await asyncio.sleep(WAIT * 2)
        assert not call.done()
        registry.gate.set()
        with anyio.fail_after(3):
            return await call

    assert asyncio.run(scenario()).structured_content == {"result": registry.value}


def test_a_call_deferred_before_its_thread_starts_still_runs_and_records(registry):
    mcp = server(registry)
    # The wait ends at once, most likely before the worker thread has started.
    mcp.deferred_calls.defer_after = 0

    async def scenario():
        reply = await decompile(mcp)
        assert reply.structured_content["deferred"] is True
        registry.gate.set()
        record = await settle(mcp, reply.structured_content["operation"]["operation_id"])
        assert record["state"] == "succeeded" and record["result"] == registry.value
        assert registry.calls == 1

    asyncio.run(scenario())


def test_a_cancelled_request_does_not_stop_its_call(registry):
    mcp = server(registry)

    async def scenario():
        with anyio.move_on_after(WAIT / 4):
            await decompile(mcp)
        # The client gave up; the call still runs to completion and frees its slot.
        assert registry.entered.wait(1)
        registry.gate.set()
        deadline = time.monotonic() + 3
        while registry.operations._calls_in_flight:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)
        registry.gate.clear()
        registry.value = "second"
        registry.gate.set()
        assert (await decompile(mcp)).structured_content == {"result": "second"}

    asyncio.run(scenario())


def test_every_deferrable_tool_publishes_the_deferred_reply():
    for name, spec in get_all_tool_specs().items():
        variants = json.dumps(spec_wire_output_schema(spec))
        assert ('"deferred"' in variants) is spec.deferrable, name
    assert not get_tool_spec("list_targets").deferrable
    assert not get_tool_spec("run_script").deferrable and not get_tool_spec("get_operation").deferrable


def test_a_deferred_failure_keeps_the_code_its_reply_had(registry):
    from ghidra_mcp.presentation.deferred_calls import _record_outcome
    from ghidra_mcp.presentation.tool_errors import ToolInputError

    record = registry.operations.defer_call("import_program", "t", started_at="now")
    reply = _record_outcome(
        registry.operations,
        record["operation_id"],
        "import_program",
        None,
        ToolInputError("language_id is required"),
        None,
    )
    stored = registry.operations.get(operation_id=record["operation_id"])["operation_error"]
    assert reply.structured_content["error"] == stored
    assert (stored["code"], stored["retryable"]) == ("VALIDATION_ERROR", False) and stored["hint"]


def test_a_failed_batch_keeps_its_items_in_the_record():
    from mcp.types import CallToolResult, TextContent

    from ghidra_mcp.presentation.operation_presentation import structured_error

    batch = {"status": "error", "items": [{"id": "a", "status": "error", "error": {"code": "NOT_FOUND"}}]}
    failed = CallToolResult(
        is_error=True, content=[TextContent(type="text", text=json.dumps(batch))], structured_content={"result": batch}
    )
    assert structured_error(failed)["result"] == batch


def test_a_deferred_program_tool_whose_result_was_stored_keeps_source_beside_it(registry):
    registry.value = "x" * 5000
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in TOOLS},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=ToolPresentationConfig(large_result_threshold_chars=200, large_result_preview_chars=50),
        command_source=lambda: {"program": "/p.bin", "revision": "r1"},
    )
    mcp = runtime.mcp
    mcp.deferred_calls.defer_after = WAIT

    async def scenario():
        reply = await decompile(mcp)
        assert reply.structured_content["deferred"] is True
        registry.gate.set()
        return await settle(mcp, reply.structured_content["operation"]["operation_id"])

    record = asyncio.run(scenario())
    # A slow call's result is the large one: the record still names its revision beside it.
    assert record["source"] == {"target": "t", "program": "/p.bin", "revision": "r1"}
    assert record["result"]["truncated"] is True and "source" not in record["result"]


def test_waiting_calls_take_freed_slots_in_arrival_order():
    calls = DeferredCalls(defer_after=5, slots=1)

    async def scenario():
        # A running call holds the only slot; one call is already waiting for it.
        assert await calls._acquire_slot(0) is True
        earlier = asyncio.ensure_future(calls._acquire_slot(5))
        await asyncio.sleep(0.01)
        calls._slots.release()
        # A call that comes later does not take the freed slot from the one before it.
        assert await calls._acquire_slot(0) is False
        assert await earlier is True
        assert not calls._slot_waiters
        calls._release_slot()

    asyncio.run(scenario())


async def _within_loop_turns(done, turns=100):
    """Let the event loop run until ``done()``: at most ``turns`` passes, none of them waiting on a timer."""
    for _ in range(turns):
        if done():
            return
        await asyncio.sleep(0)
    raise AssertionError(f"not done within {turns} event loop turns")


def test_freed_slots_go_to_every_waiting_call_at_once():
    calls = DeferredCalls(defer_after=5, slots=3)

    async def scenario():
        for _ in range(3):
            assert await calls._acquire_slot(0) is True
        order = []

        async def wait(tag):
            if await calls._acquire_slot(5):
                order.append(tag)

        waiting = [asyncio.ensure_future(wait(tag)) for tag in "abc"]
        await _within_loop_turns(lambda: len(calls._slot_waiters) == 3)
        # The running calls end; their threads give the slots back.
        releases = [threading.Thread(target=calls._release_slot) for _ in range(3)]
        for thread in releases:
            thread.start()
        for thread in releases:
            thread.join()
        # Handed over as they came free, in arrival order, and not one per poll: no
        # timer has to fire, however slowly the loop turns.
        await _within_loop_turns(lambda: len(order) == 3)
        assert order == ["a", "b", "c"] and not calls._slot_waiters
        await asyncio.gather(*waiting)

    asyncio.run(scenario())


def test_a_waiter_that_goes_away_as_it_gets_a_slot_passes_the_slot_on():
    calls = DeferredCalls(defer_after=5, slots=1)

    async def scenario():
        assert await calls._acquire_slot(0) is True
        first = asyncio.ensure_future(calls._acquire_slot(5))
        second = asyncio.ensure_future(calls._acquire_slot(5))
        await asyncio.sleep(0.01)
        calls._slots.release()
        calls._dispatch()
        # The slot is first's now, but its request goes away before it resumes.
        first.cancel()
        assert await asyncio.wait_for(second, 1) is True
        with pytest.raises(asyncio.CancelledError):
            await first
        assert not calls._slot_waiters

    asyncio.run(scenario())
