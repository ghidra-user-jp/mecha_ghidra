"""A write sent with a request_id runs at most once: a resend gets the first call's reply."""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import anyio
import pytest

from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.deferred_calls import DeferredCalls
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool

REQUEST_ID = "0e6f1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
EDITS = [{"kind": "set_comment", "address": "0x1000", "comment": "checked", "comment_type": "eol"}]


class Targets:
    def project_key(self, target):
        return "/project::test"


class Registry:
    """apply_edits runs as a core command and bsim_apply_matches as a method; both are counted."""

    def __init__(self) -> None:
        self.operations = OperationManager(Targets())
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.failure: Exception | None = None
        self.started = threading.Event()
        self.release: threading.Event | None = None

    def call(self, command, params, target):
        return self._run(command, params)

    def bsim_apply_matches(self, target, *, dry_run=False, max_functions=500, **kwargs):
        # No request_id parameter: a leaked one would raise TypeError.
        return self._run("bsim_apply_matches", {"dry_run": dry_run, "max_functions": max_functions})

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)

    def _run(self, command, params):
        self.calls.append((command, dict(params)))
        self.started.set()
        if self.release is not None:
            assert self.release.wait(15), "the test did not release the call"
        if self.failure is not None:
            raise self.failure
        return {"status": "applied", "command": command, "calls": len(self.calls)}


def _server(registry, defer_after=None):
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("apply_edits", "bsim_apply_matches", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    if defer_after is not None:
        runtime.mcp.deferred_calls.defer_after = defer_after
    return runtime.mcp


def _edit(**extra):
    return {"target": "t", "edits": EDITS, **extra}


def _assert_replay_of(again, first):
    """A resend gets the first reply, marked replayed in structuredContent and in its text.

    A result gets a last text block for it; an error keeps its one block, whose JSON says it.
    """
    assert again.is_error == first.is_error
    assert again.structured_content == {**first.structured_content, "replayed": True}
    if first.is_error:
        assert len(again.content) == len(first.content)
        assert json.loads(again.content[0].text) == again.structured_content
    else:
        assert again.content[:-1] == first.content
        assert json.loads(again.content[-1].text) == {"replayed": True}


def test_a_resend_with_the_request_id_gets_the_first_reply_without_running_again():
    registry = Registry()
    mcp = _server(registry)

    async def scenario():
        first = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        again = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID.upper()))
        record = await mcp.call_tool("get_operation", {"request_id": REQUEST_ID})
        return first, again, record

    first, again, record = asyncio.run(scenario())
    assert not first.is_error
    _assert_replay_of(again, first)
    assert len(registry.calls) == 1
    # The handler never sees the request_id.
    assert "request_id" not in registry.calls[0][1]
    operation = record.structured_content["result"]
    assert operation["kind"] == "apply_edits" and operation["state"] == "succeeded"
    assert operation["request_id"] == REQUEST_ID
    assert operation["result"] == first.structured_content["result"]


def test_other_arguments_with_a_used_request_id_fail_with_request_id_conflict():
    registry = Registry()
    mcp = _server(registry)

    async def scenario():
        await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID, atomic=False))

    conflict = asyncio.run(scenario())
    assert conflict.is_error
    assert conflict.structured_content["error"]["code"] == "REQUEST_ID_CONFLICT"
    assert len(registry.calls) == 1


def test_a_failed_call_is_replayed_as_the_same_error_without_running_again():
    registry = Registry()
    registry.failure = DomainError(code=ErrorCode.PROGRAM_NOT_FOUND, message="no program")
    mcp = _server(registry)

    async def scenario():
        first = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        again = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return first, again

    first, again = asyncio.run(scenario())
    assert first.is_error and first.structured_content["error"]["code"] == "PROGRAM_NOT_FOUND"
    _assert_replay_of(again, first)
    assert len(registry.calls) == 1


def test_a_lock_timeout_does_not_name_its_own_request_as_the_holder():
    registry = Registry()
    registry.failure = DomainError(
        ErrorCode.LOCK_TIMEOUT, "runtime target lock timed out", retryable=True, details={"lock": "target"}
    )
    mcp = _server(registry)

    async def scenario():
        reply = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        replay = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return reply, replay

    reply, replay = asyncio.run(scenario())
    assert reply.is_error
    error = reply.structured_content["error"]
    assert error["code"] == "LOCK_TIMEOUT" and error["retryable"] is True
    assert "operation_id" not in error["details"]
    assert registry.operations.get(request_id=REQUEST_ID)["state"] == "failed"
    _assert_replay_of(replay, reply)
    assert len(registry.calls) == 1


def test_a_claimed_request_waiting_to_start_is_not_a_lock_holder():
    manager = OperationManager(Targets())
    record, _ = manager.claim_call("apply_edits", "t", request_id=REQUEST_ID, fingerprint="f")
    try:
        assert manager.lock_holder("t") is None
        assert manager.lock_holder("other", any_target=True) is None
    finally:
        manager.finish_call(record["operation_id"])


def test_a_resend_while_the_first_call_runs_waits_for_it():
    registry = Registry()
    registry.release = threading.Event()
    mcp = _server(registry)

    async def scenario():
        first = asyncio.ensure_future(mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)))
        await asyncio.to_thread(registry.started.wait, 10)
        again = asyncio.ensure_future(mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)))
        await asyncio.sleep(0.2)
        assert not again.done()
        registry.release.set()
        return await first, await again

    first, again = asyncio.run(scenario())
    assert not first.is_error
    _assert_replay_of(again, first)
    assert len(registry.calls) == 1


def test_a_deferred_call_and_its_resend_name_the_same_record():
    registry = Registry()
    registry.release = threading.Event()
    mcp = _server(registry, defer_after=0.2)

    async def scenario():
        first = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        again = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        registry.release.set()
        operation_id = first.structured_content["operation"]["operation_id"]
        done = await mcp.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 10})
        after = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return first, again, done, after

    first, again, done, after = asyncio.run(scenario())
    assert first.structured_content["deferred"] is True
    assert again.structured_content["deferred"] is True
    assert (
        again.structured_content["operation"]["operation_id"] == first.structured_content["operation"]["operation_id"]
    )
    assert done.structured_content["result"]["state"] == "succeeded"
    # Once it has finished, a resend gets the tool's own reply.
    assert after.structured_content["result"] == done.structured_content["result"]["result"]
    assert len(registry.calls) == 1


def test_the_record_takes_the_outcome_even_when_the_request_is_cancelled():
    registry = Registry()
    registry.release = threading.Event()
    mcp = _server(registry)

    async def scenario():
        call = asyncio.ensure_future(mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)))
        await asyncio.to_thread(registry.started.wait, 10)
        call.cancel()
        registry.release.set()
        record = await asyncio.to_thread(
            registry.operations.wait_for, registry.operations.get(request_id=REQUEST_ID)["operation_id"], 10
        )
        again = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return record, again

    record, again = asyncio.run(scenario())
    assert record["state"] == "succeeded"
    assert again.structured_content["result"] == record["result"]
    assert len(registry.calls) == 1


@pytest.mark.parametrize("cancellation", ["asyncio", "anyio", "anyio_thread_limit"])
@pytest.mark.parametrize("request_id", [REQUEST_ID, None], ids=["tracked", "untracked"])
def test_cancellation_before_a_slot_never_runs_or_leaks_capacity(monkeypatch, cancellation, request_id):
    registry = Registry()
    registry.release = threading.Event()
    mcp = _server(registry)
    mcp.deferred_calls = DeferredCalls(defer_after=0.02, slots=1)

    async def scenario():
        first = await mcp.call_tool("apply_edits", _edit())
        assert first.structured_content["deferred"] is True
        waiting = asyncio.Event()
        acquire = mcp.deferred_calls._slots.acquire

        def observe_acquire(blocking=True):
            acquired = acquire(blocking=blocking)
            if not blocking and not acquired:
                waiting.set()
            return acquired

        monkeypatch.setattr(mcp.deferred_calls._slots, "acquire", observe_acquire)
        limiter = anyio.to_thread.current_default_thread_limiter()
        borrower = object()
        if cancellation == "anyio_thread_limit":
            # Reproduce cancellation before the old slot-wait worker could start.
            limiter.total_tokens = 1
            await limiter.acquire_on_behalf_of(borrower)
        scope = anyio.CancelScope()

        async def invoke():
            with scope:
                return await mcp.call_tool("apply_edits", _edit(request_id=request_id))

        pending = asyncio.create_task(invoke())
        try:
            await asyncio.wait_for(waiting.wait(), 2)
            if cancellation == "asyncio":
                pending.cancel()
            else:
                scope.cancel()
            # Let cancellation reach the wait before making a slot available.
            await asyncio.sleep(0)
        finally:
            if cancellation == "anyio_thread_limit":
                limiter.release_on_behalf_of(borrower)
            registry.release.set()
        try:
            await asyncio.wait_for(pending, 2)
        except asyncio.CancelledError:
            pass
        await mcp.call_tool(
            "get_operation", {"operation_id": first.structured_content["operation"]["operation_id"], "wait_seconds": 2}
        )
        assert len(registry.calls) == 1, "a call cancelled before admission must not execute later"
        if request_id is not None:
            record = registry.operations.get(request_id=request_id)
            assert record["state"] == "failed"
            assert record["operation_error"]["code"] == "OPERATION_CANCELLED"
            assert record["operation_error"]["details"]["output_state"] == "absent"
            assert record["finished_at"] is not None
            replay = await asyncio.wait_for(mcp.call_tool("apply_edits", _edit(request_id=request_id)), 2)
            assert replay.is_error and replay.structured_content["replayed"] is True
            assert replay.structured_content["error"] == record["operation_error"]
            mcp.output_validators["apply_edits"].validate(replay.structured_content)
            assert len(registry.calls) == 1
        # The cancelled waiter must not steal the released slot. A new request runs.
        next_request_id = "1e6f1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
        next_reply = await asyncio.wait_for(mcp.call_tool("apply_edits", _edit(request_id=next_request_id)), 2)
        assert not next_reply.is_error
        # Slow scheduling may defer this reply too; check the final recorded outcome.
        next_done = await mcp.call_tool("get_operation", {"request_id": next_request_id, "wait_seconds": 2})
        next_record = next_done.structured_content["result"]
        assert next_record["state"] == "succeeded"
        assert next_record["result"]["calls"] == 2

    try:
        asyncio.run(scenario())
    finally:
        registry.release.set()
        registry.operations.shutdown()


def test_without_a_request_id_every_call_runs():
    registry = Registry()
    mcp = _server(registry)

    async def scenario():
        await mcp.call_tool("apply_edits", _edit())
        await mcp.call_tool("apply_edits", _edit())

    asyncio.run(scenario())
    assert len(registry.calls) == 2


def test_bsim_apply_matches_replays_its_reply_and_its_method_never_sees_the_request_id():
    registry = Registry()
    mcp = _server(registry)
    arguments = {"target": "t", "dry_run": True, "request_id": REQUEST_ID}

    async def scenario():
        return await mcp.call_tool("bsim_apply_matches", arguments), await mcp.call_tool(
            "bsim_apply_matches", arguments
        )

    first, again = asyncio.run(scenario())
    assert not first.is_error, first.structured_content
    _assert_replay_of(again, first)
    assert registry.calls == [("bsim_apply_matches", {"dry_run": True, "max_functions": 500})]


def test_a_direct_dispatch_drops_the_request_id_before_the_handler():
    registry = Registry()
    dispatch_tool("apply_edits", {"edits": EDITS, "request_id": REQUEST_ID}, "t", registry=registry)
    assert "request_id" not in registry.calls[0][1]


def test_a_dropped_reply_is_reported_instead_of_running_the_call_again():
    manager = OperationManager(Targets(), payload_limit_bytes=1)
    record, fresh = manager.claim_call("apply_edits", "t", request_id=REQUEST_ID, fingerprint="f")
    assert fresh
    manager.finish_call(record["operation_id"], result={"status": "applied"}, reply={"structuredContent": {}})
    # Over the payload budget the record keeps neither the result nor the reply.
    assert manager.reply_for(record["operation_id"]) is None
    again, fresh = manager.claim_call("apply_edits", "t", request_id=REQUEST_ID, fingerprint="f")
    assert not fresh and again["operation_id"] == record["operation_id"]
    assert manager.get(operation_id=again["operation_id"])["result_discarded"] is True
    with pytest.raises(DomainError) as raised:
        manager.claim_call("apply_edits", "t", request_id=REQUEST_ID, fingerprint="other")
    assert raised.value.code is ErrorCode.REQUEST_ID_CONFLICT


def test_only_a_call_with_a_request_id_keeps_its_reply():
    manager = OperationManager(Targets())
    deferred = manager.defer_call("apply_edits", "t", started_at="now")
    manager.finish_call(deferred["operation_id"], result={"ok": True}, reply={"structuredContent": {"result": 1}})
    assert manager.reply_for(deferred["operation_id"]) is None


def test_every_program_write_replays_a_resend():
    from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolSafetyTag, get_all_tool_specs

    writes = [
        spec
        for spec in get_all_tool_specs().values()
        if spec.executor_kind is ExecutorKind.CORE_COMMAND and spec.safety_tag is not ToolSafetyTag.READ_ONLY
    ]
    assert len(writes) >= 20
    assert [spec.name for spec in writes if not spec.replays_requests] == []


def test_undo_runs_once_however_often_it_is_resent():
    # Undoing twice would undo two changes: the resend after a lost reply must not.
    registry = Registry()
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("undo_program_change", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )

    async def scenario():
        arguments = {"target": "t", "request_id": REQUEST_ID}
        return [await runtime.mcp.call_tool("undo_program_change", arguments) for _ in range(3)]

    replies = asyncio.run(scenario())
    for reply in replies[1:]:
        _assert_replay_of(reply, replies[0])
    assert registry.calls == [("undo_program_change", {"count": 1})]


def test_a_replayed_reply_matches_the_published_output_schema():
    registry = Registry()
    mcp = _server(registry)

    async def scenario():
        replies = [await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)) for _ in range(2)]
        registry.failure = DomainError(ErrorCode.OPERATION_FAILED, "boom")
        other = "1e6f1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
        failures = [await mcp.call_tool("apply_edits", _edit(request_id=other)) for _ in range(2)]
        return replies + failures

    replies = asyncio.run(scenario())
    assert [reply.structured_content.get("replayed") for reply in replies] == [None, True, None, True]
    assert replies[3].is_error
    for reply in replies:
        mcp.output_validators["apply_edits"].validate(reply.structured_content)


def test_a_replayed_stored_result_keeps_its_two_blocks():
    from ghidra_mcp.presentation.config import ToolPresentationConfig

    class Large(Registry):
        def _run(self, command, params):
            return {**super()._run(command, params), "notes": ["x" * 80] * 200}

    registry = Large()
    mcp = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("apply_edits", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        presentation_config=ToolPresentationConfig(large_result_threshold_chars=1000, large_result_preview_chars=100),
    ).mcp

    async def scenario():
        return [await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)) for _ in range(2)]

    first, again = asyncio.run(scenario())
    assert [block.type for block in first.content] == ["text", "resource_link"]
    # The documented notice shape: its structured content says replayed, its blocks stay two.
    assert [block.type for block in again.content] == ["text", "resource_link"]
    assert again.structured_content == {**first.structured_content, "replayed": True}
    assert len(registry.calls) == 1


def test_a_call_that_finishes_in_time_is_completed_once():
    registry = Registry()
    mcp = _server(registry)
    completed = []
    original = mcp.complete_result

    def complete_result(name, kwargs, value):
        completed.append(name)
        return original(name, kwargs, value)

    mcp.complete_result = complete_result
    reply = asyncio.run(mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID)))
    assert not reply.is_error
    # The record's reply is the one sent: no second compaction or result-store entry.
    assert completed == ["apply_edits"]


def test_a_request_that_finds_every_slot_busy_can_be_sent_again():
    registry = Registry()
    registry.release = threading.Event()
    mcp = _server(registry, defer_after=0.2)
    mcp.deferred_calls = DeferredCalls(defer_after=0.2, slots=1)
    other = "1e6f1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b"

    async def scenario():
        busy = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        assert busy.structured_content["deferred"] is True
        refused = await mcp.call_tool("apply_edits", _edit(request_id=other))
        registry.release.set()
        with anyio.fail_after(5):
            while registry.operations.is_pending(busy.structured_content["operation"]["operation_id"]):
                await asyncio.sleep(0.01)
            again = await mcp.call_tool("apply_edits", _edit(request_id=other))
        return refused, again

    refused, again = asyncio.run(scenario())
    error = refused.structured_content["error"]
    assert (error["code"], error["retryable"], error["details"]["output_state"]) == (
        "OPERATION_QUEUE_FULL",
        True,
        "absent",
    )
    # Nothing ran for it, so the same request_id runs the call once a slot is free.
    assert not again.is_error and "replayed" not in again.structured_content
    assert len(registry.calls) == 2


def test_a_resend_whose_first_reply_was_dropped_gets_a_coded_error():
    registry = Registry()
    # Too small to keep any reply.
    registry.operations = OperationManager(Targets(), payload_limit_bytes=1)
    mcp = _server(registry)

    async def scenario():
        first = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        again = await mcp.call_tool("apply_edits", _edit(request_id=REQUEST_ID))
        return first, again

    first, again = asyncio.run(scenario())
    assert not first.is_error and len(registry.calls) == 1
    assert again.is_error
    error = again.structured_content["error"]
    assert (error["code"], error["retryable"]) == ("RESULT_DISCARDED", False)
    # The first call ran: what it left is for the program to show, not for a resend to redo.
    assert error["details"]["output_state"] == "uncertain"
    operation = registry.operations.get(operation_id=error["details"]["operation_id"])
    assert (operation["state"], operation["result_discarded"]) == ("succeeded", True)
    assert "get_operation" in error["hint"]
