"""Reply to a slow tool call with a job record and let the call finish on its own thread.

A call still running after ``DEFER_AFTER_SECONDS`` replies ``deferred: true``
with a job record; the call keeps running, and ``get_operation`` returns what
the tool would have returned. The wait stays well inside the 60-second limit
many clients and proxies apply to a call, and above the default lock wait, so
a call that cannot get its lock still fails with ``LOCK_TIMEOUT`` as before.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from typing import Any

import anyio
from mcp.types import CallToolResult, TextContent

from ghidra_mcp.application.locks import CallLocks
from ghidra_mcp.contracts.tool_spec import DEFER_AFTER_SECONDS, OPERATION_WAIT_MAX_SECONDS
from ghidra_mcp.domain import DomainError, ErrorCode

from .operation_presentation import structured_error, structured_source, structured_value
from .result_compaction import _json_text
from .tool_binding import tool_error_result
from .tool_errors import ToolError
from .tool_registry import domain_error_result

logger = logging.getLogger(__name__)

# As many tool calls run at once as before, when they shared the default
# thread limiter; a deferred call keeps its slot until it finishes.  A waiter
# waits on the event loop without reserving a worker thread: a cancelled
# waiter must never acquire a slot later, after its request has gone away.
# A freed slot goes at once to the oldest waiter, so under a steady overload
# the one refused after its wait is never one that came before calls that ran.
CALL_SLOTS = 40


@dataclass(frozen=True)
class DeferredReply:
    """A reply ready to send: a still-running call's job record, or a call's reply its record already holds."""

    result: CallToolResult


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _Call:
    """One call's outcome, handed once either to its request or to its job record."""

    def __init__(self, release_slot: Callable[[], None]) -> None:
        self._lock = threading.Lock()
        self._finished = False
        self._outcome: tuple[Any, BaseException | None] | None = None
        self._on_finish: Callable[[Any, BaseException | None], CallToolResult | None] | None = None
        # The reply the record stored, once the call finished into its record.
        self.recorded: CallToolResult | None = None
        self._release_slot = release_slot

    def run(self, function: Callable[..., Any], kwargs: dict[str, Any], tracked, prepare=None) -> Any:
        try:
            with tracked():
                try:
                    if prepare is not None:
                        prepare()
                    value = function(**kwargs)
                except BaseException as exc:
                    self._finish(None, exc)
                    raise
                self._finish(value, None)
                return value
        finally:
            self._release_slot()

    def _finish(self, value: Any, error: BaseException | None) -> None:
        with self._lock:
            self._finished = True
            on_finish = self._on_finish
            if on_finish is None:
                self._outcome = (value, error)
        if on_finish is not None:
            self.recorded = on_finish(value, error)

    def defer(self, create_record: Callable[[], Callable[[Any, BaseException | None], CallToolResult | None]]) -> bool:
        """Hand the outcome to a job record; False if the call has just finished."""
        with self._lock:
            if self._finished:
                return False
            self._on_finish = create_record()
            return True

    def outcome(self) -> Any:
        assert self._outcome is not None
        value, error = self._outcome
        if error is not None:
            raise error
        return value


def _consume(task: asyncio.Future) -> None:
    # A deferred call's task is never awaited again; its exception is in the record.
    if not task.cancelled():
        task.exception()


class DeferredCalls:
    """Run synchronous tool calls on worker threads, deferring the ones that outlive the wait."""

    def __init__(
        self,
        *,
        defer_after: float = DEFER_AFTER_SECONDS,
        slots: int = CALL_SLOTS,
        prepare_thread: Callable[[], None] | None = None,
    ) -> None:
        self.defer_after = defer_after
        # Runs on the worker thread before the call (see GhidraMCPServer).
        self.prepare_thread = prepare_thread
        self._slots = threading.BoundedSemaphore(slots)
        # Calls waiting for a slot, oldest first; _dispatch hands them freed
        # slots.  Only the event loop's thread touches it.
        self._slot_waiters: collections.deque[asyncio.Future[None]] = collections.deque()
        # The loop the waiters wait on, which a slot released on a worker thread wakes.
        self._loop: asyncio.AbstractEventLoop | None = None
        # The slots bound the calls; this only keeps anyio's default limiter,
        # which the calls no longer share, from bounding them a second time.
        self._threads: anyio.CapacityLimiter | None = None

    async def run(
        self,
        name: str,
        function: Callable[..., Any],
        kwargs: dict[str, Any],
        *,
        operations,
        complete: Callable[[Any], CallToolResult],
        already_waited: float = 0.0,
        claimed: dict[str, Any] | None = None,
        defer: bool = True,
    ) -> Any:
        """Return the call's value, or a ``DeferredReply`` when it outlives the wait.

        ``complete`` turns the value into the CallToolResult the request would
        have returned; a deferred call's thread uses it to record the result.
        ``already_waited`` is time the request spent before the call (waiting
        for Ghidra to start); it counts against the wait, so the reply still
        comes within ``defer_after`` of the request.

        ``claimed`` is the record a call sent with a request_id already has
        (``OperationManager.claim_call``).  The call's thread records its
        outcome there however the call ends, even in time for this reply or
        after the request was cancelled, and a deferred reply names it; a
        call that finishes in time replies with the recorded reply.
        Cancellation while waiting for a slot instead finishes the record as
        cancelled without running the tool. A resend gets that failure too.
        ``defer=False`` waits for the call however long it runs.

        Waiting for a slot counts against the wait as well: with every slot
        still busy after it, the call does not run and the reply is a
        retryable ``OPERATION_QUEUE_FULL``.
        """
        began = time.monotonic()
        try:
            # Once acquired there is no await until the shielded execution
            # task owns the slot.
            acquired = await self._acquire_slot(self.defer_after - already_waited)
        except anyio.get_cancelled_exc_class():
            if claimed is not None:
                _cancel_before_start(operations, claimed["operation_id"], name)
            raise
        if not acquired:
            return DeferredReply(_slots_busy(operations, name, claimed))
        already_waited += time.monotonic() - began
        call = _Call(self._release_slot)
        call_locks = CallLocks()
        # None for a tool whose target is optional; the record needs a string.
        target = kwargs.get("target") or ""
        if claimed is not None:
            claimed_id = claimed["operation_id"]
            operations.bind_call_locks(claimed_id, call_locks)
            call.defer(
                lambda: lambda value, error: _record_outcome(operations, claimed_id, name, value, error, complete)
            )
        if self._threads is None:
            self._threads = anyio.CapacityLimiter(math.inf)
        started_at = _now()
        # Its own task, so the wait below can end without cancelling the call:
        # a deferred call runs to completion even if its thread had not started.
        task = asyncio.ensure_future(
            anyio.to_thread.run_sync(
                call.run,
                function,
                kwargs,
                partial(operations.tracked_call, call_locks=call_locks),
                self.prepare_thread,
                limiter=self._threads,
            )
        )
        task.add_done_callback(_consume)
        with anyio.move_on_after(max(0.0, self.defer_after - already_waited) if defer else math.inf):
            try:
                value = await asyncio.shield(task)
            except Exception:
                if call.recorded is None:
                    raise
                value = None
            # A claimed call's record already holds the reply, completed on the call's thread.
            return value if call.recorded is None else DeferredReply(call.recorded)
        if claimed is not None:
            if task.done():
                # It finished just as the wait ended; its record has the outcome too.
                return DeferredReply(call.recorded) if call.recorded is not None else task.result()
            return DeferredReply(deferred_reply(name, target, claimed, self.defer_after))
        record: dict[str, Any] = {}

        def create_record() -> Callable[[Any, BaseException | None], CallToolResult]:
            record.update(operations.defer_call(name, target, started_at=started_at, call_locks=call_locks))
            operation_id = record["operation_id"]
            return lambda value, error: _record_outcome(operations, operation_id, name, value, error, complete)

        if not call.defer(create_record):
            return call.outcome()
        return DeferredReply(deferred_reply(name, target, record, self.defer_after))

    async def _acquire_slot(self, timeout: float) -> bool:
        """Take an execution slot within ``timeout`` seconds, in arrival order; False if none came free.

        A freed slot goes straight to the oldest waiter (``_release_slot``),
        so nothing polls, and a slot never sits free while a call waits.
        """
        self._loop = asyncio.get_running_loop()
        if not self._slot_waiters and self._slots.acquire(blocking=False):
            return True
        waiter = self._loop.create_future()
        self._slot_waiters.append(waiter)
        granted = False
        try:
            # A slot may have come free since the last hand-out.
            self._dispatch()
            with anyio.move_on_after(max(0.0, timeout)):
                await waiter
                granted = True
            return granted
        finally:
            if not granted:
                if waiter.done() and not waiter.cancelled():
                    # Handed a slot just as the wait ended: pass it on.
                    self._release_slot()
                else:
                    waiter.cancel()
                    with contextlib.suppress(ValueError):
                        self._slot_waiters.remove(waiter)

    def _release_slot(self) -> None:
        """Give a slot back and hand it to the oldest waiter; any thread may call it."""
        self._slots.release()
        loop = self._loop
        if loop is None:
            return
        with contextlib.suppress(RuntimeError):
            # RuntimeError: that loop has closed, and nobody waits on it any more.
            loop.call_soon_threadsafe(self._dispatch)

    def _dispatch(self) -> None:
        """Hand the free slots to the waiters, oldest first; on the event loop's thread."""
        while self._slot_waiters:
            waiter = self._slot_waiters[0]
            if waiter.done():
                self._slot_waiters.popleft()
                continue
            if not self._slots.acquire(blocking=False):
                return
            self._slot_waiters.popleft()
            waiter.set_result(None)


def _slots_busy(operations, name: str, claimed: dict[str, Any] | None) -> CallToolResult:
    """The reply for a call that got no execution slot in time; no runtime work began."""
    message = f"OPERATION_QUEUE_FULL: every tool call slot is busy, so {name} did not run; retry later"
    error = DomainError(
        code=ErrorCode.OPERATION_QUEUE_FULL,
        message=message,
        hint="Running tool calls hold every slot; send the call again later",
        retryable=True,
        details={"output_state": "absent"},
    )
    result = domain_error_result(error, message=message)
    if claimed is not None:
        # Nothing ran, so a resend with the request_id runs the call instead of getting this reply (claim_call).
        operations.finish_call(claimed["operation_id"], error=structured_error(result), reply=_json_reply(result))
    return result


def _cancel_before_start(operations, operation_id: str, name: str) -> None:
    """Finish a claimed request that never acquired a slot; no runtime work began."""
    message = (
        f"OPERATION_CANCELLED: request was cancelled before {name} obtained an execution slot; the tool did not run"
    )
    error = DomainError(
        code=ErrorCode.OPERATION_CANCELLED,
        message=message,
        hint="Nothing was executed. Use a new request_id to retry; resending this request_id returns this cancellation",
        details={"output_state": "absent", "cancelled": True},
    )
    result = domain_error_result(error, message=message)
    operations.finish_call(operation_id, error=structured_error(result), reply=_json_reply(result))


def _record_outcome(
    operations, operation_id: str, name: str, value: Any, error: BaseException | None, complete
) -> CallToolResult:
    """Store a call's outcome the way its reply carries it, or would have; return that reply."""
    try:
        if error is None:
            result = complete(value)
        else:
            if not isinstance(error, ToolError):
                logger.error("Unexpected failure in tool %s", name, exc_info=error)
            # The reply handle_call_tool gives for the same exception.
            result = tool_error_result(error, name)
        if result.is_error:
            operations.finish_call(operation_id, error=structured_error(result), reply=_json_reply(result))
        else:
            operations.finish_call(
                operation_id,
                result=structured_value(result),
                source=structured_source(result),
                reply=_json_reply(result),
            )
        return result
    except Exception as exc:
        logger.exception("Could not record the outcome of tool %s", name)
        result = tool_error_result(exc, name)
        operations.finish_call(operation_id, error=structured_error(result), reply=_json_reply(result))
        return result


def _json_reply(result: CallToolResult) -> dict[str, Any]:
    return result.model_dump(mode="json", by_alias=True, exclude_none=True)


def deferred_reply(name: str, target: str, operation: dict[str, Any], waited: float) -> CallToolResult:
    payload = {
        "deferred": True,
        "tool": name,
        "target": target,
        "operation": {
            key: operation[key] for key in ("operation_id", "kind", "state", "poll_after_ms") if key in operation
        },
        "message": (
            f"{name} is still running after {waited:g} seconds and continues on the server. Call get_operation "
            f"with this operation_id (wait_seconds up to {OPERATION_WAIT_MAX_SECONDS}) for its result instead of "
            f"calling {name} again."
        ),
    }
    return CallToolResult(content=[TextContent(type="text", text=_json_text(payload))], structured_content=payload)


__all__ = ["CALL_SLOTS", "DEFER_AFTER_SECONDS", "DeferredCalls", "DeferredReply", "deferred_reply"]
