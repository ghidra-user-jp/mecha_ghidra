"""A read whose request is cancelled stops; a write that has started, a job and a deferred call do not."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from ghidra_mcp.application.cancellation import CallCancellation, bound, current_call_cancellation
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.domain.policies import configure_lock_timeout_seconds, get_lock_timeout_seconds
from ghidra_mcp.presentation.cli_runtime import create_cli_runtime
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from import_operation_support import FakeMonitor
from runtime_fakes import FakeProgram

PSEUDOCODE = "int main(void) { return 0; }"
DECOMPILE = {"target": "default", "address": "0x1000"}
EDITS = [{"kind": "set_comment", "address": "0x1000", "comment": "checked", "comment_type": "eol"}]


class TestCallCancellation:
    def test_the_hooks_run_once_when_the_call_is_cancelled(self):
        cancellation, ran = CallCancellation(), []
        cancellation.register(lambda: ran.append("first"))
        cancellation.register(lambda: ran.append("second"))
        assert not cancellation.cancelled
        cancellation.cancel()
        cancellation.cancel()
        assert cancellation.cancelled and ran == ["first", "second"]

    def test_a_hook_registered_after_the_cancel_runs_at_once(self):
        cancellation, ran = CallCancellation(), []
        cancellation.cancel()
        unregister = cancellation.register(lambda: ran.append("late"))
        assert ran == ["late"]
        unregister()  # nothing to take back, and no error

    def test_a_hook_that_was_taken_back_does_not_run(self):
        cancellation, ran = CallCancellation(), []
        unregister = cancellation.register(lambda: ran.append("taken back"))
        unregister()
        unregister()
        cancellation.cancel()
        assert ran == []

    def test_a_failing_hook_does_not_keep_the_others_from_running(self):
        cancellation, ran = CallCancellation(), []

        def failing():
            raise RuntimeError("the monitor is gone")

        cancellation.register(failing)
        cancellation.register(lambda: ran.append("still runs"))
        cancellation.cancel()
        assert ran == ["still runs"]

    def test_the_current_cancellation_belongs_to_one_thread_and_is_restored(self):
        outer, inner = CallCancellation(), CallCancellation()
        assert current_call_cancellation() is None
        with bound(outer):
            assert current_call_cancellation() is outer
            with bound(inner):
                assert current_call_cancellation() is inner
            assert current_call_cancellation() is outer
            seen = []
            other = threading.Thread(target=lambda: seen.append(current_call_cancellation()))
            other.start()
            other.join()
            assert seen == [None]
        assert current_call_cancellation() is None


class Targets:
    def project_key(self, target):
        return "/project::test"


class Registry:
    """Core commands that wait for ``release`` and notice the cancellation of their request."""

    def __init__(self) -> None:
        self.operations = OperationManager(Targets())
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.ended = threading.Event()
        self.cancellation: object = "not called"

    def call(self, command, params, target):
        self.cancellation = current_call_cancellation()
        if self.cancellation is not None:
            self.cancellation.register(self.cancelled.set)
        self.started.set()
        try:
            deadline = time.monotonic() + 10
            while not self.release.is_set():
                if self.cancelled.is_set():
                    raise RuntimeError("stopped: the request was cancelled")
                assert time.monotonic() < deadline, "the test did not release the call"
                time.sleep(0.005)
            return PSEUDOCODE if command == "decompile_function" else {"status": "applied"}
        finally:
            self.ended.set()

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)


@pytest.fixture
def registry():
    registry = Registry()
    yield registry
    registry.release.set()  # a worker thread still waiting must not outlive the test
    registry.operations.shutdown()


def build_server(registry, *, defer_after=10):
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("decompile_function", "apply_edits", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    runtime.mcp.deferred_calls.defer_after = defer_after
    return runtime.mcp


async def cancel_when_started(registry, task):
    assert await asyncio.to_thread(registry.started.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class TestACancelledRequest:
    def test_a_read_is_cancelled_with_its_request(self, registry):
        server = build_server(registry)

        async def scenario():
            await cancel_when_started(
                registry, asyncio.ensure_future(server.call_tool("decompile_function", DECOMPILE))
            )
            assert await asyncio.to_thread(registry.cancelled.wait, 2), "the read was never told"
            assert await asyncio.to_thread(registry.ended.wait, 2), "the read did not stop"

        asyncio.run(scenario())

    def test_a_write_that_has_started_is_never_cancelled(self, registry):
        server = build_server(registry)

        async def scenario():
            call = server.call_tool("apply_edits", {"target": "t", "edits": EDITS})
            await cancel_when_started(registry, asyncio.ensure_future(call))
            assert registry.cancellation is None, "a write gets no cancellation to watch"
            await asyncio.sleep(0.2)
            assert not registry.cancelled.is_set() and not registry.ended.is_set(), "the write must go on"
            registry.release.set()
            assert await asyncio.to_thread(registry.ended.wait, 2)

        asyncio.run(scenario())

    def test_a_read_that_was_deferred_runs_to_its_end(self, registry):
        server = build_server(registry, defer_after=0.2)

        async def scenario():
            reply = await server.call_tool("decompile_function", DECOMPILE)
            assert reply.structured_content["deferred"] is True, "the deadline defers a call; it does not cancel it"
            await asyncio.sleep(0.3)
            assert not registry.cancelled.is_set() and not registry.ended.is_set()
            registry.release.set()
            assert await asyncio.to_thread(registry.ended.wait, 2)
            operation_id = reply.structured_content["operation"]["operation_id"]
            record = await server.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 2})
            assert record.structured_content["result"]["state"] == "succeeded"

        asyncio.run(scenario())

    def test_a_request_answered_in_time_leaves_nothing_to_cancel(self, registry):
        server = build_server(registry)
        registry.release.set()

        async def scenario():
            reply = await server.call_tool("decompile_function", DECOMPILE)
            assert reply.structured_content == {"result": PSEUDOCODE}

        asyncio.run(scenario())
        assert not registry.cancelled.is_set()


KEY = ("/projects", "sample")


class Core:
    """The headless core of the runtime tests below: decompile_function waits until released or cancelled."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.stopped_by_cancel = threading.Event()
        self.quarantine = None

    def execute(self, command, params, key="default", *, task_monitor=None, on_begin=None, record_transactions=False):
        self.calls.append((command, task_monitor))
        if command != "decompile_function":
            return {"status": "applied"}
        self.entered.set()
        deadline = time.monotonic() + 10
        while not self.release.is_set():
            if task_monitor is not None and task_monitor.isCancelled():
                self.stopped_by_cancel.set()
                raise RuntimeError("DECOMPILE_TIMEOUT: stopped through the monitor")
            assert time.monotonic() < deadline, "the test did not release the call"
            time.sleep(0.002)
        return PSEUDOCODE

    def begins_itself(self, command):
        return False

    def execution_state(self, key):
        return self.quarantine

    def transaction_outcome(self):
        return "committed"

    def initialize(self, program, key="default"):
        return None

    def remove_context(self, key):
        return None

    def clear_contexts(self):
        return None


class Session:
    def __init__(self, handle):
        self.handle = handle
        self.program = FakeProgram("/sample.bin")

    def get_program(self):
        return self.program

    def get_project_handle(self):
        return self.handle

    def close(self, *, save=True, remove_program=False):
        return None

    def to_dict(self):
        return {"project_location": KEY[0], "project_name": KEY[1], "domain_path": "/sample.bin"}

    def is_analyzed(self):
        return False


@pytest.fixture
def stack():
    core = Core()
    bundle = create_cli_runtime(
        # get_operation must be published, or the deferral (and so the cancellation) is off.
        registered_specs={
            name: get_tool_spec(name) for name in ("decompile_function", "create_label", "get_operation")
        },
        core_accessor=lambda: core,
        checkout_required_commands=set(),
        presentation_config=ToolPresentationConfig(),
    )
    monitors: list[FakeMonitor] = []

    def create_cancellable_monitor():
        monitors.append(FakeMonitor())
        return monitors[-1]

    handle = SimpleNamespace(
        get_key=lambda: KEY,
        is_closed=lambda: False,
        close=lambda **_: None,
        create_cancellable_monitor=create_cancellable_monitor,
        refresh_project_data=lambda **_: None,
        get_sync_status=lambda _path: {"is_versioned": False, "can_add_to_repository": False},
    )
    store = bundle.runtime_backend._store
    store.sessions["default"] = Session(handle)
    store.target_projects["default"] = KEY
    store.project_handles[KEY] = handle
    store.locks["default"] = threading.RLock()
    previous_timeout = get_lock_timeout_seconds()
    configure_lock_timeout_seconds(3)
    try:
        yield SimpleNamespace(bundle=bundle, core=core, store=store, monitors=monitors)
    finally:
        core.release.set()
        bundle.registry.close_all()
        configure_lock_timeout_seconds(previous_timeout)


class TestTheRuntimeOfACancelledRead:
    def test_the_read_stops_through_its_ghidra_monitor(self, stack):
        server = stack.bundle.runtime.mcp

        async def scenario():
            task = asyncio.ensure_future(server.call_tool("decompile_function", DECOMPILE))
            assert await asyncio.to_thread(stack.core.entered.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await asyncio.to_thread(stack.core.stopped_by_cancel.wait, 2), "the monitor was not cancelled"

        asyncio.run(scenario())
        (monitor,) = stack.monitors
        assert monitor.isCancelled()
        assert stack.core.calls == [("decompile_function", monitor)]

    def test_a_read_that_finishes_leaves_its_monitor_alone(self, stack):
        stack.core.release.set()
        reply = asyncio.run(stack.bundle.runtime.mcp.call_tool("decompile_function", DECOMPILE))
        assert reply.structured_content == {"result": PSEUDOCODE}
        (monitor,) = stack.monitors
        assert not monitor.isCancelled()

    def test_a_read_cancelled_while_it_waits_for_its_locks_never_runs(self, stack):
        server = stack.bundle.runtime.mcp
        lock = stack.store.locks["default"]

        async def scenario():
            lock.acquire()  # the target is busy
            try:
                task = asyncio.ensure_future(server.call_tool("decompile_function", DECOMPILE))
                await asyncio.sleep(0.3)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            finally:
                lock.release()
            await asyncio.sleep(0.3)  # the worker gets the lock now

        asyncio.run(scenario())
        assert stack.core.calls == [], "nobody waits for the answer: the read must not run"
        assert stack.monitors == []

    def test_a_write_gets_no_monitor_to_cancel(self, stack):
        cancellation = CallCancellation()
        with bound(cancellation):
            stack.bundle.registry.call("create_label", {"address": "0x1000", "name": "x"}, "default")
        assert stack.core.calls == [("create_label", None)]
        assert stack.monitors == []

    def test_a_call_made_outside_a_cancellable_request_gets_no_monitor(self, stack):
        stack.core.release.set()
        stack.bundle.registry.call("decompile_function", DECOMPILE | {"name": "x"}, "default")
        assert stack.core.calls == [("decompile_function", None)]
