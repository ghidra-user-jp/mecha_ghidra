"""Analysis jobs through the real MCP binding, services, runtime and locks; only Ghidra is faked."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.domain.policies import configure_lock_timeout_seconds, get_lock_timeout_seconds
from ghidra_mcp.presentation.cli_runtime import create_cli_runtime
from ghidra_mcp.presentation.config import ToolPresentationConfig
from import_operation_support import FakeMonitor
from runtime_fakes import FakeProgram
from test_import_operations import wait_until

KEY = ("/projects", "sample")
TOOLS = ("analyze_program", "get_operation", "list_targets", "get_program_info")


class Session:
    def __init__(self, handle, path="/sample.bin", *, read_only_version=None):
        self.handle = handle
        self.program = FakeProgram(path)
        self.read_only_version = read_only_version

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


class Core:
    """The headless core: analyze_program runs until released or cancelled."""

    def __init__(self):
        self.entered, self.release = threading.Event(), threading.Event()
        self.calls = []
        self.quarantine = None
        self.program = None
        self.stopped_by_cancel = False

    def execute(self, command, params, key="default", *, task_monitor=None):
        self.calls.append((command, dict(params), key, task_monitor))
        if command != "analyze_program":
            return {"name": "sample.bin"}
        self.entered.set()
        deadline = time.monotonic() + 5
        while not self.release.is_set():
            if task_monitor.isCancelled():
                self.stopped_by_cancel = True
                raise RuntimeError("ANALYSIS_CANCELLED: auto-analysis was cancelled before it finished")
            assert time.monotonic() < deadline, "test did not release the analysis"
            time.sleep(0.002)
        self.program._changed = True
        return {"analyzed": True, "forced": bool(params.get("force"))}

    def execution_state(self, key):
        return self.quarantine

    def initialize(self, program, key="default"):
        return None

    def remove_context(self, key):
        return None

    def clear_contexts(self):
        return None


@pytest.fixture
def jobs():
    core = Core()
    bundle = create_cli_runtime(
        registered_specs={name: get_tool_spec(name) for name in TOOLS},
        core_accessor=lambda: core,
        checkout_required_commands={"analyze_program"},
        presentation_config=ToolPresentationConfig(),
    )
    sync_status = {"is_versioned": False, "can_add_to_repository": False}
    handle = SimpleNamespace(
        get_key=lambda: KEY,
        is_closed=lambda: False,
        close=lambda **_: None,
        create_cancellable_monitor=FakeMonitor,
        refresh_project_data=lambda **_: None,
        get_sync_status=lambda _path: dict(sync_status),
    )
    store = bundle.runtime_backend._store
    session = Session(handle)
    store.sessions["default"] = session
    store.target_projects["default"] = KEY
    store.project_handles[KEY] = handle
    store.locks["default"] = threading.RLock()
    core.program = session.program
    old_timeout = get_lock_timeout_seconds()
    configure_lock_timeout_seconds(0.05)
    try:
        yield SimpleNamespace(bundle=bundle, core=core, store=store, handle=handle, sync_status=sync_status)
    finally:
        core.release.set()
        # A quarantined target is refused a normal close (correctly); lift it for teardown.
        core.quarantine = None
        bundle.registry.close_all()
        configure_lock_timeout_seconds(old_timeout)


def call(jobs, name, arguments):
    return asyncio.run(jobs.bundle.runtime.mcp.call_tool(name, arguments))


def record_of(reply):
    assert not reply.is_error, reply
    return reply.structured_content["result"]


def test_analysis_runs_as_a_job_and_leaves_the_result_unsaved(jobs):
    jobs.core.release.set()
    record = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 5}))
    assert record["kind"] == "analyze_program" and record["state"] == "succeeded"
    assert record["result"] == {"program": "/sample.bin", "analyzed": True, "forced": False}
    ((command, params, key, monitor),) = jobs.core.calls
    assert (command, params, key) == ("analyze_program", {}, "default")
    assert isinstance(monitor, FakeMonitor), "the job must pass a monitor it can cancel"
    # Like any edit, the analysis is recorded as an unsaved change, not saved.
    assert jobs.store.is_dirty_program("default", "/sample.bin")
    lookup = record_of(call(jobs, "get_operation", {"operation_id": record["operation_id"], "wait_seconds": 0}))
    assert lookup["kind"] == "analyze_program" and lookup["result"] == record["result"]


def test_force_reaches_the_core_command(jobs):
    jobs.core.release.set()
    record = record_of(call(jobs, "analyze_program", {"target": "default", "force": True, "wait_seconds": 5}))
    assert record["result"]["forced"] is True
    assert jobs.core.calls[0][1] == {"force": True}


def test_resend_joins_the_job_and_a_different_request_is_refused(jobs):
    first = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
    assert jobs.core.entered.wait(2)
    again = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
    assert again["operation_id"] == first["operation_id"] and again["replayed"]
    conflict = call(jobs, "analyze_program", {"target": "default", "force": True, "wait_seconds": 0})
    assert conflict.is_error and "ANALYSIS_IN_PROGRESS" in str(conflict) and first["operation_id"] in str(conflict)
    jobs.core.release.set()
    done = record_of(call(jobs, "get_operation", {"operation_id": first["operation_id"], "wait_seconds": 5}))
    assert done["state"] == "succeeded" and len(jobs.core.calls) == 1


@pytest.mark.parametrize(
    "prepare,code",
    [
        (lambda store, handle: store.sessions.pop("default"), "PROGRAM_NOT_OPEN"),
        (
            lambda store, handle: store.sessions.update(default=Session(handle, read_only_version=2)),
            "READ_ONLY_PROGRAM",
        ),
    ],
    ids=["no-program", "past-version"],
)
def test_admission_refuses_without_creating_a_job(jobs, prepare, code):
    prepare(jobs.store, jobs.handle)
    reply = call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0})
    assert reply.is_error and code in str(reply)
    assert not jobs.core.calls


def test_admission_during_a_reopen_is_retryable(jobs):
    class Reopening(Session):
        # A reload, checkout or pull closes the old session before it registers the new one.
        def get_project_handle(self):
            raise RuntimeError("Session is already closed")

        def get_program(self):
            raise RuntimeError("Session is already closed")

    jobs.store.sessions["default"] = Reopening(jobs.handle)
    try:
        reply = call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0})
    finally:
        jobs.store.sessions["default"] = Session(jobs.handle)
    assert reply.is_error and "SESSION_CHANGED" in str(reply) and '"retryable":true' in str(reply).replace(" ", "")
    assert not jobs.core.calls


@pytest.mark.parametrize(
    "replace",
    [
        lambda store, handle: store.sessions.update(default=Session(handle)),
        lambda store, handle: store.sessions.update(default=Session(handle, "/other.bin")),
        lambda store, handle: store.sessions.pop("default"),
    ],
    ids=["reloaded", "other-program", "closed"],
)
@pytest.mark.parametrize("waiting", ["queued", "for-lock"])
def test_a_session_replaced_while_the_job_waits_is_never_analyzed(jobs, replace, waiting):
    manager = jobs.bundle.registry.operations
    lock = jobs.store.locks["default"]
    if waiting == "queued":
        # Another target's analysis occupies the only worker: the job has not read the session yet.
        jobs.store.sessions["busy"] = Session(jobs.handle, "/busy.bin")
        jobs.store.target_projects["busy"] = KEY
        jobs.store.locks["busy"] = threading.RLock()
        record_of(call(jobs, "analyze_program", {"target": "busy", "wait_seconds": 0}))
        assert jobs.core.entered.wait(2)
        receipt = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
        assert manager.get(operation_id=receipt["operation_id"])["state"] == "queued"
        replace(jobs.store, jobs.handle)
    else:
        # The job read the session, then waits for the target lock held here.
        lock.acquire()
        try:
            receipt = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
            wait_until(lambda: manager.get(operation_id=receipt["operation_id"])["phase"] == "waiting_for_lock")
            replace(jobs.store, jobs.handle)
        finally:
            lock.release()
    jobs.core.release.set()
    result = record_of(call(jobs, "get_operation", {"operation_id": receipt["operation_id"], "wait_seconds": 5}))
    error = result["operation_error"]
    assert result["state"] == "failed" and error["code"] == "SESSION_CHANGED"
    assert error["details"]["output_state"] == "absent" and error["retryable"] is True
    assert [call for call in jobs.core.calls if call[2] == "default"] == []


@pytest.mark.parametrize(
    "prepare,code",
    [
        (lambda jobs: setattr(jobs.core, "quarantine", {"reason": "stray_thread"}), "TARGET_EXECUTION_INVALID"),
        (lambda jobs: jobs.sync_status.update(is_versioned=True, is_checked_out=False), "CHECKOUT_REQUIRED"),
    ],
    ids=["quarantined", "not-checked-out"],
)
def test_the_existing_mutation_checks_run_inside_the_job(jobs, prepare, code):
    prepare(jobs)
    jobs.core.release.set()
    result = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 5}))
    error = result["operation_error"]
    assert result["state"] == "failed" and error["code"] == code
    assert error["details"]["output_state"] == "absent"
    assert not jobs.core.calls


def test_shutdown_cancels_the_running_analysis(jobs):
    receipt = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
    assert jobs.core.entered.wait(2)
    closing = threading.Thread(target=jobs.bundle.registry.close_all)
    closing.start()
    closing.join(2)
    assert not closing.is_alive(), "close_all waits only until the cancelled analysis returns"
    assert jobs.core.stopped_by_cancel, "shutdown must reach the analysis through its monitor"
    error = jobs.bundle.registry.operations.get(operation_id=receipt["operation_id"])["operation_error"]
    assert error["code"] == "OPERATION_SHUTDOWN"
    assert error["details"]["cancelled"] is True and error["details"]["output_state"] == "absent"
    assert not jobs.store.is_dirty_program("default", "/sample.bin")


def test_lock_timeout_names_the_job_that_holds_the_target(jobs):
    receipt = record_of(call(jobs, "analyze_program", {"target": "default", "wait_seconds": 0}))
    assert jobs.core.entered.wait(2)
    blocked = call(jobs, "get_program_info", {"target": "default"})
    assert blocked.is_error and "LOCK_TIMEOUT" in str(blocked)
    assert receipt["operation_id"] in str(blocked) and "get_operation" in str(blocked)
    jobs.core.release.set()
    record_of(call(jobs, "get_operation", {"operation_id": receipt["operation_id"], "wait_seconds": 5}))
    assert not call(jobs, "get_program_info", {"target": "default"}).is_error
