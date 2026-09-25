"""Real-Ghidra checks for long calls: a cancelled script job and a deferred tool call."""

import asyncio
import os
import threading
import time
from uuid import uuid4

import pytest

from test_runtime_dirty_state import TARGET, _prepare_scripts
from test_runtime_dirty_state import loaded as _loaded
from test_runtime_import_lifecycle import bundle as _bundle

bundle = _bundle
loaded = _loaded
pytestmark = pytest.mark.skipif(os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1", reason="requires real Ghidra")

# Writes a comment, then waits until cancelled, checking the monitor like a well-behaved script.
_LOOP_UNTIL_CANCELLED = """# @runtime PyGhidra
import time
setPlateComment(currentProgram.getMinAddress(), "SHOULD_ROLL_BACK")
while True:
    monitor.checkCancelled()
    time.sleep(0.05)
"""


def _until(api, record, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate(record):
        assert time.monotonic() < deadline, record
        record = api["get_operation"](operation_id=record["operation_id"], wait_seconds=1)
    return record


def test_cancel_operation_rolls_back_a_running_script(loaded):
    api = loaded.runtime.tools
    _prepare_scripts(loaded)
    before = api["get_comments"](target=TARGET, address="0x1000")["plate"]
    record = api["run_script"](target=TARGET, source=_LOOP_UNTIL_CANCELLED, wait_seconds=0)
    # The comment is set inside the script's transaction before it starts waiting.
    record = _until(api, record, lambda item: item["phase"] == "executing")
    time.sleep(0.5)
    assert api["cancel_operation"](operation_id=record["operation_id"])["state"] == "running"
    record = _until(api, record, lambda item: item["state"] not in {"queued", "running"})
    error = record["operation_error"]
    assert error["code"] == "OPERATION_CANCELLED" and error["details"]["cancelled"] is True
    assert error["details"]["transaction_outcome"] == "rolled_back"
    assert error["details"]["output_state"] == "absent"
    assert api["get_comments"](target=TARGET, address="0x1000")["plate"] == before


def test_a_deferred_call_returns_the_real_result_through_get_operation(loaded):
    mcp = loaded.runtime.mcp
    # Defer at once so an ordinary call takes the deferred path through the JVM.
    mcp.deferred_calls.defer_after = 0

    async def scenario():
        direct = await mcp.call_tool("get_program_info", {"target": TARGET})
        assert direct.structured_content["deferred"] is True, direct.structured_content
        operation_id = direct.structured_content["operation"]["operation_id"]
        reply = await mcp.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 20})
        return reply.structured_content["result"]

    try:
        record = asyncio.run(scenario())
    finally:
        mcp.deferred_calls.defer_after = 40.0
    assert record["state"] == "succeeded" and record["kind"] == "get_program_info"
    # Exactly what the same call returns when it answers directly.
    assert record["result"] == loaded.runtime.tools["get_program_info"](target=TARGET)


def test_a_timed_out_write_does_not_point_at_its_own_request(loaded, monkeypatch):
    store = loaded.runtime_backend._store
    entered, release = threading.Event(), threading.Event()

    def hold():
        with store.locks[TARGET]:
            entered.set()
            assert release.wait(15)

    holder = threading.Thread(target=hold)
    holder.start()
    request_id = str(uuid4())
    try:
        assert entered.wait(5)
        monkeypatch.setattr("ghidra_mcp.application.locks.get_lock_timeout_seconds", lambda: 0.05)
        reply = asyncio.run(
            loaded.runtime.mcp.call_tool(
                "apply_edits",
                {
                    "target": TARGET,
                    "request_id": request_id,
                    "edits": [{"kind": "set_comment", "address": "0x1000", "comment_type": "eol", "comment": "check"}],
                },
            )
        )
        error = reply.structured_content["error"]
        assert error["code"] == "LOCK_TIMEOUT"
        assert error["details"]["output_state"] == "absent"
        assert "operation_id" not in error["details"]
        assert loaded.registry.operations.get(request_id=request_id)["state"] == "failed"
    finally:
        release.set()
        holder.join(5)
    assert not holder.is_alive()


# Writes a comment, then waits for the test to create a file.
_WAIT_FOR_FILE = """# @runtime PyGhidra
import os, time
setPlateComment(currentProgram.getMinAddress(), "WAITED")
path = %r
while not os.path.exists(path):
    monitor.checkCancelled()
    time.sleep(0.05)
"""


def _first_java_call_during_script(loaded, tmp_path, *, attach):
    """Run a script while a brand-new Python thread makes its first Java call; return the job record."""
    import threading

    import jpype

    from ghidra_headless.scripts.execution import attach_server_thread

    api = loaded.runtime.tools
    _prepare_scripts(loaded)
    release = tmp_path / "release"
    record = api["run_script"](target=TARGET, source=_WAIT_FOR_FILE % str(release), wait_seconds=0)
    record = _until(api, record, lambda item: item["phase"] == "executing")
    called = threading.Event()
    done = threading.Event()

    def server_thread():
        if attach:
            attach_server_thread()
        jpype.JClass("java.lang.System").nanoTime()
        called.set()
        # Stay attached until the script has looked at the threads, then end the
        # JVM thread with this one, so a quarantined target can be recovered.
        done.wait(30)
        jpype.JClass("java.lang.Thread").detach()

    worker = threading.Thread(target=server_thread, name="AnyIO worker thread")
    worker.start()
    try:
        assert called.wait(10)
        release.touch()
        return _until(api, record, lambda item: item["state"] not in {"queued", "running"})
    finally:
        done.set()
        worker.join(10)


def test_a_server_thread_attached_under_its_name_does_not_quarantine_a_running_script(loaded, tmp_path):
    record = _first_java_call_during_script(loaded, tmp_path, attach=True)
    assert record["state"] == "succeeded", record
    assert record["result"]["execution_state"] == "valid"


def test_an_unnamed_jvm_thread_during_a_script_is_still_reported(loaded, tmp_path):
    # The control: without attach_server_thread the watch sees JPype's Thread-N.
    record = _first_java_call_during_script(loaded, tmp_path, attach=False)
    try:
        assert record["state"] == "failed"
        assert record["operation_error"]["details"]["execution_state"] == "invalid"
        assert record["operation_error"]["details"]["output_state"] == "uncertain"
    finally:
        loaded.runtime.tools["close_session"](target=TARGET, discard_changes=True)
