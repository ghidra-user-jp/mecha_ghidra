from __future__ import annotations

import json
import threading
import time
from functools import partial
from uuid import uuid4

import pytest

from ghidra_mcp.application.services import operations as operations_module
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.application.services.ports import LoadedProgram
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.operation_presentation import present_operation_outcome
from ghidra_mcp.presentation.result_store import ResultResourceStore

PROJECT = "/project::test"
SOURCE = "# @runtime PyGhidra\nprint(1)"


def wait_terminal(manager, receipt, timeout=3):
    result = manager.wait_for(receipt["operation_id"], timeout)
    if result["state"] in {"queued", "running"}:
        pytest.fail(f"operation did not finish: {result}")
    return result


class Targets:
    def project_key(self, target):
        return PROJECT


class Scripts:
    """Admission and execution of script jobs, gated by events."""

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.programs = {"default": LoadedProgram(PROJECT, "/sample.bin", 7)}
        self.calls = []
        self.controls = []
        self.result = {"status": "ok", "transaction_outcome": "committed", "stdout": {"text": "done"}}
        self.error = None
        self.refusal = None
        self.lock_timeouts = 0
        self.fail_before_begin = None

    def prepare_run(self, target, **arguments):
        if self.refusal is not None:
            raise self.refusal
        try:
            return self.programs[target]
        except KeyError:
            raise DomainError(ErrorCode.SESSION_NOT_FOUND, f"Session '{target}' is not initialized") from None

    def run_script(self, target, *, control, **arguments):
        self.controls.append(control)
        if self.lock_timeouts:
            self.lock_timeouts -= 1
            raise DomainError(ErrorCode.LOCK_TIMEOUT, "script barrier is busy", retryable=True)
        control.check_active()
        if self.fail_before_begin is not None:
            raise self.fail_before_begin
        control.bind_cancel(self.cancelled.set)
        try:
            # The runtime begins right before the script's transaction starts.
            control.begin()
            self.calls.append((target, arguments))
            self.started.set()
            assert self.release.wait(5), "test did not release the script"
        finally:
            control.bind_cancel(None)
        if self.error is not None:
            raise self.error
        return dict(self.result)


@pytest.fixture
def jobs():
    scripts = Scripts()
    manager = OperationManager(Targets(), script_service=scripts)
    try:
        yield manager, scripts
    finally:
        scripts.release.set()
        manager.shutdown()


def test_a_script_job_returns_the_script_result_and_an_identical_resend_joins_it(jobs):
    manager, scripts = jobs
    request_id = str(uuid4())
    receipt = manager.submit_script("default", source=SOURCE, request_id=request_id)
    assert receipt["kind"] == "run_script" and not receipt["replayed"]
    assert scripts.started.wait(1)
    # A lost reply resent with or without its request_id is the same job.
    assert manager.submit_script("default", source=SOURCE)["operation_id"] == receipt["operation_id"]
    assert manager.submit_script("default", source=SOURCE, request_id=request_id)["replayed"]
    # Any other script queues behind it; there is no *_IN_PROGRESS refusal.
    other = manager.submit_script("default", source=SOURCE, args=["x"])
    assert other["operation_id"] != receipt["operation_id"]
    assert manager.get(operation_id=other["operation_id"])["state"] == "queued"
    scripts.release.set()
    result = wait_terminal(manager, receipt)
    assert result["state"] == "succeeded" and result["result"] == scripts.result
    assert wait_terminal(manager, other)["state"] == "succeeded"
    assert [call[1] for call in scripts.calls] == [{"source": SOURCE}, {"source": SOURCE, "args": ["x"]}]
    # The control carries the session admission saw, so a reloaded program is refused.
    assert (scripts.controls[0].expected_project_key, scripts.controls[0].expected_generation) == (PROJECT, 7)
    # A finished script frees its request: the same text runs again as a new job.
    assert manager.submit_script("default", source=SOURCE)["operation_id"] != receipt["operation_id"]


@pytest.mark.parametrize(
    "refusal",
    [
        DomainError(ErrorCode.SCRIPT_NOT_FOUND, "no such script"),
        DomainError(ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE, "Jython is not installed"),
        DomainError(ErrorCode.VALIDATION_ERROR, "pass exactly one of script_id or source"),
    ],
)
def test_admission_refusals_leave_no_job_behind(jobs, refusal):
    manager, scripts = jobs
    scripts.refusal = refusal
    request_id = str(uuid4())
    with pytest.raises(DomainError) as refused:
        manager.submit_script("default", source=SOURCE, request_id=request_id)
    assert refused.value.code == refusal.code
    with pytest.raises(DomainError) as lookup:
        manager.get(request_id=request_id)
    assert lookup.value.code == ErrorCode.OPERATION_NOT_FOUND
    scripts.refusal = None
    with pytest.raises(DomainError) as missing:
        manager.submit_script("closed", source=SOURCE)
    assert missing.value.code == ErrorCode.SESSION_NOT_FOUND
    assert not scripts.calls


@pytest.mark.parametrize(
    "line",
    [
        "#" * 63 + "\n",
        # Non-ASCII text is measured in UTF-8, not in JSON's six-byte escapes.
        "# 日本語のコメントと説明\n",
        # Escaped quotes, backslashes and newlines still fit.
        'print("\\\\")\n',
    ],
)
def test_a_job_carries_a_whole_inline_source_but_not_more(jobs, line):
    manager, scripts = jobs
    scripts.release.set()
    header = "# @runtime PyGhidra\n"
    source = header + line * ((256 * 1024 - len(header)) // len(line.encode()))
    assert wait_terminal(manager, manager.submit_script("default", source=source))["state"] == "succeeded"
    with pytest.raises(DomainError) as oversized:
        manager.submit_script("default", source=source * 5)
    assert oversized.value.code == ErrorCode.VALIDATION_ERROR


@pytest.mark.parametrize(
    "details,output_state",
    [
        ({"transaction_outcome": "rolled_back"}, "absent"),
        ({"transaction_outcome": "unchanged"}, "absent"),
        ({"transaction_outcome": "committed"}, "created"),
        ({"transaction_outcome": "rolled_back", "output_created": True}, "created"),
        ({"transaction_outcome": "unknown", "execution_state": "invalid"}, "uncertain"),
        # Rolled back, but work the script left running may still change the program.
        ({"transaction_outcome": "rolled_back", "execution_state": "invalid"}, "uncertain"),
        # A failure after the transaction started that does not say how it ended.
        ({}, "uncertain"),
    ],
)
def test_a_failed_script_reports_what_its_transaction_left(jobs, details, output_state):
    manager, scripts = jobs
    scripts.error = DomainError(ErrorCode.SCRIPT_FAILED, "script raised", retryable=True, details=details)
    scripts.release.set()
    error = wait_terminal(manager, manager.submit_script("default", source=SOURCE))["operation_error"]
    assert error["code"] == "SCRIPT_FAILED" and error["details"]["output_state"] == output_state
    assert error["retryable"] is (output_state == "absent")


def test_a_refusal_before_the_transaction_starts_leaves_nothing(jobs):
    manager, scripts = jobs
    scripts.fail_before_begin = DomainError(ErrorCode.SESSION_CHANGED, "program changed; read it again")
    error = wait_terminal(manager, manager.submit_script("default", source=SOURCE))["operation_error"]
    assert error["code"] == "SESSION_CHANGED" and error["details"]["output_state"] == "absent"
    assert not scripts.calls


def presented_jobs(scripts):
    store = ResultResourceStore()
    present = partial(present_operation_outcome, config=ToolPresentationConfig(), store=store)
    return OperationManager(Targets(), script_service=scripts, present=present), store


def test_large_script_failures_keep_their_diagnostics_in_the_result_store():
    scripts = Scripts()
    manager, store = presented_jobs(scripts)
    details = {
        "transaction_outcome": "rolled_back",
        "execution_state": "invalid",
        "stdout": {"text": "normal output\n" * 4000},
        "stderr": {"text": "diagnostic\n" * 4000},
    }
    scripts.error = DomainError(ErrorCode.SCRIPT_FAILED, "failed", details=details)
    scripts.release.set()
    try:
        record = wait_terminal(manager, manager.submit_script("default", source=SOURCE))
    finally:
        manager.shutdown()
    error = record["operation_error"]
    assert error["code"] == "SCRIPT_FAILED" and error["truncated"] is True
    assert error["details"]["execution_state"] == "invalid"
    assert error["details"]["output_state"] == "uncertain"
    # The record stays small; the client reads the full diagnostics by result_id.
    assert len(json.dumps(record)) < 12_000
    stored = json.loads(store.read_text(error["result_id"]))["error"]["details"]
    assert {key: stored[key] for key in details} == details


def test_large_script_results_move_to_the_result_store():
    scripts = Scripts()
    manager, store = presented_jobs(scripts)
    scripts.result = {"status": "ok", "transaction_outcome": "unchanged", "stdout": {"text": "line\n" * 20000}}
    scripts.release.set()
    try:
        record = wait_terminal(manager, manager.submit_script("default", source=SOURCE))
    finally:
        manager.shutdown()
    assert record["state"] == "succeeded" and record["result"]["truncated"] is True
    assert len(json.dumps(record)) < 12_000
    assert json.loads(store.read_text(record["result"]["result_id"])) == scripts.result


def test_cancel_ends_a_queued_job_without_running_it(jobs):
    manager, scripts = jobs
    first = manager.submit_script("default", source=SOURCE)
    assert scripts.started.wait(1)
    queued = manager.submit_script("default", source=SOURCE, args=["later"])
    record = manager.cancel(queued["operation_id"])
    assert record["state"] == "failed"
    assert record["operation_error"]["code"] == "OPERATION_CANCELLED"
    assert record["operation_error"]["details"]["output_state"] == "absent"
    scripts.release.set()
    assert wait_terminal(manager, first)["state"] == "succeeded"
    assert len(scripts.calls) == 1
    with pytest.raises(DomainError) as finished:
        manager.cancel(first["operation_id"])
    assert finished.value.code == ErrorCode.VALIDATION_ERROR


def test_cancel_stops_a_running_script_through_its_monitor(jobs):
    manager, scripts = jobs
    receipt = manager.submit_script("default", source=SOURCE)
    assert scripts.started.wait(1)
    assert manager.cancel(receipt["operation_id"])["state"] == "running"
    assert scripts.cancelled.wait(1), "cancel_operation must cancel the script's monitor"
    scripts.error = DomainError(
        ErrorCode.SCRIPT_FAILED, "SCRIPT_CANCELLED: cancelled", details={"transaction_outcome": "rolled_back"}
    )
    scripts.release.set()
    error = wait_terminal(manager, receipt)["operation_error"]
    assert error["code"] == "OPERATION_CANCELLED"
    assert error["details"]["cancelled"] is True and error["details"]["output_state"] == "absent"


def test_cancel_ends_a_job_waiting_for_its_lock_at_once(jobs):
    manager, scripts = jobs
    scripts.lock_timeouts = 1_000_000
    receipt = manager.submit_script("default", source=SOURCE)
    deadline = time.monotonic() + 2
    while manager.get(operation_id=receipt["operation_id"])["phase"] != "waiting_for_lock":
        assert time.monotonic() < deadline
        time.sleep(0.005)
    record = manager.cancel(receipt["operation_id"])
    # The record ends now, although the worker still waits for the lock.
    assert record["state"] == "failed" and record["operation_error"]["code"] == "OPERATION_CANCELLED"
    scripts.lock_timeouts = 0
    scripts.release.set()
    # Once the lock is free, the worker refuses to begin; the next job runs.
    after = wait_terminal(manager, manager.submit_script("default", source=SOURCE, args=["next"]))
    assert after["state"] == "succeeded"
    assert [call[1].get("args") for call in scripts.calls] == [["next"]]
    assert manager.get(operation_id=receipt["operation_id"])["operation_error"]["code"] == "OPERATION_CANCELLED"


def test_shutdown_stops_waiting_for_a_script_that_ignores_cancellation(jobs, monkeypatch):
    manager, scripts = jobs
    monkeypatch.setattr(operations_module, "get_lock_timeout_seconds", lambda: 0.2)
    receipt = manager.submit_script("default", source=SOURCE)
    assert scripts.started.wait(1)
    closing = threading.Thread(target=manager.shutdown)
    started = time.monotonic()
    closing.start()
    closing.join(2)
    try:
        # The script never checked its monitor; shutdown went on without it.
        assert not closing.is_alive() and time.monotonic() - started < 2
        assert scripts.cancelled.is_set()
        assert manager.get(operation_id=receipt["operation_id"])["state"] == "running"
    finally:
        scripts.release.set()
