from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from ghidra_mcp.application.services import operations
from ghidra_mcp.application.services.operations import OperationManager, _error_payload
from ghidra_mcp.domain import DomainError, ErrorCode


def wait_terminal(manager, receipt, timeout=3):
    result = manager.wait_for(receipt["operation_id"], timeout)
    if result["state"] in {"queued", "running"}:
        pytest.fail(f"operation did not finish: {result}")
    return result


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("condition not reached")
        time.sleep(0.005)


class ControlledService:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.calls = []
        self.error = None
        self.result = "/sample.bin"
        self.prepares = 0
        self.lock_timeouts = 0

    def prepare_import(self, target, binary_path):
        self.prepares += 1
        return binary_path, "/project::test"

    def import_program(self, target, binary_path, *, control, **options):
        control.check_active()
        if self.lock_timeouts:
            self.lock_timeouts -= 1
            time.sleep(0.01)
            raise DomainError(ErrorCode.LOCK_TIMEOUT, "target lock is busy", retryable=True)
        control.bind_cancel(self.cancelled.set)
        try:
            control.begin()
            self.calls.append((target, binary_path, options, control.expected_project_key))
            self.started.set()
            assert self.release.wait(5), "test did not release worker"
        finally:
            control.bind_cancel(None)
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def jobs():
    service = ControlledService()
    manager = OperationManager(service)
    try:
        yield manager, service
    finally:
        service.release.set()
        manager.shutdown()


def submit(manager, *, name="sample.bin", request_id=None, target="default", **kwargs):
    return manager.submit_import(target, request_id=request_id, binary_path="/input/" + name, **kwargs)


def test_long_analysis_replay_and_result_are_one_operation(jobs):
    manager, service = jobs
    request_id = str(uuid4())
    receipt = submit(manager, request_id=request_id, analyze_imported=True)
    assert receipt["kind"] == "import_program" and receipt["request_id"] == request_id
    assert service.started.wait(1)
    current = manager.get(request_id=request_id)
    assert (current["state"], current["phase"], current["result"]) == ("running", "executing", None)
    assert current["poll_after_ms"] == 1000
    # Even if the input has disappeared and binding lookup would now fail,
    # a replay consults the original record before any admission/runtime work.
    service.prepare_import = lambda *_: pytest.fail("replay must not resolve target or inspect file")
    again = submit(manager, request_id=request_id.upper(), analyze_imported=True)
    assert again["operation_id"] == receipt["operation_id"] and again["replayed"]
    service.release.set()
    result = wait_terminal(manager, receipt)
    assert result["state"] == "succeeded"
    assert result["result"] == {"program": "/sample.bin"}
    assert result["finished_at"] is not None and result["poll_after_ms"] == 0
    result["result"]["program"] = "tampered"
    assert manager.get(request_id=request_id)["result"]["program"] == "/sample.bin"
    assert len(service.calls) == 1


def test_simultaneous_retry_conflict_and_project_alias(jobs):
    manager, service = jobs
    request_id = str(uuid4())
    barrier = threading.Barrier(8)

    def send(_):
        barrier.wait()
        return submit(manager, request_id=request_id)

    with ThreadPoolExecutor(8) as pool:
        receipts = list(pool.map(send, range(8)))
    assert len({r["operation_id"] for r in receipts}) == 1
    assert sum(not r["replayed"] for r in receipts) == 1
    with pytest.raises(DomainError) as conflict:
        submit(manager, request_id=request_id, analyze_imported=True)
    assert conflict.value.code == ErrorCode.REQUEST_ID_CONFLICT
    with pytest.raises(DomainError) as alias:
        submit(manager, target="alias")
    assert alias.value.code == ErrorCode.IMPORT_IN_PROGRESS
    assert alias.value.details["operation_id"] == receipts[0]["operation_id"]
    assert service.started.wait(1) and len(service.calls) == 1


def test_resend_without_request_id_joins_the_running_job(jobs):
    manager, service = jobs
    first = submit(manager, analyze_imported=True)
    assert first["request_id"] is None and not first["replayed"]
    assert service.started.wait(1)
    again = submit(manager, analyze_imported=True)
    assert again["operation_id"] == first["operation_id"] and again["replayed"]
    # A request_id supplied on a resend becomes a lookup alias of that job.
    request_id = str(uuid4())
    aliased = submit(manager, request_id=request_id, analyze_imported=True)
    assert aliased["operation_id"] == first["operation_id"]
    assert manager.get(request_id=request_id)["operation_id"] == first["operation_id"]
    with pytest.raises(DomainError) as different:
        submit(manager, analyze_imported=False)
    assert different.value.code == ErrorCode.IMPORT_IN_PROGRESS
    service.release.set()
    assert wait_terminal(manager, first)["state"] == "succeeded"
    assert len(service.calls) == 1


def test_queue_full_is_retryable_and_does_not_consume_request():
    service = ControlledService()
    manager = OperationManager(service, queue_limit=1)
    try:
        first = submit(manager)
        assert service.started.wait(1)
        submit(manager, name="second.bin")
        request_id = str(uuid4())
        with pytest.raises(DomainError) as full:
            submit(manager, name="third.bin", request_id=request_id)
        assert full.value.code == ErrorCode.OPERATION_QUEUE_FULL and full.value.retryable
        with pytest.raises(DomainError) as missing:
            manager.get(request_id=request_id)
        assert missing.value.code == ErrorCode.OPERATION_NOT_FOUND
        service.release.set()
        wait_terminal(manager, first)
        manager._queue.join()
        third = submit(manager, name="third.bin", request_id=request_id)
        assert not third["replayed"] and wait_terminal(manager, third)["state"] == "succeeded"
    finally:
        service.release.set()
        manager.shutdown()


def test_history_evicts_the_oldest_released_jobs_but_keeps_reservations():
    service = ControlledService()
    manager = OperationManager(service, history_limit=2)
    try:
        service.error = DomainError(ErrorCode.OPERATION_FAILED, "close failed", details={"partial_import": True})
        service.release.set()
        uncertain = wait_terminal(manager, submit(manager, name="kept.bin", request_id=str(uuid4())))
        service.error = None
        done = [wait_terminal(manager, submit(manager, name=f"{i}.bin", request_id=str(uuid4()))) for i in range(3)]
        with pytest.raises(DomainError) as evicted:
            manager.get(operation_id=done[0]["operation_id"])
        assert evicted.value.code == ErrorCode.OPERATION_NOT_FOUND
        with pytest.raises(DomainError):
            manager.get(request_id=done[0]["request_id"])
        assert manager.get(operation_id=done[2]["operation_id"])["state"] == "succeeded"
        # A job that still reserves its output is never evicted.
        assert manager.get(operation_id=uncertain["operation_id"])["operation_error"]["details"]["output_state"] == (
            "created"
        )
        with pytest.raises(DomainError) as blocked:
            submit(manager, name="kept.bin")
        assert blocked.value.code == ErrorCode.IMPORT_OUTPUT_UNCERTAIN
    finally:
        manager.shutdown()


@pytest.mark.parametrize(
    "details,output_state",
    [
        ({"partial_import": True, "imported_domain_path": "/sample.bin"}, "created"),
        ({"cleanup_error": True}, "uncertain"),
        ({}, "uncertain"),
        ({"rollback_deleted": True, "partial_import": False}, "absent"),
        ({"output_created": False}, "absent"),
    ],
)
def test_cleanup_evidence_sets_output_state_and_reservation(jobs, details, output_state):
    manager, service = jobs
    hint = "Use load_project_program with imported_domain_path if partial_import is true"
    service.error = DomainError(
        ErrorCode.OPERATION_FAILED, "save/close failed", hint=hint, retryable=True, details=details
    )
    service.release.set()
    receipt = submit(manager, request_id=str(uuid4()))
    result = wait_terminal(manager, receipt)
    error = result["operation_error"]
    assert result["state"] == "failed"
    assert all(error["details"][k] == v for k, v in details.items())
    assert error["details"]["output_state"] == output_state
    assert error["hint"] == hint
    assert error["retryable"] is (output_state == "absent")
    assert "retry_with_new_request_id" not in error["details"]
    assert submit(manager, request_id=receipt["request_id"])["operation_id"] == receipt["operation_id"]
    if output_state != "absent":
        with pytest.raises(DomainError) as uncertain:
            submit(manager)
        assert uncertain.value.code == ErrorCode.IMPORT_OUTPUT_UNCERTAIN
        assert uncertain.value.details["operation_id"] == receipt["operation_id"]
    else:
        service.error = None
        assert wait_terminal(manager, submit(manager))["state"] == "succeeded"


def test_base_exception_fails_worker_and_queued_jobs(jobs, caplog):
    manager, service = jobs
    service.error = SystemExit("worker exits")
    first = submit(manager)
    assert service.started.wait(1)
    queued = submit(manager, name="queued.bin")
    with caplog.at_level(logging.ERROR, logger=operations.__name__):
        service.release.set()
        failed = wait_terminal(manager, first)
    assert failed["operation_error"]["code"] == "OPERATION_WORKER_FAILED"
    assert failed["operation_error"]["details"]["output_state"] == "uncertain"
    queued_result = wait_terminal(manager, queued)
    assert queued_result["state"] == "failed" and queued_result["started_at"] is None
    assert queued_result["operation_error"]["details"]["output_state"] == "absent"
    assert "Job worker stopped unexpectedly" in caplog.text
    with pytest.raises(DomainError) as stopped:
        submit(manager, name="new.bin")
    assert stopped.value.code == ErrorCode.OPERATION_WORKER_UNAVAILABLE
    assert len(service.calls) == 1


def test_invalid_result_cannot_leave_running_record(jobs):
    manager, service = jobs
    service.result = object()
    service.release.set()
    result = wait_terminal(manager, submit(manager))
    assert result["state"] == "failed" and result["operation_error"]["details"]["output_state"] == "uncertain"
    with pytest.raises(DomainError) as blocked:
        submit(manager)
    assert blocked.value.code == ErrorCode.IMPORT_OUTPUT_UNCERTAIN


def test_shutdown_cancels_the_running_import_and_drops_the_queue(jobs):
    manager, service = jobs
    first = submit(manager)
    assert service.started.wait(1)
    queued = submit(manager, name="queued.bin")
    # The loader rolled its half-analyzed program back after the cancellation.
    service.error = DomainError(ErrorCode.OPERATION_FAILED, "analysis cancelled", details={"rollback_deleted": True})
    closing = threading.Thread(target=manager.shutdown)
    closing.start()
    try:
        queued_result = wait_terminal(manager, queued)
        assert queued_result["operation_error"]["code"] == "OPERATION_SHUTDOWN"
        assert queued_result["started_at"] is None
        assert service.cancelled.wait(1), "shutdown must cancel the running analysis"
        assert closing.is_alive()
        with pytest.raises(DomainError):
            submit(manager, name="late.bin")
        service.release.set()
        closing.join(2)
        assert not closing.is_alive()
        error = wait_terminal(manager, first)["operation_error"]
        assert error["code"] == "OPERATION_SHUTDOWN"
        assert error["details"]["cancelled"] is True and error["details"]["output_state"] == "absent"
        assert len(service.calls) == 1
    finally:
        service.release.set()
        closing.join(2)


def test_shutdown_while_waiting_for_a_lock_never_starts_the_import(jobs):
    manager, service = jobs
    service.lock_timeouts = 10_000
    receipt = submit(manager)
    wait_until(lambda: manager.get(operation_id=receipt["operation_id"])["phase"] == "waiting_for_lock")
    manager.shutdown()
    result = manager.get(operation_id=receipt["operation_id"])
    assert result["state"] == "failed" and result["operation_error"]["code"] == "OPERATION_SHUTDOWN"
    assert result["operation_error"]["details"]["output_state"] == "absent"
    assert "cancelled" not in result["operation_error"]["details"], "a job that never started was not cancelled"
    assert not service.calls


def test_lock_timeout_before_start_keeps_the_job_waiting(jobs):
    manager, service = jobs
    service.lock_timeouts = 3
    service.release.set()
    receipt = submit(manager)
    assert receipt["state"] in {"queued", "running"}
    result = wait_terminal(manager, receipt)
    assert result["state"] == "succeeded" and service.lock_timeouts == 0


def test_wait_for_returns_when_the_job_finishes(jobs):
    manager, service = jobs
    receipt = submit(manager)
    assert service.started.wait(1)
    # Any accepted spelling of the ID waits for the same job.
    assert manager.is_pending(receipt["operation_id"].upper())
    started = time.monotonic()
    pending = manager.wait_for(receipt["operation_id"].upper(), 0.2)
    assert time.monotonic() - started >= 0.15
    assert pending["state"] == "running" and pending["poll_after_ms"] == 0
    threading.Timer(0.1, service.release.set).start()
    started = time.monotonic()
    done = manager.wait_for(receipt["operation_id"], 5)
    assert done["state"] == "succeeded" and time.monotonic() - started < 2


def test_idle_worker_exits_and_a_new_one_starts(jobs, monkeypatch):
    monkeypatch.setattr(operations, "_IDLE_EXIT_SECONDS", 0.05)
    manager, service = jobs
    service.release.set()
    wait_terminal(manager, submit(manager))
    wait_until(lambda: manager._thread is None)
    assert wait_terminal(manager, submit(manager, name="next.bin"))["state"] == "succeeded"


def test_restart_is_not_proof_of_nonexecution(jobs):
    manager, _ = jobs
    receipt = submit(manager, request_id=str(uuid4()))
    restarted = OperationManager(ControlledService())
    assert manager.server_instance_id != restarted.server_instance_id
    for selector in ({"request_id": receipt["request_id"]}, {"operation_id": receipt["operation_id"]}):
        with pytest.raises(DomainError) as missing:
            restarted.get(**selector)
        assert missing.value.code == ErrorCode.OPERATION_NOT_FOUND
        assert missing.value.details["server_instance_id"] == restarted.server_instance_id


@pytest.mark.parametrize("request_id", ["+" + "1" * 31, " " + "1" * 31, "1" * 31 + "_", "١" * 32, "bad"])
def test_request_id_must_be_a_real_uuid(jobs, request_id):
    manager, _ = jobs
    with pytest.raises(DomainError) as invalid:
        submit(manager, request_id=request_id)
    assert invalid.value.code == ErrorCode.VALIDATION_ERROR
    with pytest.raises(DomainError) as lookup:
        manager.get(request_id=request_id)
    assert lookup.value.code == ErrorCode.VALIDATION_ERROR


def test_unserializable_exception_is_still_terminal(jobs):
    class BrokenError(Exception):
        def __str__(self):
            raise RuntimeError("format failure")

    manager, service = jobs
    service.error = BrokenError()
    service.release.set()
    result = wait_terminal(manager, submit(manager))
    assert result["state"] == "failed" and result["operation_error"]["code"] == "OPERATION_WORKER_FAILED"


def test_error_details_with_foreign_keys_stay_classified():
    payload = _error_payload(
        DomainError(ErrorCode.OPERATION_FAILED, "boom", details={("loc", "name"): object()}), "import_program"
    )
    assert payload["code"] == "OPERATION_FAILED"
    assert list(payload["details"]) == ["('loc', 'name')", "operation"]


def test_outer_worker_failure_marks_queue_and_stops_admission(jobs, monkeypatch, caplog):
    manager, service = jobs
    first = submit(manager)
    assert service.started.wait(1)
    queued = submit(manager, name="queued.bin")
    # Finalization is outside the loader's try/except and must still be covered.
    monkeypatch.setattr(manager, "_finish_locked", lambda *_: (_ for _ in ()).throw(RuntimeError("finalizer failed")))
    with caplog.at_level(logging.ERROR, logger=operations.__name__):
        service.release.set()
        assert wait_terminal(manager, first)["state"] == "failed"
    assert wait_terminal(manager, queued)["state"] == "failed"
    assert "finalizer failed" in caplog.text
    with pytest.raises(DomainError) as unavailable:
        submit(manager, name="next.bin")
    assert unavailable.value.code == ErrorCode.OPERATION_WORKER_UNAVAILABLE


def test_unknown_queue_entry_is_skipped(jobs, caplog):
    manager, service = jobs
    first = submit(manager)
    assert service.started.wait(1)
    manager._queue.put_nowait("interrupted-admission")
    queued = submit(manager, name="queued.bin")
    with caplog.at_level(logging.WARNING, logger=operations.__name__):
        service.release.set()
        assert wait_terminal(manager, first)["state"] == "succeeded"
        assert wait_terminal(manager, queued)["state"] == "succeeded"
    assert "skipped unknown operation" in caplog.text
    assert wait_terminal(manager, submit(manager, name="later.bin"))["state"] == "succeeded"


def test_thread_start_failure_does_not_accept_or_reserve(jobs, monkeypatch):
    manager, service = jobs
    request_id = str(uuid4())
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", lambda _: (_ for _ in ()).throw(RuntimeError("cannot start")))
        with pytest.raises(RuntimeError, match="cannot start"):
            submit(manager, request_id=request_id)
    with pytest.raises(DomainError) as missing:
        manager.get(request_id=request_id)
    assert missing.value.code == ErrorCode.OPERATION_NOT_FOUND
    service.release.set()
    assert wait_terminal(manager, submit(manager, request_id=request_id))["state"] == "succeeded"


def test_replay_touches_no_filesystem(jobs, monkeypatch):
    manager, service = jobs
    request_id = str(uuid4())
    receipt = submit(manager, request_id=request_id, name="~alice/x.bin")
    assert service.started.wait(1)
    # A resend is answered from memory: no home-directory lookup, no path
    # normalization, even on the event loop that runs MCP replays inline.
    monkeypatch.setattr("pathlib.Path.expanduser", lambda *_: pytest.fail("replay resolved the path"))
    assert submit(manager, request_id=request_id, name="~alice/x.bin")["operation_id"] == receipt["operation_id"]
