from __future__ import annotations

import threading
import time
from uuid import uuid4

import pytest

from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.application.services.ports import LoadedProgram
from ghidra_mcp.domain import DomainError, ErrorCode

PROJECT = "/project::test"


def wait_terminal(manager, receipt, timeout=3):
    result = manager.wait_for(receipt["operation_id"], timeout)
    if result["state"] in {"queued", "running"}:
        pytest.fail(f"operation did not finish: {result}")
    return result


class AnalysisService:
    """Admission and execution of analysis jobs, gated by events."""

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.programs = {"default": LoadedProgram(PROJECT, "/sample.bin", 7), "other": LoadedProgram(PROJECT, "/b", 8)}
        self.calls = []
        self.controls = []
        self.error = None
        self.lock_timeouts = 0
        self.analyzed = True

    def project_key(self, target):
        return PROJECT if target in self.programs or target == "idle" else None

    def prepare_analysis(self, target):
        try:
            return self.programs[target]
        except KeyError:
            raise DomainError(ErrorCode.SESSION_NOT_FOUND, f"Session '{target}' is not initialized") from None

    def prepare_import(self, target, binary_path):
        return binary_path, PROJECT

    def import_program(self, target, binary_path, *, control, **options):
        control.check_active()
        control.begin()
        self.calls.append(("import", target, binary_path))
        return "/" + binary_path.rsplit("/", 1)[-1]

    def analyze_program(self, target, *, force, control):
        self.controls.append(control)
        if self.lock_timeouts:
            self.lock_timeouts -= 1
            raise DomainError(ErrorCode.LOCK_TIMEOUT, "target lock is busy", retryable=True)
        control.check_active()
        control.bind_cancel(self.cancelled.set)
        try:
            control.begin()
            self.calls.append(("analyze", target, force))
            self.started.set()
            assert self.release.wait(5), "test did not release the analysis"
        finally:
            control.bind_cancel(None)
        # One run fails; the next one succeeds unless the test sets another error.
        error, self.error = self.error, None
        if error:
            raise error
        return {"analyzed": self.analyzed, "forced": force}


@pytest.fixture
def jobs():
    service = AnalysisService()
    manager = OperationManager(service)
    try:
        yield manager, service
    finally:
        service.release.set()
        manager.shutdown()


def test_analysis_job_reports_the_program_and_is_not_repeated_by_a_resend(jobs):
    manager, service = jobs
    request_id = str(uuid4())
    receipt = manager.submit_analysis("default", request_id=request_id)
    assert receipt["kind"] == "analyze_program" and not receipt["replayed"]
    assert service.started.wait(1)
    # A lost reply resent with or without its request_id is the same job.
    assert manager.submit_analysis("default")["operation_id"] == receipt["operation_id"]
    assert manager.submit_analysis("default", request_id=request_id)["replayed"]
    with pytest.raises(DomainError) as different:
        manager.submit_analysis("default", force=True)
    assert different.value.code == ErrorCode.ANALYSIS_IN_PROGRESS
    assert different.value.details["operation_id"] == receipt["operation_id"]
    service.release.set()
    result = wait_terminal(manager, receipt)
    assert result["state"] == "succeeded"
    assert result["result"] == {"program": "/sample.bin", "analyzed": True, "forced": False}
    assert service.calls == [("analyze", "default", False)]
    # The control carries what admission saw, so the runtime can refuse a replaced session.
    assert (service.controls[0].expected_project_key, service.controls[0].expected_generation) == (PROJECT, 7)
    # A finished analysis frees the program at once.
    again = manager.submit_analysis("default", force=True)
    assert again["operation_id"] != receipt["operation_id"]


def test_admission_errors_leave_no_job_behind(jobs):
    manager, service = jobs
    request_id = str(uuid4())
    with pytest.raises(DomainError) as missing:
        manager.submit_analysis("closed", request_id=request_id)
    assert missing.value.code == ErrorCode.SESSION_NOT_FOUND
    with pytest.raises(DomainError) as lookup:
        manager.get(request_id=request_id)
    assert lookup.value.code == ErrorCode.OPERATION_NOT_FOUND
    assert not service.calls


def test_request_id_cannot_switch_job_kinds(jobs):
    manager, service = jobs
    service.release.set()
    request_id = str(uuid4())
    imported = wait_terminal(manager, manager.submit_import("default", binary_path="/in/a.bin", request_id=request_id))
    assert imported["state"] == "succeeded" and imported["kind"] == "import_program"
    with pytest.raises(DomainError) as conflict:
        manager.submit_analysis("default", request_id=request_id)
    assert conflict.value.code == ErrorCode.REQUEST_ID_CONFLICT


def test_imports_and_analyses_share_one_queue_in_submission_order(jobs):
    manager, service = jobs
    analysis = manager.submit_analysis("default")
    assert service.started.wait(1)
    imported = manager.submit_import("default", binary_path="/in/next.bin")
    # The kinds never block each other: the single worker runs them one at a time.
    same_name = manager.submit_import("default", binary_path="/in/sample.bin")
    assert manager.get(operation_id=imported["operation_id"])["state"] == "queued"
    service.release.set()
    assert wait_terminal(manager, analysis)["state"] == "succeeded"
    assert wait_terminal(manager, imported)["state"] == "succeeded"
    assert wait_terminal(manager, same_name)["state"] == "succeeded"
    assert [call[0] for call in service.calls] == ["analyze", "import", "import"]


def test_a_failed_import_that_keeps_its_name_does_not_block_analysis(jobs):
    manager, service = jobs
    service.release.set()
    failing = service.import_program

    def import_program(target, binary_path, *, control, **options):
        failing(target, binary_path, control=control, **options)
        raise DomainError(ErrorCode.OPERATION_FAILED, "close failed", details={"partial_import": True})

    service.import_program = import_program
    failed = wait_terminal(manager, manager.submit_import("default", binary_path="/in/sample.bin"))
    assert failed["operation_error"]["details"]["output_state"] == "created"
    # The program exists and is loaded: it can be analyzed at once.
    analysis = wait_terminal(manager, manager.submit_analysis("default"))
    assert analysis["state"] == "succeeded" and analysis["result"]["program"] == "/sample.bin"
    # Only another import of that name stays refused.
    with pytest.raises(DomainError) as refused:
        manager.submit_import("default", binary_path="/in/sample.bin")
    assert refused.value.code == ErrorCode.IMPORT_OUTPUT_UNCERTAIN


def test_a_request_after_a_reload_is_a_new_job(jobs):
    manager, service = jobs
    request_id = str(uuid4())
    first = manager.submit_analysis("default", request_id=request_id)
    assert service.started.wait(1)
    service.programs["default"] = LoadedProgram(PROJECT, "/sample.bin", 8)
    # Same arguments, but the target now holds another session: not the old job.
    second = manager.submit_analysis("default")
    assert second["operation_id"] != first["operation_id"] and not second["replayed"]
    # A request_id always names the job it was first given to.
    assert manager.submit_analysis("default", request_id=request_id)["operation_id"] == first["operation_id"]
    service.release.set()
    assert wait_terminal(manager, second)["state"] == "succeeded"
    assert [control.expected_generation for control in service.controls] == [7, 8]


@pytest.mark.parametrize(
    "details,output_state",
    [
        ({}, "absent"),
        ({"partial_import": True}, "absent"),
        ({"output_created": True}, "created"),
        # The failure could not be cleaned up after (or converted): inspect the program.
        ({"cleanup_error": True}, "uncertain"),
        ({"output_created": True, "cleanup_error": True}, "uncertain"),
    ],
)
def test_a_failed_analysis_reports_what_it_left_and_frees_the_program(jobs, details, output_state):
    manager, service = jobs
    service.error = DomainError(ErrorCode.OPERATION_FAILED, "analyzer failed", retryable=True, details=details)
    service.release.set()
    failed = wait_terminal(manager, manager.submit_analysis("default"))
    error = failed["operation_error"]
    assert failed["state"] == "failed" and error["details"]["output_state"] == output_state
    # The transaction was aborted, so a transient cause may be retried; committed changes may not.
    assert error["retryable"] is (output_state == "absent")
    service.error = None
    assert wait_terminal(manager, manager.submit_analysis("default"))["state"] == "succeeded"


def test_shutdown_cancels_a_running_analysis(jobs):
    manager, service = jobs
    receipt = manager.submit_analysis("default")
    assert service.started.wait(1)
    service.error = DomainError(ErrorCode.OPERATION_FAILED, "ANALYSIS_CANCELLED: cancelled")
    closing = threading.Thread(target=manager.shutdown)
    closing.start()
    try:
        assert service.cancelled.wait(1), "shutdown must cancel the running analysis"
        service.release.set()
        closing.join(2)
        error = wait_terminal(manager, receipt)["operation_error"]
        assert error["code"] == "OPERATION_SHUTDOWN"
        assert error["details"]["cancelled"] is True and error["details"]["output_state"] == "absent"
    finally:
        service.release.set()
        closing.join(2)


def test_lock_timeout_before_the_analysis_starts_keeps_it_waiting(jobs):
    manager, service = jobs
    service.lock_timeouts = 2
    service.release.set()
    result = wait_terminal(manager, manager.submit_analysis("default"))
    assert result["state"] == "succeeded" and service.lock_timeouts == 0


def test_lock_holder_names_the_job_only_while_it_holds_its_locks(jobs):
    manager, service = jobs
    assert manager.lock_holder("default") is None
    service.lock_timeouts = 1_000_000
    waiting = manager.submit_analysis("default")
    deadline = time.monotonic() + 2
    while manager.get(operation_id=waiting["operation_id"])["phase"] != "waiting_for_lock":
        assert time.monotonic() < deadline
        time.sleep(0.005)
    # Still waiting for its own locks: it is not what anyone else waits for.
    assert manager.lock_holder("default") is None
    service.lock_timeouts = 0
    assert service.started.wait(2)
    operation_id = waiting["operation_id"]
    assert manager.lock_holder("default") == operation_id
    # Another target of the same project waits for the job's project lock.
    assert manager.lock_holder("idle") == operation_id
    assert manager.lock_holder("elsewhere") is None
    assert manager.lock_holder("elsewhere", any_target=True) == operation_id
    service.release.set()
    wait_terminal(manager, waiting)
    assert manager.lock_holder("default") is None


def test_a_cancelled_job_is_no_lock_holder_while_its_worker_still_waits(jobs):
    manager, service = jobs
    waiting, release = threading.Event(), threading.Event()

    def analyze_program(target, *, force, control):
        control.check_active()
        # Holding the service locks, waiting for a runtime lock nothing interrupts.
        waiting.set()
        assert release.wait(5)
        control.begin()
        pytest.fail("a cancelled job must not begin")

    service.analyze_program = analyze_program
    receipt = manager.submit_analysis("default")
    assert waiting.wait(2)
    assert manager.lock_holder("default") == receipt["operation_id"]
    manager.cancel(receipt["operation_id"])
    # get_operation would return at once, and the retry fail again.
    assert manager.lock_holder("default") is None
    assert manager.lock_holder("elsewhere", any_target=True) is None
    release.set()
    manager._queue.join()
    assert manager.get(operation_id=receipt["operation_id"])["operation_error"]["code"] == "OPERATION_CANCELLED"


def test_cancelled_queued_jobs_free_their_queue_slots():
    service = AnalysisService()
    manager = OperationManager(service, queue_limit=2)
    try:
        running = manager.submit_analysis("default")
        assert service.started.wait(1)
        queued = [manager.submit_import("default", binary_path=f"/in/{name}.bin") for name in ("a", "b")]
        with pytest.raises(DomainError) as full:
            manager.submit_import("default", binary_path="/in/c.bin")
        assert full.value.code == ErrorCode.OPERATION_QUEUE_FULL
        for receipt in queued:
            assert manager.cancel(receipt["operation_id"])["state"] == "failed"
        # The worker has not reached them, but cancelled jobs take no slot.
        accepted = manager.submit_import("default", binary_path="/in/c.bin")
        service.release.set()
        assert wait_terminal(manager, running)["state"] == "succeeded"
        assert wait_terminal(manager, accepted)["state"] == "succeeded"
        assert [call[2] for call in service.calls if call[0] == "import"] == ["/in/c.bin"]
    finally:
        service.release.set()
        manager.shutdown()


def test_a_request_after_cancel_operation_is_a_new_job(jobs):
    manager, service = jobs
    first = manager.submit_analysis("default")
    assert service.started.wait(1)
    service.error = DomainError(ErrorCode.OPERATION_FAILED, "ANALYSIS_CANCELLED: cancelled")
    assert manager.cancel(first["operation_id"])["state"] == "running"
    assert service.cancelled.wait(1)
    # The job being cancelled takes nobody along: the analysis asked for again runs after it.
    again = manager.submit_analysis("default")
    assert again["operation_id"] != first["operation_id"] and not again["replayed"]
    service.release.set()
    assert wait_terminal(manager, first)["operation_error"]["code"] == "OPERATION_CANCELLED"
    assert wait_terminal(manager, again)["state"] == "succeeded"
    assert [call[0] for call in service.calls] == ["analyze", "analyze"]


def test_an_import_being_cancelled_keeps_its_name_until_it_ends(jobs):
    manager, service = jobs
    started, release = threading.Event(), threading.Event()

    def import_program(target, binary_path, *, control, **options):
        control.check_active()
        control.begin()
        started.set()
        assert release.wait(5)
        raise DomainError(ErrorCode.OPERATION_FAILED, "IMPORT_CANCELLED: cancelled", details={"rollback_deleted": True})

    service.import_program = import_program
    first = manager.submit_import("default", binary_path="/in/sample.bin")
    assert started.wait(1)
    manager.cancel(first["operation_id"])
    # It may still leave the program behind, so another import of the name waits for it.
    with pytest.raises(DomainError) as waiting:
        manager.submit_import("default", binary_path="/in/sample.bin")
    assert waiting.value.code == ErrorCode.IMPORT_IN_PROGRESS and waiting.value.retryable
    assert waiting.value.details["operation_id"] == first["operation_id"]
    release.set()
    ended = wait_terminal(manager, first)["operation_error"]
    assert (ended["code"], ended["details"]["output_state"]) == ("OPERATION_CANCELLED", "absent")
    service.import_program = AnalysisService.import_program.__get__(service)
    assert wait_terminal(manager, manager.submit_import("default", binary_path="/in/sample.bin"))["state"] == (
        "succeeded"
    )


def test_a_cancel_that_lands_while_the_outcome_is_presented_stands(jobs):
    manager, service = jobs
    presenting, presented = threading.Event(), threading.Event()

    def analyze_program(target, *, force, control):
        control.check_active()
        raise DomainError(ErrorCode.SESSION_CHANGED, "the target was reloaded", retryable=True)

    def present(kind, target, result, error):
        presenting.set()
        assert presented.wait(5)
        return result, error

    service.analyze_program = analyze_program
    manager.present = present
    receipt = manager.submit_analysis("default")
    assert presenting.wait(1)
    cancelled = manager.cancel(receipt["operation_id"])
    assert cancelled["operation_error"]["code"] == "OPERATION_CANCELLED"
    presented.set()
    manager._queue.join()
    # The worker's own outcome does not overwrite what the client was told.
    assert manager.get(operation_id=receipt["operation_id"])["operation_error"]["code"] == "OPERATION_CANCELLED"
    assert list(manager._released).count(receipt["operation_id"]) == 1


def test_an_oversized_result_drops_only_itself():
    manager = OperationManager(AnalysisService(), payload_limit_bytes=200)
    small = [manager.defer_call("apply_edits", "default", started_at="now") for _ in range(2)]
    for call in small:
        manager.finish_call(call["operation_id"], result={"ok": 1})
    big = manager.defer_call("apply_edits", "default", started_at="now")
    manager.finish_call(big["operation_id"], result={"blob": "x" * 1000})
    assert manager.get(operation_id=big["operation_id"])["result_discarded"] is True
    # Dropping the earlier results would not have made room for it.
    assert [manager.get(operation_id=call["operation_id"])["result"] for call in small] == [{"ok": 1}, {"ok": 1}]


def test_a_dropped_record_keeps_no_result_in_its_error():
    manager = OperationManager(AnalysisService(), payload_limit_bytes=200)
    call = manager.defer_call("batch_read", "default", started_at="now")
    # A batch_read that failed on every item reports its result as the error (structured_error).
    failed_items = {"items": [{"id": "1", "status": "error", "error": {"message": "x" * 500}}]}
    manager.finish_call(
        call["operation_id"],
        error={"message": "The call failed", "result": failed_items, "details": {"output_state": "absent"}},
    )
    record = manager.get(operation_id=call["operation_id"])
    assert record["result_discarded"] is True
    assert "result" not in record["operation_error"]
    assert record["operation_error"]["details"]["output_state"] == "absent"


def test_payload_bookkeeping_stays_bounded_behind_a_kept_import():
    service = AnalysisService()
    service.release.set()
    manager = OperationManager(service, history_limit=4)
    try:

        def import_program(target, binary_path, *, control, **options):
            control.check_active()
            control.begin()
            raise DomainError(ErrorCode.OPERATION_FAILED, "close failed", details={"partial_import": True})

        service.import_program = import_program
        failed = wait_terminal(manager, manager.submit_import("default", binary_path="/in/sample.bin"))
        # Its output may exist, so the record keeps the name and is never evicted.
        assert failed["operation_error"]["details"]["output_state"] == "created"
        for _ in range(50):
            call = manager.defer_call("apply_edits", "default", started_at="now")
            manager.finish_call(call["operation_id"], result={"ok": True})
        assert len(manager._records) <= 5
        assert set(manager._payload_order) <= set(manager._records)
    finally:
        manager.shutdown()
