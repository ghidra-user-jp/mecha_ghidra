"""Lock-holder diagnostics use acquired locks, including calls recorded after they started."""

import threading
from uuid import uuid4

import pytest

from ghidra_mcp.application.locks import CallLocks, acquire_ordered_locks
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.domain import DomainError


class Targets:
    def project_key(self, target):
        return "/project::other" if target == "elsewhere" else "/project::test"


@pytest.mark.parametrize("claimed", [False, True], ids=["deferred", "request_id"])
@pytest.mark.parametrize("lock_name", ["target", "project"])
def test_only_acquired_locks_name_the_call_and_never_itself(claimed, lock_name):
    manager = OperationManager(Targets())
    observed = CallLocks()
    entered, release = threading.Event(), threading.Event()
    own_holder = []
    if claimed:
        record, _ = manager.claim_call("apply_edits", "t", request_id=str(uuid4()), fingerprint="f")
        manager.bind_call_locks(record["operation_id"], observed)
        assert manager.lock_holder("t") is None

    def run():
        with manager.tracked_call(call_locks=observed):
            with acquire_ordered_locks([(lock_name, threading.RLock())]):
                entered.set()
                assert release.wait(5)
                own_holder.append(manager.lock_holder("t", any_target=True))

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(2)
        if not claimed:
            record = manager.defer_call("decompile_function", "t", started_at="now", call_locks=observed)
        operation_id = record["operation_id"]
        assert manager.lock_holder("t") == operation_id
        assert manager.lock_holder("same_project") == (operation_id if lock_name == "project" else None)
        assert manager.lock_holder("elsewhere") is None
        assert manager.lock_holder("elsewhere", any_target=True) == operation_id
    finally:
        release.set()
        worker.join(5)
        manager.shutdown()
    assert not worker.is_alive()
    assert own_holder == [None]
    # No holder is reported even in the gap before the record is finalized.
    assert manager.lock_holder("t") is None
    manager.finish_call(operation_id)


def test_nested_acquisition_and_failed_wait_keep_only_locks_still_held():
    observed = CallLocks()
    lock = threading.RLock()
    busy = threading.Lock()
    busy.acquire()
    entered, release = threading.Event(), threading.Event()

    def run():
        with observed.observe(), acquire_ordered_locks([("target", lock)]):
            with acquire_ordered_locks([("target", lock)]):
                pass
            with pytest.raises(DomainError):
                with acquire_ordered_locks([("target", lock), ("project", busy)], timeout=0):
                    pytest.fail("the project lock is held by another thread")
            entered.set()
            assert release.wait(5)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(2)
        assert observed.held_by_other_thread() == {"target"}
    finally:
        release.set()
        worker.join(5)
        busy.release()
    assert not worker.is_alive()
    assert not observed.held_by_other_thread()
