"""ScriptBarrier: readers and shutdown are bounded against a running script."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import fasteners
import pytest

from ghidra_mcp.application import locks
from ghidra_mcp.application.locks import ScriptBarrier
from ghidra_mcp.domain import DomainError, ErrorCode


def _hold_writer(barrier: ScriptBarrier):
    entered = threading.Event()
    release = threading.Event()

    def run():
        with barrier.write_lock():
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert entered.wait(5)
    return release, thread


def test_reader_times_out_while_a_script_holds_the_barrier():
    barrier = ScriptBarrier()
    release, thread = _hold_writer(barrier)
    try:
        with pytest.raises(DomainError) as excinfo, barrier.read_lock(timeout=0.05):
            pass
        assert excinfo.value.code is ErrorCode.LOCK_TIMEOUT
        assert excinfo.value.retryable is True
        details = excinfo.value.details
        assert details["lock"] == "script_barrier" and details["timeout"] == 0.05
        assert details["script_state"] == "running" and details["waited_seconds"] >= 0.05
        assert "a Ghidra script is running" in excinfo.value.message
    finally:
        release.set()
        thread.join(5)
    with barrier.read_lock(timeout=0.05):
        pass


def test_bounded_writer_times_out_behind_a_running_writer():
    barrier = ScriptBarrier()
    release, thread = _hold_writer(barrier)
    try:
        with pytest.raises(DomainError) as excinfo, barrier.write_lock(timeout=0.05):
            pass
        assert excinfo.value.code is ErrorCode.LOCK_TIMEOUT
    finally:
        release.set()
        thread.join(5)
    with barrier.write_lock(timeout=0.05):
        assert barrier.writer_pending is True
    assert barrier.writer_pending is False


def test_writer_may_reenter_as_reader_without_waiting_for_itself():
    barrier = ScriptBarrier()
    with barrier.write_lock(), barrier.read_lock(timeout=0.01), barrier.write_lock(timeout=0.01):
        pass


def test_readers_proceed_after_the_writer_leaves():
    barrier = ScriptBarrier()
    release, thread = _hold_writer(barrier)
    results = []

    def reader():
        with barrier.read_lock(timeout=5):
            results.append("read")

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    release.set()
    thread.join(5)
    reader_thread.join(5)
    assert results == ["read"]


def test_close_all_skips_instead_of_hanging_behind_a_script(monkeypatch, caplog):
    from ghidra_mcp.application import locks
    from ghidra_mcp.infrastructure.ghidra_adapter.runtime import target_lifecycle

    barrier = ScriptBarrier()
    monkeypatch.setattr(target_lifecycle, "SCRIPT_BARRIER", barrier)
    monkeypatch.setattr(locks, "get_lock_timeout_seconds", lambda: 0.05)
    lifecycle = object.__new__(target_lifecycle.RuntimeTargetLifecycle)
    lifecycle._store = SimpleNamespace(operation_lock=fasteners.ReaderWriterLock())
    closed = []
    lifecycle._close_all_locked = lambda: closed.append(True)

    release, thread = _hold_writer(barrier)
    try:
        with caplog.at_level("ERROR"):
            lifecycle.close_all()
        assert closed == []
        assert "close_all skipped" in caplog.text
    finally:
        release.set()
        thread.join(5)
    lifecycle.close_all()
    assert closed == [True]


@pytest.mark.parametrize("entrypoint", ["script", "sync"])
@pytest.mark.parametrize("holder", ["reader", "writer"])
def test_exclusive_runtime_operations_obey_lock_policy(monkeypatch, entrypoint, holder):
    from ghidra_mcp.application import locks
    from ghidra_mcp.infrastructure.ghidra_adapter.runtime import core_execution, sync_locking

    barrier = ScriptBarrier()
    monkeypatch.setattr(core_execution, "SCRIPT_BARRIER", barrier)
    monkeypatch.setattr(sync_locking, "SCRIPT_BARRIER", barrier)
    monkeypatch.setattr(locks, "get_lock_timeout_seconds", lambda: 0.05)
    monkeypatch.setattr(locks, "get_script_queue_timeout_seconds", lambda: 0.05)
    store = SimpleNamespace(operation_lock=fasteners.ReaderWriterLock())
    core = core_execution.RuntimeCoreExecution(
        store=store, checkout_required_commands=set(), normalize_result=lambda result: result
    )
    sync = sync_locking.SyncLockingMixin()
    sync._store = store
    done = threading.Event()
    errors = []

    def call():
        try:
            if entrypoint == "script":
                core.call("run_script", target="queued", exclusive=True)
            else:
                with sync._target_operation("queued", exclusive=True):
                    pytest.fail("a timed-out operation must never reach the protected section")
        except Exception as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=call, daemon=True)
    held_lock = barrier.read_lock() if holder == "reader" else barrier.write_lock()
    try:
        with held_lock:
            thread.start()
            assert done.wait(1), "exclusive runtime operation ignored the configured lock timeout"
            assert len(errors) == 1 and isinstance(errors[0], DomainError)
            assert errors[0].code is ErrorCode.LOCK_TIMEOUT
            assert errors[0].retryable is True
            details = errors[0].details
            assert details["lock"] == "script_barrier" and details["timeout"] == 0.05
            assert details["script_state"] == ("running" if holder == "writer" else "queued")
            assert details["active_readers"] == (1 if holder == "reader" else 0)
    finally:
        thread.join(5)
    assert not thread.is_alive()
    # A timed-out writer must also leave the barrier usable by the next operation.
    with barrier.read_lock(timeout=0):
        pass
    with barrier.write_lock(timeout=0):
        pass


def test_bounded_writer_times_out_behind_a_reader_and_removes_its_ticket():
    barrier = ScriptBarrier()
    done = threading.Event()
    errors = []

    def writer():
        try:
            with barrier.write_lock(timeout=0.05):
                pass
        except DomainError as exc:
            errors.append(exc)
        finally:
            done.set()

    thread = threading.Thread(target=writer, daemon=True)
    try:
        with barrier.read_lock():
            thread.start()
            assert done.wait(2), "writer ignored its timeout while a reader remained active"
            assert len(errors) == 1 and errors[0].code is ErrorCode.LOCK_TIMEOUT
            assert barrier.writer_pending is False
    finally:
        thread.join(5)
    with barrier.write_lock(timeout=0):
        pass


def test_queued_writer_delays_new_readers_for_the_grace_but_not_reader_reentrancy(monkeypatch):
    """A queued writer holds new readers for READER_GRACE_SECONDS; owners re-enter at once and nobody is rejected."""

    barrier = ScriptBarrier()
    monkeypatch.setattr(locks, "READER_GRACE_SECONDS", 0.3)
    waiting = threading.Event()
    wait_until = barrier._wait_until
    outcomes = []

    def observe_wait(predicate, timeout, *, role, **kwargs):
        if role == "writer":
            waiting.set()
        return wait_until(predicate, timeout, role=role, **kwargs)

    monkeypatch.setattr(barrier, "_wait_until", observe_wait)

    def new_reader():
        started = time.monotonic()
        try:
            with barrier.read_lock(timeout=5):
                outcomes.append(("entered", time.monotonic() - started, written.is_set()))
        except DomainError as exc:
            outcomes.append(("error", exc))

    written = threading.Event()

    def writer():
        with barrier.write_lock():
            written.set()

    thread = threading.Thread(target=writer, daemon=True)
    reader = threading.Thread(target=new_reader, daemon=True)
    try:
        with barrier.read_lock():
            thread.start()
            assert waiting.wait(5)
            started = time.monotonic()
            with barrier.read_lock(timeout=0):  # re-entrancy never waits for the queued writer
                pass
            assert time.monotonic() - started < 0.2
            reader.start()
            reader.join(2)
            assert not reader.is_alive()
            assert not written.is_set()
    finally:
        thread.join(5)
        if reader.ident is not None:
            reader.join(5)
    assert written.is_set()
    assert len(outcomes) == 1 and outcomes[0][0] == "entered"
    _, waited, writer_had_run = outcomes[0]
    assert 0.25 <= waited < 2  # deferred for the grace, then passed the still-queued writer
    assert writer_had_run is False


def test_writers_run_fifo_before_new_readers(monkeypatch):
    barrier = ScriptBarrier()
    wait_until = barrier._wait_until
    waiting = {name: threading.Event() for name in ("writer-1", "writer-2", "reader")}
    order = []
    errors = []

    def observe_wait(predicate, timeout, *, role, **kwargs):
        event = waiting.get(threading.current_thread().name)
        if event is not None:
            event.set()
        return wait_until(predicate, timeout, role=role, **kwargs)

    monkeypatch.setattr(barrier, "_wait_until", observe_wait)

    def worker(name):
        try:
            lock = barrier.read_lock(timeout=5) if name == "reader" else barrier.write_lock(timeout=5)
            with lock:
                order.append(name)
        except Exception as exc:
            errors.append(exc)

    threads = []
    try:
        with barrier.read_lock():
            for name in waiting:
                thread = threading.Thread(target=worker, args=(name,), name=name, daemon=True)
                threads.append(thread)
                thread.start()
                assert waiting[name].wait(5)
    finally:
        for thread in threads:
            thread.join(5)
    assert not errors
    assert order == ["writer-1", "writer-2", "reader"]


def test_new_readers_pass_a_queued_writer_after_the_grace_period(monkeypatch):
    """A long read on one target must not turn every other read into LOCK_TIMEOUT."""

    barrier = ScriptBarrier()
    monkeypatch.setattr(locks, "READER_GRACE_SECONDS", 0.05)
    writer_waiting = threading.Event()
    written = threading.Event()
    wait_until = barrier._wait_until

    def observe_wait(predicate, timeout, *, role, **kwargs):
        if role == "writer":
            writer_waiting.set()
        return wait_until(predicate, timeout, role=role, **kwargs)

    monkeypatch.setattr(barrier, "_wait_until", observe_wait)

    def writer():
        with barrier.write_lock(timeout=5):
            written.set()

    thread = threading.Thread(target=writer, daemon=True)
    try:
        with barrier.read_lock():  # the long-running read the writer is queued behind
            thread.start()
            assert writer_waiting.wait(5)
            started = time.monotonic()
            with barrier.read_lock(timeout=5):  # a new reader: waits out the grace, then proceeds
                assert time.monotonic() - started < 2
                assert barrier.writer_pending is True
                assert not written.is_set()
    finally:
        thread.join(5)
    assert written.is_set()
    # A *running* writer still holds readers off for their whole timeout.
    release, holder = _hold_writer(barrier)
    try:
        with pytest.raises(DomainError) as excinfo, barrier.read_lock(timeout=0.2):
            pass
        assert excinfo.value.code is ErrorCode.LOCK_TIMEOUT
    finally:
        release.set()
        holder.join(5)


def test_generations_let_the_writer_in_once_the_long_read_ends(monkeypatch):
    """Elders gone -> new readers are held again -> the readers admitted meanwhile drain -> writer acquires."""

    barrier = ScriptBarrier()
    monkeypatch.setattr(locks, "READER_GRACE_SECONDS", 0.2)
    writer_waiting = threading.Event()
    written = threading.Event()
    wait_until = barrier._wait_until

    def observe_wait(predicate, timeout, *, role, **kwargs):
        if role == "writer":
            writer_waiting.set()
        return wait_until(predicate, timeout, role=role, **kwargs)

    monkeypatch.setattr(barrier, "_wait_until", observe_wait)

    def writer():
        with barrier.write_lock(timeout=10):
            written.set()

    elder_release = threading.Event()
    elder_inside = threading.Event()

    def elder():
        with barrier.read_lock():
            elder_inside.set()
            elder_release.wait(10)

    passer_release = threading.Event()
    passer_inside = threading.Event()

    def passer():  # admitted past the queued writer once the elder proves long
        with barrier.read_lock(timeout=10):
            passer_inside.set()
            passer_release.wait(10)

    late = {}

    def late_reader():  # arrives after the elder left: held for one grace, then enters or the writer ran
        started = time.monotonic()
        with barrier.read_lock(timeout=10):
            late["waited"] = time.monotonic() - started
            late["writer_ran"] = written.is_set()

    threads = [threading.Thread(target=fn, daemon=True) for fn in (elder, writer, passer, late_reader)]
    try:
        threads[0].start()
        assert elder_inside.wait(5)
        threads[1].start()
        assert writer_waiting.wait(5)
        threads[2].start()
        assert passer_inside.wait(5)  # passed the queued writer after the grace
        assert not written.is_set()
        elder_release.set()  # elders gone: the passer becomes the next generation
        threads[0].join(5)
        threads[3].start()
        time.sleep(0.1)  # within the new grace: the late reader is held again...
        assert "waited" not in late
        assert not written.is_set()  # ...and the writer still waits for the passer
        passer_release.set()  # generation drains -> writer acquires -> late reader follows
        assert written.wait(5)
        for thread in threads[1:]:
            thread.join(5)
    finally:
        elder_release.set()
        passer_release.set()
        for thread in threads:
            thread.join(5)
    assert late["writer_ran"] is True
    assert late["waited"] < 2


def test_writer_is_not_starved_by_continuous_short_reads(monkeypatch):
    barrier = ScriptBarrier()
    monkeypatch.setattr(locks, "READER_GRACE_SECONDS", 0.1)
    stop = threading.Event()
    written = threading.Event()
    reads = []

    def reader():
        while not stop.is_set():
            with barrier.read_lock(timeout=5):
                reads.append(1)
                time.sleep(0.005)

    readers = [threading.Thread(target=reader, daemon=True) for _ in range(6)]
    for thread in readers:
        thread.start()
    time.sleep(0.1)
    started = time.monotonic()
    try:
        with barrier.write_lock(timeout=5):
            written.set()
        acquired_after = time.monotonic() - started
    finally:
        stop.set()
        for thread in readers:
            thread.join(5)
    assert written.is_set()
    assert acquired_after < 3
    assert len(reads) > 20  # the readers really were hammering the barrier


def test_run_script_writer_uses_the_script_queue_budget(monkeypatch):
    barrier = ScriptBarrier()
    monkeypatch.setattr(locks, "get_lock_timeout_seconds", lambda: 5.0)
    monkeypatch.setattr(locks, "get_script_queue_timeout_seconds", lambda: 0.05)
    inside = threading.Event()
    release = threading.Event()

    def reader():
        with barrier.read_lock():
            inside.set()
            release.wait(5)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    assert inside.wait(5)
    try:
        started = time.monotonic()
        with pytest.raises(DomainError) as excinfo, barrier.write_lock(timeout=locks.USE_SCRIPT_QUEUE_TIMEOUT):
            pass
        assert time.monotonic() - started < 2
        assert excinfo.value.details["timeout"] == 0.05
        assert excinfo.value.details["active_readers"] == 1
        assert "still reading" in excinfo.value.message
    finally:
        release.set()
        thread.join(5)


def test_reader_to_writer_upgrade_fails_without_leaking_a_ticket():
    barrier = ScriptBarrier()
    with barrier.read_lock():
        with pytest.raises(RuntimeError, match="Cannot upgrade"), barrier.write_lock(timeout=0):
            pass
        assert not barrier.writer_pending
    with barrier.write_lock(timeout=0):
        pass


@pytest.mark.parametrize("kind", ["read", "write"])
def test_body_exception_releases_the_barrier(kind):
    barrier = ScriptBarrier()
    context = barrier.read_lock() if kind == "read" else barrier.write_lock()
    with pytest.raises(ValueError, match="body failed"), context:
        raise ValueError("body failed")
    acquired = []

    def writer():
        with barrier.write_lock(timeout=0):
            acquired.append(True)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    thread.join(5)
    assert acquired == [True]


def test_interrupted_writer_does_not_leave_a_pending_ticket(monkeypatch):
    barrier = ScriptBarrier()
    wait_until = barrier._wait_until

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(barrier, "_wait_until", interrupt)
    with pytest.raises(KeyboardInterrupt), barrier.write_lock(timeout=0):
        pass
    assert not barrier.writer_pending
    monkeypatch.setattr(barrier, "_wait_until", wait_until)
    with barrier.read_lock(timeout=0):
        pass


def test_concurrent_readers_never_overlap_a_writer():
    barrier = ScriptBarrier()
    start = threading.Barrier(8)
    guard = threading.Lock()
    active = {"read": 0, "write": 0}
    errors = []

    def worker(index):
        try:
            start.wait(5)
            for iteration in range(20):
                kind = "write" if (iteration + index) % 3 == 0 else "read"
                context = barrier.write_lock(timeout=5) if kind == "write" else barrier.read_lock(timeout=5)
                with context:
                    with guard:
                        assert active["write"] == 0
                        if kind == "write":
                            assert active["read"] == 0
                        active[kind] += 1
                    time.sleep(0)  # Give contenders a chance to run while ownership is held.
                    with guard:
                        active[kind] -= 1
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not any(thread.is_alive() for thread in threads)
    assert not errors
    assert active == {"read": 0, "write": 0}
