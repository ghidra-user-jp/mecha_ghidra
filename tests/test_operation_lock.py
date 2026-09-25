from __future__ import annotations

import threading
import time

import pytest

from ghidra_mcp.application.locks import OperationLock
from ghidra_mcp.domain import DomainError, ErrorCode


def _hold_read(lock):
    held, release = threading.Event(), threading.Event()

    def reader():
        with lock.read_lock():
            held.set()
            assert release.wait(5)

    thread = threading.Thread(target=reader)
    thread.start()
    assert held.wait(1)
    return release, thread


def _bounded_writer(lock, timeout, outcome):
    def writer():
        started = time.monotonic()
        try:
            with lock.bounded_write_lock(timeout, purpose="create_project"):
                outcome["acquired_after"] = time.monotonic() - started
        except DomainError as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=writer)
    thread.start()
    return thread


def test_waiting_bounded_writer_never_holds_new_readers_off():
    lock = OperationLock()
    release, reader = _hold_read(lock)
    outcome = {}
    writer = _bounded_writer(lock, 2, outcome)
    try:
        time.sleep(0.05)
        started = time.monotonic()
        # fasteners' write_lock() would queue here and block this reader.
        with lock.read_lock():
            pass
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        reader.join(1)
    writer.join(2)
    assert "error" not in outcome and outcome["acquired_after"] < 1.5


def test_bounded_writer_gives_up_with_a_retryable_lock_timeout():
    lock = OperationLock()
    release, reader = _hold_read(lock)
    outcome = {}
    try:
        _bounded_writer(lock, 0.1, outcome).join(2)
    finally:
        release.set()
        reader.join(1)
    error = outcome["error"]
    assert error.code == ErrorCode.LOCK_TIMEOUT and error.retryable
    assert error.details == {"lock": "runtime", "timeout": 0.1}
    assert "create_project" in error.message
    # Nothing is left behind: an ordinary writer gets the lock afterwards.
    with lock.write_lock():
        assert lock.is_writer()


def test_bounded_writer_excludes_readers_while_it_holds_the_lock():
    lock = OperationLock()
    entered, leave = threading.Event(), threading.Event()

    def writer():
        with lock.bounded_write_lock(1, purpose="create_project"):
            entered.set()
            assert leave.wait(5)

    thread = threading.Thread(target=writer)
    thread.start()
    assert entered.wait(1)
    read = threading.Event()

    def reader():
        with lock.read_lock():
            read.set()

    other = threading.Thread(target=reader)
    other.start()
    assert not read.wait(0.1)
    leave.set()
    thread.join(1)
    assert read.wait(1)
    other.join(1)


def test_bounded_writer_is_reentrant_and_refuses_reader_escalation():
    lock = OperationLock()
    with lock.write_lock(), lock.bounded_write_lock(0, purpose="create_project"):
        assert lock.is_writer()
    with lock.bounded_write_lock(0, purpose="create_project"), lock.bounded_write_lock(0, purpose="nested"):
        assert lock.is_writer()
    with lock.read_lock(), pytest.raises(RuntimeError, match="escalation"):
        with lock.bounded_write_lock(0, purpose="create_project"):
            pass
    assert not lock.is_writer() and not lock.is_reader()
