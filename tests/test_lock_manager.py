from __future__ import annotations

import threading

import pytest

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure import LockManager


def test_lock_manager_acquire_target_and_project_lock():
    manager = LockManager()

    with manager.acquire(target="fw", project_key="/tmp/prj::sample", timeout=0.05):
        assert "fw" in manager._target_locks  # noqa: SLF001
        assert "/tmp/prj::sample" in manager._project_locks  # noqa: SLF001


def test_lock_manager_timeout_raises_domain_error():
    manager = LockManager()
    target_lock = manager._get_target_lock("fw")  # noqa: SLF001
    acquired = threading.Event()
    release = threading.Event()

    def _holder():
        target_lock.acquire()
        acquired.set()
        release.wait(timeout=1.0)
        target_lock.release()

    thread = threading.Thread(target=_holder)
    thread.start()
    acquired.wait(timeout=1.0)
    try:
        with pytest.raises(DomainError) as exc_info:
            with manager.acquire(target="fw", timeout=0.01):
                pass
    finally:
        release.set()
        thread.join(timeout=1.0)

    err = exc_info.value
    assert err.code == ErrorCode.LOCK_TIMEOUT
    assert err.retryable is True
    assert err.details == {"lock": "target", "timeout": 0.01}
