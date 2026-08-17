from __future__ import annotations

import threading

import pytest

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure import LockManager


def test_lock_manager_acquire_target_and_project_lock():
    manager = LockManager()

    with manager.acquire(target="fw", project_key="/tmp/prj::sample", timeout=0.05):
        assert manager.cached_lock_counts == {"target": 1, "project": 1}

    assert manager.cached_lock_counts == {"target": 0, "project": 0}


def test_lock_manager_timeout_raises_domain_error():
    manager = LockManager()
    acquired = threading.Event()
    release = threading.Event()

    def _holder():
        with manager.acquire(target="fw", timeout=0.5):
            acquired.set()
            release.wait(timeout=1.0)

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


def test_lock_manager_allows_different_targets_to_overlap():
    manager = LockManager()
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def _holder():
        with manager.acquire(target="fw1", timeout=0.5):
            first_entered.set()
            release_first.wait(timeout=1.0)

    thread = threading.Thread(target=_holder)
    thread.start()
    assert first_entered.wait(timeout=1.0)

    try:
        with manager.acquire(target="fw2", timeout=0.05):
            second_entered.set()
        assert second_entered.is_set()
    finally:
        release_first.set()
        thread.join(timeout=1.0)


def test_lock_manager_does_not_cache_completed_invalid_target_names():
    manager = LockManager()

    for index in range(1000):
        with manager.acquire(target=f"missing-{index}", timeout=0.05):
            pass

    assert manager.cached_lock_counts == {"target": 0, "project": 0}
