"""Locking primitives for target/project operations."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator

import fasteners

from ghidra_mcp.domain import DEFAULT_LOCK_TIMEOUT_SECONDS, DomainError, ErrorCode, LOCK_ORDER


class LockManager:
    """Fail-fast lock manager with fixed acquisition order."""

    def __init__(self) -> None:
        self._registry_lock = fasteners.ReaderWriterLock()
        self._target_locks: dict[str, threading.RLock] = {}
        self._project_locks: dict[str, threading.RLock] = {}

    def _get_target_lock(self, target: str) -> threading.RLock:
        lock = self._target_locks.get(target)
        if lock is None:
            lock = threading.RLock()
            self._target_locks[target] = lock
        return lock

    def _get_project_lock(self, project_key: str) -> threading.RLock:
        lock = self._project_locks.get(project_key)
        if lock is None:
            lock = threading.RLock()
            self._project_locks[project_key] = lock
        return lock

    @contextlib.contextmanager
    def acquire(
        self,
        *,
        target: str | None = None,
        project_key: str | None = None,
        timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        with self._registry_lock.write_lock():
            target_lock = self._get_target_lock(target) if target else None
            project_lock = self._get_project_lock(project_key) if project_key else None

        stack: list[threading.RLock] = []

        try:
            if target_lock is not None:
                self._acquire_lock(target_lock, timeout=timeout, lock_name="target", order=LOCK_ORDER)
                stack.append(target_lock)
            if project_lock is not None:
                self._acquire_lock(project_lock, timeout=timeout, lock_name="project", order=LOCK_ORDER)
                stack.append(project_lock)
            yield
        finally:
            while stack:
                stack.pop().release()

    def _acquire_lock(
        self,
        lock: threading.RLock,
        *,
        timeout: float,
        lock_name: str,
        order: tuple[str, ...],
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if lock.acquire(blocking=False):
                return
            if time.monotonic() >= deadline:
                raise DomainError(
                    code=ErrorCode.LOCK_TIMEOUT,
                    message=f"Failed to acquire {lock_name} lock",
                    hint=f"Lock acquisition order: {' -> '.join(order)}",
                    retryable=True,
                    details={"lock": lock_name, "timeout": timeout},
                )
            time.sleep(0.005)


__all__ = ["LockManager"]
