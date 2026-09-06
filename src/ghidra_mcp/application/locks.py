"""Shared locking primitives for application and runtime operations."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Hashable, Iterable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

from ghidra_mcp.domain import LOCK_ORDER, DomainError, ErrorCode, get_lock_timeout_seconds


class _UsePolicy:
    """Sentinel: resolve the wait from the runtime lock policy at call time."""


USE_POLICY_TIMEOUT = _UsePolicy()


@contextlib.contextmanager
def acquire_ordered_locks(
    locks: Iterable[tuple[str, Any]],
    *,
    timeout: float | _UsePolicy | None = USE_POLICY_TIMEOUT,
    order: tuple[str, ...] = LOCK_ORDER,
    message_prefix: str = "",
) -> Iterator[None]:
    """Acquire locks in caller-supplied order using one shared deadline.

    ``timeout=None`` waits forever; the default reads the configurable policy
    (``configure_lock_timeout_seconds``) when the lock is requested.
    """

    if isinstance(timeout, _UsePolicy):
        timeout = get_lock_timeout_seconds()
    deadline = None if timeout is None else time.monotonic() + timeout
    acquired: list[Any] = []
    try:
        for lock_name, lock in locks:
            if deadline is None:
                acquired_lock = lock.acquire()
            else:
                remaining = max(0.0, deadline - time.monotonic())
                acquired_lock = lock.acquire(timeout=remaining)
            if not acquired_lock:
                raise DomainError(
                    code=ErrorCode.LOCK_TIMEOUT,
                    message=f"Failed to acquire {message_prefix}{lock_name} lock",
                    hint=f"Lock acquisition order: {' -> '.join(order)}",
                    retryable=True,
                    details={"lock": lock_name, "timeout": timeout},
                )
            acquired.append(lock)
        yield
    finally:
        while acquired:
            acquired.pop().release()


@dataclass(slots=True)
class _KeyedLockEntry:
    lock: threading.RLock
    users: int = 0


class KeyedLockPool:
    """Provide per-key locks and evict them after the last user exits."""

    def __init__(self) -> None:
        self._entries: dict[Hashable, _KeyedLockEntry] = {}
        self._state_lock = threading.Lock()

    @contextlib.contextmanager
    def reserve(self, key: Hashable) -> Iterator[threading.RLock]:
        with self._state_lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _KeyedLockEntry(lock=threading.RLock())
                self._entries[key] = entry
            entry.users += 1
        try:
            yield entry.lock
        finally:
            with self._state_lock:
                entry.users -= 1
                if entry.users == 0 and self._entries.get(key) is entry:
                    self._entries.pop(key, None)

    @contextlib.contextmanager
    def acquire(
        self,
        key: Hashable,
        *,
        timeout: float | None = None,
        lock_name: str = "keyed",
    ) -> Iterator[None]:
        with self.reserve(key) as lock:
            with acquire_ordered_locks(
                [(lock_name, lock)],
                timeout=timeout,
                order=(lock_name,),
            ):
                yield

    @property
    def active_count(self) -> int:
        with self._state_lock:
            return len(self._entries)


class LockManager:
    """Fail-fast target/project lock manager with fixed acquisition order."""

    def __init__(self) -> None:
        self._target_pool = KeyedLockPool()
        self._project_pool = KeyedLockPool()

    @contextlib.contextmanager
    def acquire(
        self,
        *,
        target: str | None = None,
        project_key: str | None = None,
        timeout: float | _UsePolicy | None = USE_POLICY_TIMEOUT,
    ) -> Iterator[None]:
        locks: list[tuple[str, threading.RLock]] = []
        with ExitStack() as reservations:
            if target is not None:
                lock = reservations.enter_context(self._target_pool.reserve(target))
                locks.append(("target", lock))
            if project_key is not None:
                lock = reservations.enter_context(self._project_pool.reserve(project_key))
                locks.append(("project", lock))
            with acquire_ordered_locks(locks, timeout=timeout):
                yield

    @property
    def cached_lock_counts(self) -> dict[str, int]:
        return {
            "target": self._target_pool.active_count,
            "project": self._project_pool.active_count,
        }


__all__ = ["USE_POLICY_TIMEOUT", "KeyedLockPool", "LockManager", "acquire_ordered_locks"]
