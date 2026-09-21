"""Shared locking primitives for application and runtime operations."""

from __future__ import annotations

import contextlib
import threading
import time
from collections import deque
from collections.abc import Callable, Hashable, Iterable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any

from ghidra_mcp.domain import (
    LOCK_ORDER,
    DomainError,
    ErrorCode,
    get_lock_timeout_seconds,
    get_script_queue_timeout_seconds,
)


class _UsePolicy:
    """Sentinel: resolve the wait from the runtime lock policy at call time."""


USE_POLICY_TIMEOUT = _UsePolicy()
# Sentinel: the run_script queue budget (``--script-queue-timeout-seconds``), used by the
# writer that waits for in-flight reads before a script may start.
USE_SCRIPT_QUEUE_TIMEOUT = _UsePolicy()
# How long a queued writer may hold new readers off while a reader that predates it
# (an "elder") is still running.  See ScriptBarrier.
READER_GRACE_SECONDS = 1.0


def _resolve_timeout(timeout: float | _UsePolicy | None) -> float | None:
    if timeout is USE_SCRIPT_QUEUE_TIMEOUT:
        return get_script_queue_timeout_seconds()
    if isinstance(timeout, _UsePolicy):
        return get_lock_timeout_seconds()
    return timeout


class _WriterTicket:
    """A queued writer's place in line plus the readers it is currently waiting out."""

    __slots__ = ("elders", "since")

    def __init__(self, readers: Iterable[threading.Thread], now: float) -> None:
        self.elders: set[threading.Thread] = set(readers)
        self.since = now


class ScriptBarrier:
    """Process-wide reader/writer barrier around Ghidra script execution.

    Scripts mutate state that no per-RuntimeState lock covers (sys.modules,
    the OSGi bundle host, the Jython runtime), so every runtime instance in
    the process shares one barrier: ordinary commands hold it as readers,
    script execution and provider initialization as the writer.

    A script may run for up to an hour, or forever when it ignores its
    monitor, so readers do not wait for it unboundedly: while a writer is
    active, ``read_lock`` waits at most ``timeout`` seconds (the runtime lock
    policy by default) and then raises a retryable ``LOCK_TIMEOUT``.
    ``write_lock(timeout=...)`` bounds a writer the same way (``run_script``
    uses the separate script queue budget).  Acquisition and ownership changes
    use one condition: no unbounded lock acquisition follows the timed wait.
    Waiting writers run in FIFO order; existing owners re-enter without
    waiting for themselves.

    Admission of new readers while a writer is *queued* is generational.  The
    writer records the readers present when it queued (its elders).  New
    readers are held off, so ordinary short reads drain and the writer slips
    in.  If an elder is still running after ``READER_GRACE_SECONDS`` it is a
    long read (analysis, a big decompile): new readers then pass the queued
    writer instead of failing for that read's whole duration.  Once every
    elder has left, the readers admitted meanwhile become the next elders and
    new readers are held off again for one grace period, so a drain happens
    and the writer acquires.  A reader therefore never waits more than one
    grace for a queued writer, and the writer is delayed by chains of long
    reads, never by the volume of short ones.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._readers: dict[threading.Thread, int] = {}
        self._writer: threading.Thread | None = None
        self._writer_depth = 0
        self._pending_writers: deque[_WriterTicket] = deque()

    @property
    def writer_pending(self) -> bool:
        with self._condition:
            return self._writer is not None or bool(self._pending_writers)

    # ---- diagnostics ------------------------------------------------------

    def _script_state_locked(self) -> str:
        if self._writer is not None:
            return "running"
        return "queued" if self._pending_writers else "idle"

    def _timeout_error(self, *, role: str, timeout: float | None, waited: float) -> DomainError:
        state = self._script_state_locked()
        details: dict[str, Any] = {
            "lock": "script_barrier",
            "timeout": timeout,
            "waited_seconds": round(waited, 3),
            "script_state": state,
            "active_readers": len(self._readers),
        }
        if role == "writer":
            reason = f"{len(self._readers)} operation(s) are still reading the program"
            if state == "running":
                reason = "another Ghidra script is still running"
            hint = "Retry once the running operations finish; raise --script-queue-timeout-seconds to wait longer"
        else:
            reason = "a Ghidra script is running" if state == "running" else "a Ghidra script is queued to run"
            hint = "Retry after the script completes; long scripts should check monitor.checkCancelled()"
            if state == "queued":
                details["retry_after_seconds"] = READER_GRACE_SECONDS
        return DomainError(
            code=ErrorCode.LOCK_TIMEOUT,
            message=f"Failed to acquire the script barrier as {role}: {reason} (waited {waited:.1f}s)",
            hint=hint,
            retryable=True,
            details=details,
        )

    # ---- waiting ------------------------------------------------------------

    def _wait_until(
        self,
        predicate: Callable[[], bool],
        timeout: float | _UsePolicy | None,
        *,
        role: str,
        strict: bool = True,
        reported_timeout: float | None = None,
        waited: float = 0.0,
    ) -> bool:
        """Wait with the condition held; the caller records ownership before releasing it.

        Returns True when ``predicate`` held before ``timeout``; with
        ``strict=False`` a timeout returns False instead of raising.  A caller
        that waits in stages passes the bound it advertised as
        ``reported_timeout`` and the time already spent as ``waited``.
        """
        timeout = _resolve_timeout(timeout)
        if self._condition.wait_for(predicate, timeout=timeout):
            return True
        if not strict:
            return False
        raise self._timeout_error(
            role=role,
            timeout=timeout if reported_timeout is None else reported_timeout,
            waited=waited + (timeout or 0.0),
        )

    def _new_reader_may_pass_locked(self, now: float) -> bool:
        """Whether a reader that is not an owner may enter past the queued head writer."""
        head = self._pending_writers[0]
        if not (head.elders & self._readers.keys()):
            if self._readers:
                # The readers the writer queued behind are gone; the ones admitted
                # meanwhile form the next generation and get one grace to drain.
                head.elders = set(self._readers)
                head.since = now
            return False
        return now - head.since > READER_GRACE_SECONDS

    def _reader_may_enter_locked(self, current: threading.Thread, now: float) -> bool:
        if self._writer is current:
            return True
        if self._writer is not None:
            return False
        if current in self._readers or not self._pending_writers:
            return True
        return self._new_reader_may_pass_locked(now)

    @contextlib.contextmanager
    def read_lock(self, timeout: float | _UsePolicy | None = USE_POLICY_TIMEOUT) -> Iterator[None]:
        current = threading.current_thread()
        timeout = _resolve_timeout(timeout)
        with self._condition:
            started = time.monotonic()
            deadline = None if timeout is None else started + timeout
            while True:
                now = time.monotonic()
                if self._reader_may_enter_locked(current, now):
                    break
                if deadline is not None and now >= deadline:
                    raise self._timeout_error(role="reader", timeout=timeout, waited=now - started)
                # Wake at the deadline or when the head writer's grace ends,
                # whichever comes first; ownership changes notify explicitly.
                wait = None if deadline is None else deadline - now
                if self._writer is None and self._pending_writers:
                    gate_check = self._pending_writers[0].since + READER_GRACE_SECONDS - now
                    wait = gate_check if wait is None else min(wait, gate_check)
                self._wait_until(
                    lambda: self._reader_may_enter_locked(current, time.monotonic()),
                    None if wait is None else max(0.0, wait),
                    role="reader",
                    strict=False,
                )
            self._readers[current] = self._readers.get(current, 0) + 1
        try:
            yield
        finally:
            with self._condition:
                self._readers[current] -= 1
                if self._readers[current] == 0:
                    del self._readers[current]
                self._condition.notify_all()

    @contextlib.contextmanager
    def write_lock(self, timeout: float | _UsePolicy | None = None) -> Iterator[None]:
        """Exclusive section.  ``timeout=None`` (the default) queues behind a running writer."""

        current = threading.current_thread()
        timeout = _resolve_timeout(timeout)
        with self._condition:
            if self._writer is current:
                self._writer_depth += 1
            else:
                if current in self._readers:
                    raise RuntimeError("Cannot upgrade a script barrier reader to a writer")
                ticket = _WriterTicket(self._readers, time.monotonic())
                self._pending_writers.append(ticket)
                try:
                    self._wait_until(
                        lambda: self._writer is None and not self._readers and self._pending_writers[0] is ticket,
                        timeout,
                        role="writer",
                    )
                    self._writer = current
                    self._writer_depth = 1
                finally:
                    # Timeouts and interruptions must not strand readers or
                    # later writers behind a ticket that can never acquire.
                    self._pending_writers.remove(ticket)
                    self._condition.notify_all()
        try:
            yield
        finally:
            with self._condition:
                self._writer_depth -= 1
                if self._writer_depth == 0:
                    self._writer = None
                self._condition.notify_all()


SCRIPT_BARRIER = ScriptBarrier()


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


__all__ = [
    "READER_GRACE_SECONDS",
    "SCRIPT_BARRIER",
    "USE_POLICY_TIMEOUT",
    "USE_SCRIPT_QUEUE_TIMEOUT",
    "KeyedLockPool",
    "LockManager",
    "ScriptBarrier",
    "acquire_ordered_locks",
]
