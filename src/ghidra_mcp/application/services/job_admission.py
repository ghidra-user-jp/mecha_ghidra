"""Coordinate a job's admission with the deadline of the request waiting for it."""

from __future__ import annotations

import contextlib
import contextvars
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

from ghidra_mcp.domain import DomainError, ErrorCode

_T = TypeVar("_T")
_CURRENT: contextvars.ContextVar[JobAdmission | None] = contextvars.ContextVar("job_admission", default=None)


class JobAdmission:
    """An expired request cannot admit a job after telling the client nothing ran.

    The worker may still be checking a slow filesystem. Only committing the
    admission and expiring the request share a lock; those checks never do.
    A receipt committed first is returned even if the worker has not returned.
    """

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self._lock = threading.Lock()
        self._expired = False
        self._started = False
        self._receipt: dict[str, Any] | None = None

    @staticmethod
    def timeout_error() -> DomainError:
        return DomainError(
            code=ErrorCode.LOCK_TIMEOUT,
            message="Job admission did not finish before the response deadline; nothing was accepted",
            hint="Retry the request; this attempt will not start a job later",
            retryable=True,
            details={"lock": "admission", "output_state": "absent"},
        )

    def _check(self) -> None:
        if self._expired or time.monotonic() >= self.deadline:
            raise self.timeout_error()

    def run(self, function: Callable[[], _T]) -> _T:
        with self._lock:
            self._check()
            self._started = True
        token = _CURRENT.set(self)
        try:
            return function()
        finally:
            _CURRENT.reset(token)

    def expire(self) -> tuple[bool, dict[str, Any] | None]:
        with self._lock:
            self._expired = True
            return self._started, self._receipt

    def _accept(self, receipt: dict[str, Any]) -> dict[str, Any]:
        self._receipt = receipt
        return receipt

    @contextlib.contextmanager
    def commit(self) -> Iterator[Callable[[dict[str, Any]], dict[str, Any]]]:
        with self._lock:
            self._check()
            yield self._accept


@contextlib.contextmanager
def admission_commit() -> Iterator[Callable[[dict[str, Any]], dict[str, Any]]]:
    """Guard the manager's in-memory admission and capture its receipt, if this request has a deadline."""
    admission = _CURRENT.get()
    if admission is None:
        yield lambda receipt: receipt
    else:
        with admission.commit() as accept:
            yield accept
