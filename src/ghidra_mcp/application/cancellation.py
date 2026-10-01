"""Let the request that started a tool call stop it.

A read runs on a thread of its own while its request waits for it, so cancelling the request cannot interrupt the
read: the Ghidra work goes on and holds its locks.  ``DeferredCalls`` gives such a read a ``CallCancellation`` and
cancels it when the request is cancelled; the runtime that runs the read registers the cancel of the call's Ghidra
monitor with it.  Only a read gets one: a write that has started always finishes, and a job or a call that was
deferred is stopped by ``cancel_operation`` alone.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Callable, Iterator

logger = logging.getLogger(__name__)

_CURRENT = threading.local()


class CallCancellation:
    """The cancellation of one tool call: ``cancel()`` runs the hooks the running call registered."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._hooks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        """Cancel the call: every registered hook runs once, whatever thread asks; later calls do nothing."""
        with self._lock:
            if self._cancelled:
                return
            self._cancelled = True
            hooks, self._hooks = self._hooks, []
        for hook in hooks:
            self._run(hook)

    def register(self, hook: Callable[[], None]) -> Callable[[], None]:
        """Run ``hook`` when the call is cancelled, at once if it already was; returns what takes the hook back."""
        with self._lock:
            if not self._cancelled:
                self._hooks.append(hook)
                return lambda: self._discard(hook)
        self._run(hook)
        return lambda: None

    def _discard(self, hook: Callable[[], None]) -> None:
        with self._lock, contextlib.suppress(ValueError):
            self._hooks.remove(hook)

    @staticmethod
    def _run(hook: Callable[[], None]) -> None:
        try:
            hook()
        except Exception:  # a hook that fails must not keep the others from running
            logger.debug("A cancellation hook failed", exc_info=True)


def current_call_cancellation() -> CallCancellation | None:
    """The cancellation of the tool call running on this thread, if its request can still cancel it."""
    return getattr(_CURRENT, "value", None)


@contextlib.contextmanager
def bound(cancellation: CallCancellation | None) -> Iterator[None]:
    """Make ``cancellation`` the current one on this thread for the duration of a call."""
    previous = getattr(_CURRENT, "value", None)
    _CURRENT.value = cancellation
    try:
        yield
    finally:
        _CURRENT.value = previous


__all__ = ["CallCancellation", "bound", "current_call_cancellation"]
