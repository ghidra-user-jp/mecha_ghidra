"""Progress notifications for a call that waits (``notifications/progress``).

A call that waits for a job, or for a slow tool, tells a client that asked for progress that it is still working.
A client asks by putting a ``progressToken`` in the request's ``_meta``; without one nothing is sent and nothing
runs.  The value is the seconds waited so far, which only grows (the spec requires that), and the message names
what is running.  A reporter is silent until the first ``interval`` has passed, so a call that finishes at once
still gets its plain JSON reply; nothing is sent after the body of ``ticking`` ends, which is before the reply.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import anyio

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 1.0

Send = Callable[[float, float | None, str | None], Awaitable[None]]
Message = str | Callable[[], str]


class ProgressReporter:
    """Sends ``notifications/progress`` for one request."""

    def __init__(self, send: Send, *, interval: float | None = None, clock: Callable[[], float] = time.monotonic):
        self._send = send
        self._interval = INTERVAL_SECONDS if interval is None else interval
        self._clock = clock
        self._began = clock()
        self._last = 0.0
        self._stopped = False

    @classmethod
    def for_request(cls, ctx: Any, params: Any) -> ProgressReporter | None:
        """The reporter for a request whose client asked for progress, else None."""
        meta = getattr(params, "meta", None) or {}
        if meta.get("progress_token") is None:
            return None
        return cls(ctx.session.report_progress)

    @property
    def interval(self) -> float:
        return self._interval

    async def tick(self, message: str | None = None) -> None:
        """Report the seconds waited so far; never fails the call it reports on."""
        if self._stopped:
            return
        value = max(self._clock() - self._began, self._last + 0.001)  # strictly increasing, as the spec requires
        self._last = value
        try:
            await self._send(round(value, 3), None, message)
        except Exception as exc:  # the client went away or its stream closed: stop reporting
            self._stopped = True
            logger.debug("Progress report stopped (%s)", type(exc).__name__)


def _consume(task: asyncio.Future) -> None:
    if not task.cancelled():
        task.exception()  # retrieved, so a failed ticker never logs "exception was never retrieved"


@contextlib.asynccontextmanager
async def ticking(progress: ProgressReporter | None, message: Message) -> AsyncIterator[None]:
    """Report every interval while the body runs; nothing once it ends, and nothing without a reporter."""
    if progress is None:
        yield
        return

    async def report() -> None:
        while True:
            await anyio.sleep(progress.interval)
            await progress.tick(message() if callable(message) else message)

    ticker = asyncio.ensure_future(report())
    ticker.add_done_callback(_consume)
    try:
        yield
    finally:
        # Not awaited: awaiting here could swallow the cancellation of the call itself.
        ticker.cancel()


__all__ = ["INTERVAL_SECONDS", "ProgressReporter", "ticking"]
