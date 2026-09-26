"""Wait on the event loop, holding no thread, for state that another thread changes."""

from __future__ import annotations

from collections.abc import Callable

import anyio

# How often a waiting call looks again.
POLL_SECONDS = 0.05


async def wait_until(done: Callable[[], bool], timeout: float) -> bool:
    """True as soon as ``done()`` returns true, False after ``timeout`` seconds.

    ``done`` is called once per look, and not again after it returned true,
    so it may take what it waits for (a slot, say).
    """
    with anyio.move_on_after(max(0.0, timeout)):
        while not done():
            await anyio.sleep(POLL_SECONDS)
        return True
    return False


__all__ = ["POLL_SECONDS", "wait_until"]
