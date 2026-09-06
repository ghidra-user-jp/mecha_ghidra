"""Domain policy constants for concurrency/lifecycle rules."""

from __future__ import annotations

import threading

LOCK_ORDER: tuple[str, ...] = ("registry", "target", "project")

# How long a request waits for a target/project lock before failing with a
# retryable LOCK_TIMEOUT.  Tools run in worker threads, so parallel tool calls
# from one agent routinely contend for the same target; queueing them for a
# while is far more useful than failing immediately.  Operators tune this with
# ``--lock-timeout-seconds``.
DEFAULT_LOCK_TIMEOUT_SECONDS: float = 30.0

_lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS

# Whether checkout_project_program (and the automatic checkout made by
# commit_project_program) requests an exclusive checkout when the caller does
# not say.  Headless Ghidra cannot merge, so an agent that edits a program other
# users also edit can only discard one side; exclusive checkouts make the
# conflict impossible instead of merely detectable.  Operators turn this on
# with ``--shared-sync-exclusive-checkout``.
DEFAULT_EXCLUSIVE_CHECKOUT: bool = False

_exclusive_checkout_default: bool = DEFAULT_EXCLUSIVE_CHECKOUT
_policy_lock = threading.Lock()


def get_lock_timeout_seconds() -> float:
    with _policy_lock:
        return _lock_timeout_seconds


def configure_lock_timeout_seconds(seconds: float) -> None:
    """Set the process-wide lock wait; ``seconds`` must be positive."""

    global _lock_timeout_seconds
    value = float(seconds)
    if value <= 0:
        raise ValueError("lock timeout must be > 0 seconds")
    with _policy_lock:
        _lock_timeout_seconds = value


def get_exclusive_checkout_default() -> bool:
    with _policy_lock:
        return _exclusive_checkout_default


def configure_exclusive_checkout_default(enabled: bool) -> None:
    """Set whether checkouts are exclusive when a caller does not choose."""

    global _exclusive_checkout_default
    with _policy_lock:
        _exclusive_checkout_default = bool(enabled)


__all__ = [
    "DEFAULT_EXCLUSIVE_CHECKOUT",
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "LOCK_ORDER",
    "configure_exclusive_checkout_default",
    "configure_lock_timeout_seconds",
    "get_exclusive_checkout_default",
    "get_lock_timeout_seconds",
]
