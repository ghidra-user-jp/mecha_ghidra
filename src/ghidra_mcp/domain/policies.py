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


# How long run_script waits for in-flight operations to finish before it may
# start (the script barrier's writer wait).  A script run is a rare, long,
# deliberately requested operation, so waiting a few minutes behind a running
# analysis beats failing after the general lock timeout and asking the client
# to retry.  Operators tune this with ``--script-queue-timeout-seconds``.
DEFAULT_SCRIPT_QUEUE_TIMEOUT_SECONDS: float = 300.0


# Whether checkout_project_program (and the automatic checkout made by
# commit_project_program) requests an exclusive checkout when the caller does
# not say.  Headless Ghidra cannot merge, so an agent that edits a program other
# users also edit can only discard one side; exclusive checkouts make the
# conflict impossible instead of merely detectable.  Operators turn this on
# with ``--shared-sync-exclusive-checkout``.
DEFAULT_EXCLUSIVE_CHECKOUT: bool = False

_policy_lock = threading.Lock()


class _Policy:
    """The process-wide values set by the CLI at startup."""

    __slots__ = ("exclusive_checkout_default", "lock_timeout_seconds", "script_queue_timeout_seconds")

    def __init__(self) -> None:
        self.lock_timeout_seconds = DEFAULT_LOCK_TIMEOUT_SECONDS
        self.script_queue_timeout_seconds = DEFAULT_SCRIPT_QUEUE_TIMEOUT_SECONDS
        self.exclusive_checkout_default = DEFAULT_EXCLUSIVE_CHECKOUT


_policy = _Policy()


def get_lock_timeout_seconds() -> float:
    with _policy_lock:
        return _policy.lock_timeout_seconds


def configure_lock_timeout_seconds(seconds: float) -> None:
    """Set the process-wide lock wait; ``seconds`` must be positive."""

    value = float(seconds)
    if value <= 0:
        raise ValueError("lock timeout must be > 0 seconds")
    with _policy_lock:
        _policy.lock_timeout_seconds = value


def get_script_queue_timeout_seconds() -> float:
    with _policy_lock:
        return _policy.script_queue_timeout_seconds


def configure_script_queue_timeout_seconds(seconds: float) -> None:
    """Set how long run_script waits for other operations before starting; must be positive."""

    value = float(seconds)
    if value <= 0:
        raise ValueError("script queue timeout must be > 0 seconds")
    with _policy_lock:
        _policy.script_queue_timeout_seconds = value


def get_exclusive_checkout_default() -> bool:
    with _policy_lock:
        return _policy.exclusive_checkout_default


def configure_exclusive_checkout_default(enabled: bool) -> None:
    """Set whether checkouts are exclusive when a caller does not choose."""

    with _policy_lock:
        _policy.exclusive_checkout_default = bool(enabled)


__all__ = [
    "DEFAULT_EXCLUSIVE_CHECKOUT",
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "DEFAULT_SCRIPT_QUEUE_TIMEOUT_SECONDS",
    "LOCK_ORDER",
    "configure_exclusive_checkout_default",
    "configure_lock_timeout_seconds",
    "configure_script_queue_timeout_seconds",
    "get_exclusive_checkout_default",
    "get_lock_timeout_seconds",
    "get_script_queue_timeout_seconds",
]
