"""Domain policy constants for concurrency/lifecycle rules."""

from __future__ import annotations

LOCK_ORDER: tuple[str, ...] = ("registry", "target", "project")
DEFAULT_LOCK_TIMEOUT_SECONDS: float = 0.1
LOCK_FAIL_FAST: bool = True

__all__ = ["DEFAULT_LOCK_TIMEOUT_SECONDS", "LOCK_FAIL_FAST", "LOCK_ORDER"]
