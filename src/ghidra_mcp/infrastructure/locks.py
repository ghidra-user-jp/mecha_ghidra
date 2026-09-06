"""Compatibility re-export; locking primitives live in ``ghidra_mcp.application.locks``.

Application services depend on these primitives, so they belong to the
application layer rather than to infrastructure.
"""

from ghidra_mcp.application.locks import (
    USE_POLICY_TIMEOUT,
    KeyedLockPool,
    LockManager,
    acquire_ordered_locks,
)

__all__ = ["USE_POLICY_TIMEOUT", "KeyedLockPool", "LockManager", "acquire_ordered_locks"]
