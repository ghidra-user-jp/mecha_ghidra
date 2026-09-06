"""Run a callable inside one Ghidra program transaction.

Programs are opened without the permanent "Batch Processing" transaction that
``GhidraProject.openProgram`` would install, so every mutation must open and
close its own transaction.  Tool handlers do this through ``core_helpers._txn``;
this helper covers the runtime paths (auto-analysis on first load) that have a
program but no handler context.
"""

from __future__ import annotations

from typing import Callable, TypeVar

_T = TypeVar("_T")


def run_in_transaction(program, description: str, operation: Callable[[], _T]) -> _T:
    transaction_id = program.startTransaction(description)
    success = False
    try:
        result = operation()
        success = True
        return result
    finally:
        program.endTransaction(transaction_id, success)


__all__ = ["run_in_transaction"]
