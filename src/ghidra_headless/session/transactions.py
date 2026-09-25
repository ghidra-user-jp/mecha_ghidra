"""Run a callable inside one Ghidra program transaction, and note how a command's transactions ended.

Programs are opened without the permanent "Batch Processing" transaction that
``GhidraProject.openProgram`` would install, so every mutation must open and
close its own transaction.  Tool handlers do this through ``core_helpers._txn``;
this helper covers the runtime paths (analysis after an import) that have a
program but no handler context.

``recorded_transactions`` tells what a failed command left behind.  The
program's modification number cannot: an aborted transaction advances it too,
although its changes are gone.
"""

from __future__ import annotations

import contextlib
import functools
import threading
from typing import Callable, Iterator, TypeVar

_T = TypeVar("_T")

UNCHANGED = "unchanged"
COMMITTED = "committed"
ROLLED_BACK = "rolled_back"
UNCERTAIN = "uncertain"


def run_in_transaction(program, description: str, operation: Callable[[], _T]) -> _T:
    transaction_id = program.startTransaction(description)
    success = False
    try:
        result = operation()
        success = True
        return result
    finally:
        program.endTransaction(transaction_id, success)


@functools.cache
def _recorder_class():
    """The TransactionListener noting what one thread starts; defined once the JVM is up."""
    from jpype import JImplements, JOverride

    @JImplements("ghidra.framework.model.TransactionListener")
    class _Recorder(object):
        def __init__(self, thread):
            self.thread = thread
            self.started = []
            self.history_changed = False

        @JOverride
        def transactionStarted(self, domain_object, transaction):
            # Headless callbacks run on the thread that started the
            # transaction; only top-level transactions are reported.
            if threading.current_thread() is self.thread:
                self.started.append(transaction)

        @JOverride
        def transactionEnded(self, domain_object):
            return None

        @JOverride
        def undoStackChanged(self, domain_object):
            return None

        @JOverride
        def undoRedoOccurred(self, domain_object):
            # Undo/redo changes the program without starting a transaction.
            # An earlier step stays applied if a later history step fails.
            if threading.current_thread() is self.thread:
                self.history_changed = True

    return _Recorder


class TransactionRecord:
    """The transactions a block started on one program, and how they ended."""

    def __init__(self, recorder=None) -> None:
        self._recorder = recorder

    def outcome(self) -> str:
        """``committed`` includes applied undo/redo steps; ``unchanged`` means neither kind of change ran."""
        if self._recorder is None:
            return UNCERTAIN
        if not self._recorder.started:
            return COMMITTED if self._recorder.history_changed else UNCHANGED
        try:
            statuses = {str(transaction.getStatus()) for transaction in self._recorder.started}
        except Exception:
            return UNCERTAIN
        if statuses == {"ABORTED"}:
            return COMMITTED if self._recorder.history_changed else ROLLED_BACK
        if statuses <= {"COMMITTED", "ABORTED"}:
            return COMMITTED
        # NOT_DONE or NOT_DONE_BUT_ABORTED: a transaction is still open.
        return UNCERTAIN


@contextlib.contextmanager
def recorded_transactions(program) -> Iterator[TransactionRecord]:
    """Note the transactions this thread starts on ``program`` while the block runs."""
    recorder = _recorder_class()(threading.current_thread())
    try:
        program.addTransactionListener(recorder)
    except Exception:
        yield TransactionRecord()
        return
    try:
        yield TransactionRecord(recorder)
    finally:
        with contextlib.suppress(Exception):
            program.removeTransactionListener(recorder)


__all__ = [
    "COMMITTED",
    "ROLLED_BACK",
    "UNCERTAIN",
    "UNCHANGED",
    "TransactionRecord",
    "recorded_transactions",
    "run_in_transaction",
]
