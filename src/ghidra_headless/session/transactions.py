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

# How a command's or script's transactions ended; scripts.execution reports
# the same values as details.transaction_outcome.
UNCHANGED = "unchanged"
COMMITTED = "committed"
ROLLED_BACK = "rolled_back"
UNKNOWN = "unknown"


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
        # Set by note_external_write: the block wrote outside the program too.
        self.external_write = False

    def outcome(self) -> str:
        """``committed`` includes applied undo/redo steps; ``unchanged`` means neither kind of change ran.

        After a write outside the program, which transactions do not show,
        the outcome is ``unknown``.
        """
        if self._recorder is None or self.external_write:
            return UNKNOWN
        changed = self._recorder.history_changed
        if not self._recorder.started:
            return COMMITTED if changed else UNCHANGED
        try:
            ended = [
                (str(transaction.getStatus()), bool(transaction.hasCommittedDBTransaction()))
                for transaction in self._recorder.started
            ]
        except Exception:
            return UNKNOWN
        if any(status not in ("COMMITTED", "ABORTED") for status, _ in ended):
            # NOT_DONE or NOT_DONE_BUT_ABORTED: a transaction is still open.
            return UNKNOWN
        # A committed transaction that wrote nothing to the database changed
        # nothing, as scripts.execution.classify_transaction also counts it.
        if changed or any(status == "COMMITTED" and wrote for status, wrote in ended):
            return COMMITTED
        return ROLLED_BACK if any(status == "ABORTED" for status, _ in ended) else UNCHANGED


_CURRENT = threading.local()


def note_external_write() -> None:
    """Say the running block starts writing outside the program, such as to a BSim database.

    A failure after this may have left part of that write, so the block's
    outcome becomes ``unknown``.  Outside ``recorded_transactions`` it does
    nothing.
    """
    record = getattr(_CURRENT, "record", None)
    if record is not None:
        record.external_write = True


@contextlib.contextmanager
def _current(record: TransactionRecord) -> Iterator[TransactionRecord]:
    previous = getattr(_CURRENT, "record", None)
    _CURRENT.record = record
    try:
        yield record
    finally:
        _CURRENT.record = previous


@contextlib.contextmanager
def recorded_transactions(program) -> Iterator[TransactionRecord]:
    """Note the transactions this thread starts on ``program`` while the block runs."""
    import jpype

    recorder = _recorder_class()(threading.current_thread())
    # Ghidra keeps transaction listeners in a weak set and JPype keeps its Java
    # proxy only weakly: without this reference a GC during the block drops
    # the listener and a committed write would look unchanged.
    listener = jpype.JObject(recorder, jpype.JClass("ghidra.framework.model.TransactionListener"))
    try:
        program.addTransactionListener(listener)
    except Exception:
        registered = False
    else:
        registered = True
    if not registered:
        with _current(TransactionRecord()) as record:
            yield record
        return
    try:
        with _current(TransactionRecord(recorder)) as record:
            yield record
    finally:
        with contextlib.suppress(Exception):
            program.removeTransactionListener(listener)


__all__ = [
    "COMMITTED",
    "ROLLED_BACK",
    "UNCHANGED",
    "UNKNOWN",
    "TransactionRecord",
    "note_external_write",
    "recorded_transactions",
    "run_in_transaction",
]
