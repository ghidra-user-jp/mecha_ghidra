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
        # Noted by a write boundary that knows its own transactions (see
        # note_transaction): with the Ghidra GUI, listener callbacks come later
        # on the Swing thread, so the recorder alone sees none of them.
        self._noted: list = []
        self._noted_history = False

    def note_transaction(self, transaction) -> None:
        """Count ``transaction`` (a ``TransactionInfo``) as started by the block."""
        self._noted.append(transaction)

    def note_history_change(self) -> None:
        """Count an undo or redo step as a change made by the block."""
        self._noted_history = True

    def outcome(self) -> str:
        """``committed`` includes applied undo/redo steps; ``unchanged`` means neither kind of change ran.

        After a write outside the program, which transactions do not show,
        the outcome is ``unknown``.
        """
        if self.external_write:
            return UNKNOWN
        noted = bool(self._noted) or self._noted_history
        if self._recorder is None and not noted:
            return UNKNOWN
        started = list(self._recorder.started) if self._recorder is not None else []
        for transaction in self._noted:
            if not any(transaction is seen or transaction == seen for seen in started):
                started.append(transaction)
        changed = self._noted_history or (self._recorder is not None and self._recorder.history_changed)
        if not started:
            return COMMITTED if changed else UNCHANGED
        try:
            ended = [
                (str(transaction.getStatus()), bool(transaction.hasCommittedDBTransaction())) for transaction in started
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


def current_record() -> TransactionRecord | None:
    """The record of the block running on this thread, or None."""
    return getattr(_CURRENT, "record", None)


def note_transaction(transaction) -> None:
    """Count ``transaction`` in the running block's record (a write boundary's own transaction, rule 6)."""
    record = current_record()
    if record is not None:
        record.note_transaction(transaction)


def note_history_change() -> None:
    """Count an undo or redo step in the running block's record."""
    record = current_record()
    if record is not None:
        record.note_history_change()


@contextlib.contextmanager
def use_record(record: TransactionRecord | None) -> Iterator[TransactionRecord | None]:
    """Make ``record`` this thread's running record, as on the thread that entered the block."""
    previous = getattr(_CURRENT, "record", None)
    _CURRENT.record = record
    try:
        yield record
    finally:
        _CURRENT.record = previous


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
    "current_record",
    "note_external_write",
    "note_history_change",
    "note_transaction",
    "recorded_transactions",
    "run_in_transaction",
    "use_record",
]
