"""The write boundary: headless as before, and the GUI backend's rules 1, 3, 5 and 6 (spec §6.2, §6.3).

A fake program models Ghidra's shared transactions (any start joins the open
one; one abort rolls the whole transaction back) and a one-thread executor
stands in for Swing's EDT.  The real GUI is exercised by the GUI integration
tests; nothing here needs a JVM.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.gui.write_boundary import MECHA_PREFIX, GuiWriteBoundary
from ghidra_headless.session.transactions import TransactionRecord, use_record
from ghidra_headless.session.write_boundary import WriteBoundary


class FakeInfo:
    def __init__(self, description: str) -> None:
        self.description = description
        self.status = "NOT_DONE"
        self.committed = False

    def getDescription(self):
        return self.description

    def getStatus(self):
        return self.status

    def hasCommittedDBTransaction(self):
        return self.committed


class FakeProgram:
    """Ghidra's shared transactions: a start joins the open one, even another thread's (``foreign``)."""

    def __init__(self, *, foreign: str | None = None) -> None:
        self.foreign = foreign
        self.current: FakeInfo | None = None
        self.entries = 0
        self.aborted = False
        self.ended: list[FakeInfo] = []
        self.undo_names: list[str] = []
        self.redo_names: list[str] = []
        self.threads: list[str] = []

    def getCurrentTransactionInfo(self):
        if self.current is not None:
            return self.current
        return None if self.foreign is None else FakeInfo(self.foreign)

    def startTransaction(self, description):
        self.threads.append(threading.current_thread().name)
        if self.current is None:
            # Joining another thread's open transaction keeps its description, as Ghidra does.
            self.current = FakeInfo(self.foreign if self.foreign is not None else description)
            self.aborted = False
        self.entries += 1
        return self.entries

    def endTransaction(self, _transaction_id, commit):
        """True only when this end finished the transaction as committed (DomainObjectAdapterDB)."""
        if not commit:
            self.aborted = True
        self.entries -= 1
        info = self.current
        if self.entries == 0:
            info.status = "ABORTED" if self.aborted else "COMMITTED"
            info.committed = not self.aborted
            if not self.aborted:
                self.undo_names.append(info.description)
            self.ended.append(info)
            self.current = None
        return info.status == "COMMITTED"

    def canUndo(self):
        return bool(self.undo_names)

    def canRedo(self):
        return bool(self.redo_names)

    def getUndoName(self):
        # Ghidra names no undo step while a transaction is open.
        if self.getCurrentTransactionInfo() is not None:
            return ""
        return self.undo_names[-1] if self.undo_names else ""

    def getRedoName(self):
        if self.getCurrentTransactionInfo() is not None:
            return ""
        return self.redo_names[-1] if self.redo_names else ""

    def undo(self):
        self.redo_names.append(self.undo_names.pop())

    def redo(self):
        self.undo_names.append(self.redo_names.pop())


@pytest.fixture
def edt():
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="fake-edt")
    yield executor
    executor.shutdown(wait=True)


def boundary_for(edt, *, state=None, timeout=1.0, before_run=None):
    def run_on_edt(function):
        def call():
            if before_run is not None:
                before_run()
            return function()

        return edt.submit(call).result()

    return GuiWriteBoundary(
        lock_timeout_seconds=timeout, thread_state=state or threading.local(), run_on_edt=run_on_edt
    )


def test_headless_boundary_commits_or_rolls_back_on_the_calling_thread():
    program = FakeProgram()
    assert WriteBoundary().write(program, "Rename function", lambda: "done") == "done"
    with pytest.raises(RuntimeError):
        WriteBoundary().write(program, "Rename function", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert [(info.description, info.status) for info in program.ended] == [
        ("Rename function", "COMMITTED"),
        ("Rename function", "ABORTED"),
    ]
    assert set(program.threads) == {threading.current_thread().name}


def test_gui_write_runs_on_the_edt_with_the_commands_state_and_mecha_name(edt):
    state = threading.local()
    state.current_key = "default"
    program = FakeProgram()
    seen = {}

    def change():
        seen["thread"] = threading.current_thread().name
        seen["key"] = getattr(state, "current_key", None)
        return 42

    record = TransactionRecord()
    with use_record(record):
        assert boundary_for(edt, state=state).write(program, "Rename function", change) == 42
    assert seen == {"thread": seen["thread"], "key": "default"}
    assert seen["thread"].startswith("fake-edt")
    assert program.ended[0].description == MECHA_PREFIX + "Rename function"
    # Rule 6: the boundary noted its own transaction; no listener was involved.
    assert record.outcome() == "committed"
    # The EDT thread keeps none of the command's state afterwards.
    assert edt.submit(lambda: getattr(state, "current_key", None)).result() is None
    assert state.current_key == "default"


def test_a_failed_gui_write_rolls_back_only_its_transaction_and_says_so(edt):
    program = FakeProgram()
    record = TransactionRecord()
    with use_record(record), pytest.raises(ValueError):
        boundary_for(edt).write(program, "Set comment", lambda: (_ for _ in ()).throw(ValueError("bad")))
    assert program.ended[0].status == "ABORTED"
    assert record.outcome() == "rolled_back"


def test_rule_1_times_out_before_starting_while_another_transaction_stays_open(edt):
    program = FakeProgram(foreign="Auto Analysis")
    with pytest.raises(HeadlessError) as raised:
        boundary_for(edt, timeout=0.2).write(program, "Rename function", lambda: None)
    assert raised.value.code == "LOCK_TIMEOUT"
    assert raised.value.details == {"lock": "program_transaction", "transaction": "Auto Analysis"}
    assert program.ended == [] and program.threads == []


def test_rule_1_waits_for_the_other_transaction_to_end(edt):
    program = FakeProgram(foreign="Auto Analysis")
    threading.Timer(0.1, lambda: setattr(program, "foreign", None)).start()
    started = time.monotonic()
    boundary_for(edt, timeout=5.0).write(program, "Rename function", lambda: None)
    assert time.monotonic() - started >= 0.1
    assert program.ended[0].status == "COMMITTED"


def test_the_edt_checks_again_before_starting_and_retries(edt):
    """A GUI command's background transaction can open between the check and the EDT section."""
    program = FakeProgram()
    appearances = iter([True, False])
    runs = []

    def background_transaction_appears():
        runs.append(True)
        program.foreign = "Background command" if next(appearances, False) else None
        if program.foreign is not None:
            threading.Timer(0.05, lambda: setattr(program, "foreign", None)).start()

    boundary_for(edt, before_run=background_transaction_appears).write(program, "Rename function", lambda: None)
    # Without the check on the EDT, the write would have joined "Background command".
    assert [info.description for info in program.ended] == [MECHA_PREFIX + "Rename function"]
    assert len(runs) == 2


def test_the_retry_on_the_edt_gives_up_at_the_deadline(edt):
    """A transaction only the EDT ever sees still ends in LOCK_TIMEOUT, not in retrying forever."""
    program = FakeProgram()

    def only_the_edt_sees_it():
        program.foreign = "Seen by the EDT"
        threading.Timer(0.01, lambda: setattr(program, "foreign", None)).start()

    started = time.monotonic()
    with pytest.raises(HeadlessError) as raised:
        boundary_for(edt, timeout=0.3, before_run=only_the_edt_sees_it).write(program, "Rename", lambda: None)
    assert raised.value.code == "LOCK_TIMEOUT"
    assert raised.value.details == {"lock": "program_transaction", "transaction": "Seen by the EDT"}
    assert time.monotonic() - started < 3
    assert program.ended == []


def test_the_next_item_never_joins_another_threads_transaction(edt):
    """apply_edits(atomic=false): between items, another thread may open a transaction; the item fails."""
    program = FakeProgram()
    boundary = boundary_for(edt)

    def items():
        boundary.end(program, boundary.start(program, "Annotation edit"), True)
        program.foreign = "Auto Analysis"
        with pytest.raises(HeadlessError) as raised:
            boundary.start(program, "Annotation edit")
        return raised.value

    error = boundary.section(program, items)
    assert error.code == "LOCK_TIMEOUT" and error.details["transaction"] == "Auto Analysis"
    assert [(info.description, info.status) for info in program.ended] == [
        (MECHA_PREFIX + "Annotation edit", "COMMITTED")
    ]


def test_a_mecha_transaction_another_thread_kept_open_is_not_reported_as_committed(edt):
    """A background entry joined Mecha's transaction and is still open when Mecha's last entry ends."""
    program = FakeProgram()
    record = TransactionRecord()

    def change():
        program.startTransaction("background entry")  # joins Mecha's transaction
        return "done"

    with use_record(record), pytest.raises(HeadlessError) as raised:
        boundary_for(edt).write(program, "Rename function", change)
    assert raised.value.code == "OPERATION_FAILED"
    assert record.outcome() == "unknown"


def test_nested_boundaries_join_their_own_outer_transaction_instead_of_waiting(edt):
    """apply_edits opens the outer transaction; each edit's handler calls the boundary again."""
    program = FakeProgram()
    boundary = boundary_for(edt, timeout=0.2)

    def batch():
        outer = boundary.start(program, "Apply annotation edits")
        boundary.write(program, "Rename function", lambda: None)
        boundary.write(program, "Set comment", lambda: None)
        boundary.end(program, outer, True)
        return "applied"

    assert boundary.section(program, batch) == "applied"
    assert [(info.description, info.status) for info in program.ended] == [
        (MECHA_PREFIX + "Apply annotation edits", "COMMITTED")
    ]
    assert all(thread.startswith("fake-edt") for thread in program.threads)


def test_undo_takes_back_mecha_steps_only_and_stops_at_the_humans(edt):
    program = FakeProgram()
    program.undo_names = ["Set Comment", MECHA_PREFIX + "Rename function", MECHA_PREFIX + "Apply annotation edits"]
    record = TransactionRecord()
    with use_record(record):
        undone = boundary_for(edt).undo(program, 3, lambda: None)
    assert undone == [MECHA_PREFIX + "Apply annotation edits", MECHA_PREFIX + "Rename function"]
    assert program.undo_names == ["Set Comment"]
    assert record.outcome() == "committed"


def test_undo_refuses_when_the_latest_step_is_the_humans(edt):
    program = FakeProgram()
    program.undo_names = [MECHA_PREFIX + "Rename function", "Set Comment"]
    with pytest.raises(HeadlessError) as raised:
        boundary_for(edt).undo(program, 1, lambda: None)
    assert raised.value.code == "GUI_UNSUPPORTED"
    assert raised.value.details == {"reason": "foreign_undo", "top_undo_name": "Set Comment"}
    assert program.undo_names == [MECHA_PREFIX + "Rename function", "Set Comment"]


def test_undo_waits_for_another_transaction_before_reading_the_step_name(edt):
    """§6.3: while a transaction is open Ghidra names no step, so undo applies rule 1 first."""
    program = FakeProgram(foreign="Auto Analysis")
    program.undo_names = [MECHA_PREFIX + "Rename function"]
    with pytest.raises(HeadlessError) as raised:
        boundary_for(edt, timeout=0.2).undo(program, 1, lambda: None)
    assert raised.value.code == "LOCK_TIMEOUT"
    assert program.undo_names == [MECHA_PREFIX + "Rename function"]
    program.foreign = None
    assert boundary_for(edt).undo(program, 1, lambda: None) == [MECHA_PREFIX + "Rename function"]


def test_redo_follows_the_same_rule(edt):
    program = FakeProgram()
    program.redo_names = ["Set Comment"]
    with pytest.raises(HeadlessError) as raised:
        boundary_for(edt).redo(program, 1, lambda: None)
    assert raised.value.details == {"reason": "foreign_redo", "top_redo_name": "Set Comment"}


def test_headless_undo_and_redo_walk_the_history_unchanged():
    program = FakeProgram()
    program.undo_names = ["Set Comment", "Rename function"]
    names = WriteBoundary().undo(program, 5, program.getUndoName)
    assert names == ["Rename function", "Set Comment"]
    assert WriteBoundary().redo(program, 1, program.getRedoName) == ["Set Comment"]
