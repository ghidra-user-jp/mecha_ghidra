"""What a command's transactions say it left behind (no JVM: the recorder is faked)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.commands import mutating_bsim
from ghidra_headless.session import transactions
from ghidra_headless.session.transactions import TransactionRecord


class _Transaction:
    def __init__(self, status: str, wrote: bool) -> None:
        self._status = status
        self._wrote = wrote

    def getStatus(self):
        return self._status

    def hasCommittedDBTransaction(self):
        return self._wrote


def _record(*started: _Transaction, history_changed: bool = False) -> TransactionRecord:
    return TransactionRecord(SimpleNamespace(started=list(started), history_changed=history_changed))


@pytest.mark.parametrize(
    ("record", "outcome"),
    [
        (TransactionRecord(), "unknown"),
        (_record(), "unchanged"),
        (_record(history_changed=True), "committed"),
        (_record(_Transaction("COMMITTED", True)), "committed"),
        (_record(_Transaction("COMMITTED", False)), "unchanged"),
        (_record(_Transaction("ABORTED", False)), "rolled_back"),
        (_record(_Transaction("ABORTED", False), _Transaction("COMMITTED", True)), "committed"),
        (_record(_Transaction("NOT_DONE", False)), "unknown"),
    ],
)
def test_outcome_follows_how_the_transactions_ended(record, outcome):
    assert record.outcome() == outcome


def test_a_write_outside_the_program_makes_the_outcome_unknown():
    record = _record()
    with transactions._current(record):
        transactions.note_external_write()
    assert record.outcome() == "unknown"
    # Outside a recorded block there is nothing to mark.
    transactions.note_external_write()
    assert _record().outcome() == "unchanged"


class _Database:
    def __init__(self, *, initializes: bool) -> None:
        self._initializes = initializes

    def initialize(self):
        return self._initializes

    def getLastError(self):
        return SimpleNamespace(category="Initialization", message="Connection to localhost:5432 refused")

    def getInfo(self):
        return SimpleNamespace(trackcallgraph=False, execats=[], functionTags=[], dateColumnName=None)

    def getLSHVectorFactory(self):
        return None

    def close(self):
        pass


class _GenSignatures:
    def __init__(self, _track_callgraph) -> None:
        pass

    def __getattr__(self, _name):
        return lambda *_args: None

    def getDescriptionManager(self):
        return SimpleNamespace(numFunctions=lambda: 1, listAllFunctions=lambda: iter(()))


class _InsertRequest:
    manage = None

    def execute(self, _database):
        return None


@pytest.mark.parametrize("initializes", [False, True])
def test_bsim_registration_marks_the_database_write_before_it_starts(monkeypatch, initializes):
    database = _Database(initializes=initializes)
    factory = SimpleNamespace(deriveBSimURL=lambda url: url, buildClient=lambda _url, _async: database)
    monkeypatch.setattr(
        mutating_bsim,
        "_bsim_registration_classes",
        lambda: (factory, _GenSignatures, _InsertRequest, None, None),
    )
    monkeypatch.setattr(mutating_bsim, "_program_repository_and_path", lambda _program: ("ghidra:/p", None))
    monkeypatch.setattr(mutating_bsim, "_sort_callgraph", lambda _manager: None)
    functions = SimpleNamespace(getFunctions=lambda _forward: iter(()), getFunctionCount=lambda: 0)
    ctx = SimpleNamespace(
        program=SimpleNamespace(getFunctionManager=lambda: functions),
        monitor=lambda: None,
    )
    record = _record()
    with transactions._current(record), pytest.raises(HeadlessError) as failed:
        mutating_bsim.bsim_register_target({"bsim_url": "postgresql://db/bsim"}, ensure_context=lambda: ctx, txn=None)
    if initializes:
        # The insert ran and failed: the database may hold part of it.
        assert failed.value.code == "BSIM_INSERT_FAILED"
        assert record.outcome() == "unknown"
    else:
        # Refused at the connection, before anything was written.
        assert failed.value.code == "BSIM_DATABASE_INIT_FAILED"
        assert record.outcome() == "unchanged"
