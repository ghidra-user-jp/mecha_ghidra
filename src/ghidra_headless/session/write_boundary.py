"""Where commands change a program: the write boundary (spec §6.2).

Handlers never start transactions on their own terms; they go through the
active boundary: ``write`` for one change (``core_helpers._txn``), ``section``
around a command that opens several transactions itself (``apply_edits``),
with ``start`` and ``end`` for those, and ``undo``/``redo`` for history steps.

The default boundary is the headless one: what the handlers always did, on
the calling thread.  The Ghidra GUI backend installs its own
(``ghidra_headless.gui.write_boundary``), which shares the program with the
human and applies the GUI write rules there, so no handler branches on the
backend.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

_T = TypeVar("_T")


class WriteBoundary:
    """The headless boundary: transactions on the calling thread, named as the handler names them."""

    def write(self, program, description: str, func: Callable[[], _T]) -> _T:
        """Run ``func`` in one transaction; commit if it returns, roll back if it raises."""
        transaction_id = self.start(program, description)
        success = False
        try:
            result = func()
            success = True
            return result
        finally:
            self.end(program, transaction_id, success)

    def section(self, program, func: Callable[[], _T]) -> _T:
        """Run a command body that opens its own transactions with ``start`` and ``end``."""
        del program
        return func()

    def start(self, program, description: str) -> int:
        return program.startTransaction(description)

    def end(self, program, transaction_id: int, commit: bool) -> None:
        program.endTransaction(transaction_id, commit)

    def wait_until_idle(self, program) -> None:
        """Before work that locks the whole program (a save, a .gzf export): nothing else writes here."""
        del program

    def undo(self, program, count: int, name_of: Callable[[], object]) -> list[object]:
        """Undo up to ``count`` steps; the names of the steps undone, newest first."""
        return self._history(program, count, name_of, redo=False)

    def redo(self, program, count: int, name_of: Callable[[], object]) -> list[object]:
        """Redo up to ``count`` steps; the names of the steps redone."""
        return self._history(program, count, name_of, redo=True)

    @staticmethod
    def _history(program, count: int, name_of: Callable[[], object], *, redo: bool) -> list[object]:
        done: list[object] = []
        for _ in range(count):
            if not bool(program.canRedo() if redo else program.canUndo()):
                break
            name = name_of()
            if redo:
                program.redo()
            else:
                program.undo()
            done.append(name)
        return done


# The active boundary; one per process (the backend is chosen at startup).
_ACTIVE: list[WriteBoundary] = [WriteBoundary()]


def write_boundary() -> WriteBoundary:
    return _ACTIVE[0]


def use_write_boundary(boundary: WriteBoundary) -> None:
    """Install ``boundary`` for every later command (the GUI backend does this once at startup)."""
    _ACTIVE[0] = boundary


__all__ = ["WriteBoundary", "use_write_boundary", "write_boundary"]
