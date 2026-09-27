"""The GUI backend's write boundary (spec §6.2 rules 1, 3, 5 and 6; §6.3).

The program is shared with the human, so a Mecha write must not join a
transaction the human (or auto-analysis) has open, and nothing may join
Mecha's: Ghidra lets any thread's ``startTransaction`` join the open one, and
one entry ending with ``commit=false`` rolls back every joined change.

- **Rule 1**: before a write starts, wait (up to the lock timeout) until the
  program has no open transaction; then ``LOCK_TIMEOUT``, with nothing done.
- **Rule 3**: the transaction section runs on the EDT, where the human's GUI
  edits also run, so they cannot land inside it.  The section checks again on
  the EDT before starting: a GUI command leaves a short background
  transaction behind (``EmptyBackgroundCommand``), and a section that finds
  it waits and tries again.  The command's thread-local state goes with it.
- **Rule 5**: transactions are named ``Mecha: <description>``.
- **Rule 6**: each transaction's ``TransactionInfo`` goes into the running
  command's record; listener callbacks arrive too late to count.

Boundaries nest: ``apply_edits`` opens its own transactions around each
edit's handler, and those call the boundary again.  Rules 1 and 3 apply only
at the outermost boundary; an inner one runs in place (already on the EDT)
and joins the transaction its own command opened.  A start while none of
Mecha's own entries is open (the next item of ``apply_edits`` with
``atomic=false``) never joins another thread's transaction: it fails with
``LOCK_TIMEOUT`` instead, as the EDT cannot wait for it.  When Mecha's
outermost entry ends and the transaction did not commit, another thread's
work joined it (the residual risk of §6.2); the write then fails instead of
reporting success.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session.transactions import current_record, note_history_change, note_transaction, use_record
from ghidra_headless.session.write_boundary import WriteBoundary

from . import edt

_T = TypeVar("_T")

MECHA_PREFIX = "Mecha: "
_POLL_SECONDS = 0.05
# The command's thread-local state (core_runtime._THREAD_STATE) that the EDT section needs.
_STATE_FIELDS = (
    "current_key",
    "task_monitor",
    "on_begin",
    "transaction_outcome",
    "transaction_record",
    "command_source",
)
_DEPTH = "mecha_write_depth"
_OPEN = "mecha_open_entries"
_OWN_STATE = (_DEPTH, _OPEN)


def _open_transaction(program) -> str | None:
    info = program.getCurrentTransactionInfo()
    return None if info is None else str(info.getDescription())


def _lock_timeout(description: str) -> HeadlessError:
    return HeadlessError(
        f"LOCK_TIMEOUT: the program has another transaction open ({description}); nothing was changed. "
        "Ghidra's auto-analysis or a GUI command is still running; retry when it ends",
        details={"lock": "program_transaction", "transaction": description},
    )


class _Busy:
    """The EDT found a transaction open when the section was about to start."""


class GuiWriteBoundary(WriteBoundary):
    """Rules 1, 3, 5 and 6 around every Mecha write to a program the GUI owns."""

    def __init__(
        self,
        *,
        lock_timeout_seconds: float,
        thread_state=None,
        run_on_edt: Callable[[Callable[[], object]], object] | None = None,
    ) -> None:
        """``thread_state`` defaults to the core's command state, ``run_on_edt`` to Swing's EDT (tests pass fakes)."""
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        if thread_state is None:
            from ghidra_headless.handlers import core_runtime

            thread_state = core_runtime._THREAD_STATE
        self._state = thread_state
        self._run_on_edt = run_on_edt or edt.run_on_edt

    def _thread_state(self) -> dict[str, object]:
        return {
            name: getattr(self._state, name) for name in (*_STATE_FIELDS, *_OWN_STATE) if hasattr(self._state, name)
        }

    def _set_thread_state(self, values: dict[str, object]) -> None:
        for name in (*_STATE_FIELDS, *_OWN_STATE):
            if name in values:
                setattr(self._state, name, values[name])
            elif hasattr(self._state, name):
                delattr(self._state, name)

    # ---- the WriteBoundary surface ------------------------------------------

    def write(self, program, description: str, func: Callable[[], _T]) -> _T:
        if self._depth() > 0:
            return super().write(program, description, func)
        return self.section(program, lambda: WriteBoundary.write(self, program, description, func))

    def section(self, program, func: Callable[[], _T]) -> _T:
        if self._depth() > 0:
            return func()
        return self._on_edt_when_idle(program, func)

    def start(self, program, description: str) -> int:
        if self._open_entries() == 0:
            # Never join another thread's transaction (see the module docstring).
            foreign = _open_transaction(program)
            if foreign is not None:
                raise _lock_timeout(foreign)
        transaction_id = program.startTransaction(MECHA_PREFIX + description)
        setattr(self._state, _OPEN, self._open_entries() + 1)
        info = program.getCurrentTransactionInfo()
        if info is not None:
            note_transaction(info)
        return transaction_id

    def end(self, program, transaction_id: int, commit: bool) -> None:
        # True only when this end finished the whole transaction as committed.
        committed = bool(program.endTransaction(transaction_id, commit))
        remaining = max(self._open_entries() - 1, 0)
        setattr(self._state, _OPEN, remaining)
        if commit and remaining == 0 and not committed:
            raise HeadlessError(
                "OPERATION_FAILED: Mecha's transaction did not commit: work of another thread (Ghidra's "
                "auto-analysis or a tool's background command) joined it and rolled it back or is still running; "
                "read the program again before continuing"
            )

    def wait_until_idle(self, program) -> None:
        """Rule 1 for work that locks the program: a save or export while another transaction is open
        fails, or makes Ghidra offer to force it, which rolls that transaction back."""
        self._wait_until_idle(program, time.monotonic() + self.lock_timeout_seconds)

    def undo(self, program, count: int, name_of: Callable[[], object]) -> list[object]:
        del name_of  # the names come from the program on the EDT
        return self._on_edt_when_idle(program, lambda: self._history(program, count, redo=False))

    def redo(self, program, count: int, name_of: Callable[[], object]) -> list[object]:
        del name_of
        return self._on_edt_when_idle(program, lambda: self._history(program, count, redo=True))

    # ---- rules 1 and 3 -------------------------------------------------------

    def _depth(self) -> int:
        return int(getattr(self._state, _DEPTH, 0))

    def _open_entries(self) -> int:
        return int(getattr(self._state, _OPEN, 0))

    def _wait_until_idle(self, program, deadline: float) -> None:
        """Rule 1: no transaction open on ``program``; LOCK_TIMEOUT at the deadline, before anything changed."""
        while True:
            description = _open_transaction(program)
            if description is None:
                return
            if time.monotonic() >= deadline:
                raise _lock_timeout(description)
            time.sleep(_POLL_SECONDS)

    def _on_edt_when_idle(self, program, func: Callable[[], _T]) -> _T:
        """Run ``func`` on the EDT once the program has no open transaction, with this command's state."""
        deadline = time.monotonic() + self.lock_timeout_seconds
        state = {**self._thread_state(), _DEPTH: 1, _OPEN: 0}
        record = current_record()
        while True:
            self._wait_until_idle(program, deadline)
            outcome: dict[str, object] = {}

            def attempt(outcome: dict[str, object] = outcome) -> None:
                busy = _open_transaction(program)
                if busy is not None:
                    outcome["value"] = _Busy
                    outcome["transaction"] = busy
                    return
                saved = self._thread_state()
                self._set_thread_state(state)
                try:
                    with use_record(record):
                        outcome["value"] = func()
                except BaseException as exc:  # re-raised on the calling thread
                    outcome["error"] = exc
                finally:
                    self._set_thread_state(saved)

            self._run_on_edt(attempt)
            if "error" in outcome:
                raise outcome["error"]  # type: ignore[misc]
            if outcome.get("value") is _Busy:
                # A GUI command's background transaction was still open: wait again, up to the deadline.
                if time.monotonic() >= deadline:
                    raise _lock_timeout(str(outcome["transaction"]))
                time.sleep(_POLL_SECONDS)
                continue
            return outcome.get("value")  # type: ignore[return-value]

    # ---- §6.3 ----------------------------------------------------------------

    @staticmethod
    def _history(program, count: int, *, redo: bool) -> list[object]:
        """Undo or redo Mecha's own steps only, newest first; stop at the first that is not Mecha's."""
        done: list[object] = []
        for _ in range(count):
            if not bool(program.canRedo() if redo else program.canUndo()):
                break
            name = str(program.getRedoName() if redo else program.getUndoName())
            if not name.startswith(MECHA_PREFIX):
                if done:
                    break
                what = "redo" if redo else "undo"
                raise HeadlessError(
                    f"GUI_UNSUPPORTED: the next {what} step is not Mecha's ({name}); "
                    f"only the human can {what} it, in the Ghidra GUI",
                    details={"reason": f"foreign_{what}", f"top_{what}_name": name},
                )
            if redo:
                program.redo()
            else:
                program.undo()
            note_history_change()
            done.append(name)
        return done


def install_gui_write_boundary(*, lock_timeout_seconds: float) -> GuiWriteBoundary:
    """Make every later command write through the GUI boundary (once, at startup)."""
    from ghidra_headless.session.write_boundary import use_write_boundary

    boundary = GuiWriteBoundary(lock_timeout_seconds=lock_timeout_seconds)
    use_write_boundary(boundary)
    return boundary


__all__ = ["MECHA_PREFIX", "GuiWriteBoundary", "install_gui_write_boundary"]
