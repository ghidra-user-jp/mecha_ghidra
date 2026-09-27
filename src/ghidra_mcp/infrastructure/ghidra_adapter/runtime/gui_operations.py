"""The GUI tools of the Ghidra GUI backend: ``get_gui_context`` and ``show_in_gui`` (spec §8, §9).

Neither takes a target's lock: ``show_in_gui`` reads the target's program
from the registry and does not wait for a long command (a decompile) on that
target to end, and neither changes the program.
"""

from __future__ import annotations

from typing import Any

from ghidra_headless.errors import HeadlessError

from .session_store import RuntimeSessionStore


class RuntimeGuiOperations:
    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    def _bound_sessions(self) -> list[tuple[str, Any]]:
        with self._store.registry_lock.read_lock():
            return list(self._store.sessions.items())

    @staticmethod
    def _revision(name: str, program) -> str | None:
        from ghidra_headless.handlers import core_runtime

        context = core_runtime._CONTEXTS.get(name)
        if context is None:
            return None
        return "%s:%s" % (context.generation, program.getModificationNumber())

    def get_gui_context(self) -> dict[str, Any]:
        from ghidra_headless.gui import navigation
        from ghidra_headless.gui.project_handle import project_closed_error, runtime_project

        project = runtime_project()
        if project is None:  # the human closed this server's project or opened another one (spec §5.1)
            raise project_closed_error()

        def targets_for(program) -> list[dict[str, Any]]:
            bound = []
            for name, session in self._bound_sessions():
                try:
                    candidate = session.get_program()
                except Exception:  # a session a reload is replacing
                    continue
                if candidate is not None and candidate == program:
                    bound.append({"target": name, "revision": self._revision(name, program)})
            return sorted(bound, key=lambda entry: entry["target"])

        return navigation.gui_context(project, targets_for)

    def show_in_gui(self, name: str, *, address: str | None = None, function_name: str | None = None) -> dict:
        from ghidra_headless.gui import navigation
        from ghidra_headless.handlers import core_helpers, core_runtime

        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            raise self._store.missing_session_error(name)
        program = session.get_program()
        handle = session.get_project_handle()
        context = core_runtime._CONTEXTS.get(name)

        def find_function(function: str):
            if context is None:
                raise HeadlessError(f"NOT_FOUND: Function not found: {function}")
            return core_helpers._find_function_by_name(context, function)

        with handle.hold_program(program) as still_open:
            if not still_open:
                raise HeadlessError(
                    f"PROGRAM_NOT_OPEN: target '{name}'s program is no longer open in the Ghidra GUI; "
                    "load it again with load_project_program",
                    details={"reason": "closed_in_gui"},
                )
            # Resolved on this thread before the view changes (spec §8.2, step 2).
            resolved = navigation.resolve_location(
                program, address=address, name=function_name, find_function_by_name=find_function
            )
            return navigation.show_program(
                handle.get_java_project(),
                program,
                address=resolved,
                requested={"address": address, "name": function_name},
                target=name,
            )


__all__ = ["RuntimeGuiOperations"]
