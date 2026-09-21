"""Runtime side of Ghidra script execution.

Scripts run inside the server JVM against the loaded program, the way the
Ghidra Script Manager runs them: the internal ``run_script`` core command wraps
the run in an outer transaction and rolls it back when the script fails.  The
call takes the process-wide script barrier and the runtime-wide exclusive
barrier, so no other tool touches the program while a script runs.

A script that leaves a transaction open or work running makes the program
state unverifiable; the target is then quarantined (``execution_state=invalid``)
until ``close_session(discard_changes=true)`` and a reload.
"""

from __future__ import annotations

from typing import Any, Dict

from ghidra_mcp.application.locks import SCRIPT_BARRIER

from .core_execution import RuntimeCoreExecution
from .session_store import RuntimeSessionStore


class RuntimeScriptExecution:
    def __init__(self, *, store: RuntimeSessionStore, core_execution: RuntimeCoreExecution) -> None:
        self._store = store
        self._core_execution = core_execution

    def script_runtime_availability(self) -> Dict[str, bool]:
        from ghidra_headless.scripts import providers

        with SCRIPT_BARRIER.read_lock():
            return providers.runtime_availability()

    def run_script(self, name: str, *, request: Dict[str, Any]) -> Dict[str, Any]:
        return self._core_execution.call("run_script", dict(request), target=name, exclusive=True)


__all__ = ["RuntimeScriptExecution"]
