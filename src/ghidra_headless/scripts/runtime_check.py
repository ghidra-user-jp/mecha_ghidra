"""Verify the upstream script runner without replacing PyGhidra internals."""

from __future__ import annotations

import contextlib
import tempfile
import uuid
from importlib.metadata import version
from pathlib import Path

import jpype

from ghidra_headless.errors import HeadlessError
from ghidra_headless.scripts import providers
from ghidra_headless.scripts.capture import BoundedCapture

_state: dict = {"probe_ok": None, "probe_error": "not checked", "pyghidra_version": None}


def runtime_check_state() -> dict:
    return dict(_state)


def require_script_runtime_ready() -> None:
    """Guard every language: Java/Jython parents can invoke PyGhidra children."""
    if _state["probe_ok"] is not True:
        raise HeadlessError(
            f"SCRIPT_RUNTIME_UNAVAILABLE: script exception propagation is not verified: {_state['probe_error']}",
            details=runtime_check_state(),
        )


def probe_exception_propagation(probe_dir: Path) -> bool:
    """Run a raising script through the standard provider once per JVM.

    Called under the application's script barrier. Fail closed on swallowed or
    unexpected exceptions; never patch, reflect into, or subclass PyGhidra internals.
    """
    try:
        providers.ensure_bundle_host()
        if _state["probe_ok"] is not None:
            return bool(_state["probe_ok"])
        _state.update(probe_ok=False, probe_error="probe did not complete")
        _state["pyghidra_version"] = version("pyghidra")
        provider = providers.provider_for(providers.RUNTIME_PYGHIDRA)
        probe_dir.mkdir(parents=True, exist_ok=True)
        with (
            tempfile.TemporaryDirectory(prefix="propagation-", dir=probe_dir) as directory,
            contextlib.ExitStack() as stack,
        ):
            token = "mecha_propagation_probe_" + uuid.uuid4().hex
            path = Path(directory) / "probe.py"
            path.write_text(f'# @runtime PyGhidra\nraise RuntimeError("{token}")\n', encoding="utf-8")
            out = BoundedCapture(4096)
            stack.callback(out.writer.close)
            err = BoundedCapture(4096)
            stack.callback(err.writer.close)
            source = jpype.JClass("generic.jar.ResourceFile")(str(path))
            script = provider.getScriptInstance(source, err.writer)
            state = jpype.JClass("ghidra.app.script.GhidraState")(None, None, None, None, None, None)
            controls = jpype.JClass("ghidra.app.script.ScriptControls")(
                out.writer, err.writer, jpype.JClass("ghidra.util.task.TaskMonitor").DUMMY
            )
            try:
                script.execute(state, controls)
            except BaseException as exc:
                if token not in str(exc):
                    raise RuntimeError(f"unexpected propagation probe exception: {exc}") from exc
            else:
                raise RuntimeError("PyGhidra swallowed the script exception; install the pinned upstream dependency")
        _state.update(probe_ok=True, probe_error=None)
    except Exception as exc:
        _state.update(probe_ok=False, probe_error=str(exc))
    return bool(_state["probe_ok"])
