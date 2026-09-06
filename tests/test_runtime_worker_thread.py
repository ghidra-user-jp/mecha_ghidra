"""Real-Ghidra check that tool work survives being run from a worker thread.

mcp 2.x executes synchronous tool handlers in worker threads.  On macOS the
first AWT initialization from a non-main thread blocks forever unless the JVM
was started with ``-Djava.awt.headless=true``; this test exercises the actual
import path from a thread and fails instead of hanging.
"""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import pytest

from ghidra_mcp import cli
from test_runtime_readonly_commands import (
    _ensure_project_created,
    _resolve_runtime_binary_path,
    _start_pyghidra_if_needed,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)

_WORKER_TIMEOUT_SECONDS = 300.0


def test_import_and_decompile_from_worker_thread_do_not_block(tmp_path: Path):
    _start_pyghidra_if_needed()
    from java.awt import GraphicsEnvironment

    assert bool(GraphicsEnvironment.isHeadless()), "JVM must run headless so worker threads can touch AWT"

    binary_path = _resolve_runtime_binary_path()
    target = f"worker_{uuid.uuid4().hex[:8]}"
    project_dir = tmp_path / "worker_project"
    _ensure_project_created(project_dir, "worker_validation")
    outcome: dict[str, object] = {}

    def work() -> None:
        try:
            cli.register_target(target=target, project_location=str(project_dir), project_name="worker_validation")
            imported = cli.import_program(target=target, binary_path=binary_path, analyze_imported=True)
            cli.load_project_program(target=target, domain_path=imported["program"])
            functions = cli.list_functions(offset=0, limit=1, target=target)
            outcome["decompiled"] = cli.decompile_function(name=functions[0]["name"], target=target)
        except Exception as exc:  # pragma: no cover - surfaced through the assertion below
            outcome["error"] = exc

    thread = threading.Thread(target=work, name="mcp-worker-probe", daemon=True)
    thread.start()
    thread.join(timeout=_WORKER_TIMEOUT_SECONDS)
    try:
        assert not thread.is_alive(), "worker thread is still blocked after the timeout (AWT/main-thread deadlock?)"
        assert "error" not in outcome, outcome.get("error")
        assert isinstance(outcome.get("decompiled"), str) and outcome["decompiled"]
    finally:
        if not thread.is_alive():
            try:
                cli.close_session(target)
            except Exception:
                pass
