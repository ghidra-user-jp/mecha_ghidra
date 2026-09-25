"""Subprocess fixture: the real CLI over stdio or HTTP, with a JVM start that only takes time."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.startup import STARTUP_THREAD_NAME

JVM_SECONDS = 1.5
CORE = SimpleNamespace(clear_contexts=lambda: None)


def main(root: Path, mode: str, port: int | None = None) -> int:
    def start_jvm(_ghidra_path, _launcher):
        (root / "jvm_started").touch()
        time.sleep(JVM_SECONDS)
        (root / "jvm_finished").touch()
        if mode == "fail":
            raise ValueError("Java was not found")

    def core():
        # The last startup step loads the core; closing the runtime uses it too.
        if threading.current_thread().name == STARTUP_THREAD_NAME:
            (root / "core_loaded").touch()
        return CORE

    cli._prepare_pyghidra_headless = lambda _path: None
    cli._start_pyghidra_headless = start_jvm
    cli.redirect_java_stdout_to_stderr = lambda: None
    # Only the signal half: without a JVM there is no thread to attach.
    cli._prepare_event_loop_thread = cli._rearm_python_signals
    cli.detach_current_thread = lambda: None
    cli._core = core
    if port is None:
        transport = ["--transport", "stdio"]
    else:
        transport = ["--transport", "http", "--mcp-host", "127.0.0.1", "--mcp-port", str(port)]
    return cli.main(["--project-location", str(root), "--project-name", "t", *transport])


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else None))
