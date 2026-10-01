"""Subprocess fixture: the real MCP transport and deferral, with a core command gated by files."""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from pathlib import Path

from ghidra_mcp.application.cancellation import current_call_cancellation
from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation import cli, progress
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.transport import run_mcp_server, streamable_http_run_kwargs

PSEUDOCODE = "int main(void) { return 0; }"


class Targets:
    def project_key(self, target):
        return "/project::test"


class Registry:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.operations = OperationManager(Targets())

    def call(self, command, params, target):
        cancellation = current_call_cancellation()
        (self.root / "started").touch()
        deadline = time.monotonic() + 15
        while not (self.root / "release").exists():
            if cancellation is not None and cancellation.cancelled:
                # What the runtime does through the call's Ghidra monitor when its request was cancelled.
                (self.root / "cancelled").touch()
                raise RuntimeError("the request was cancelled")
            if time.monotonic() > deadline:
                raise RuntimeError("test did not release the call")
            threading.Event().wait(0.005)
        (self.root / "finished").touch()
        return PSEUDOCODE

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)


def main(root: Path, port: int | None = None, defer_after: float = 0.2) -> int:
    progress.INTERVAL_SECONDS = 0.05  # a call that waits a moment reports a few times
    registry = Registry(root)
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("decompile_function", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    runtime.mcp.deferred_calls.defer_after = defer_after
    try:
        if port is None:
            run_mcp_server(runtime.mcp, transport="stdio")
        else:
            # The options ``mecha_ghidra --transport http`` serves with.
            options = argparse.Namespace(mcp_host="127.0.0.1", mcp_port=port, mcp_path="/mcp", log_level="WARNING")
            run_kwargs = streamable_http_run_kwargs(args=options, logger=logging.getLogger("test"), announce=False)
            run_mcp_server(runtime.mcp, transport="http", **run_kwargs)
    finally:
        (root / "shutdown_entered").touch()
        # What close_all does first: wait for calls still running on their threads.
        registry.operations.shutdown()
        (root / "shutdown_finished").touch()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("port", type=int, nargs="?")
    parser.add_argument("--defer-after", type=float, default=0.2)
    arguments = parser.parse_args()
    cli._run_cli = lambda _argv: main(arguments.root, arguments.port, arguments.defer_after)
    sys.exit(cli.main([]))
