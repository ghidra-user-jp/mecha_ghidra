"""Subprocess fixture: the real MCP transport and deferral, with a core command gated by files."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

from ghidra_mcp.application.services.operations import OperationManager
from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.transport import run_mcp_server

PSEUDOCODE = "int main(void) { return 0; }"


class Targets:
    def project_key(self, target):
        return "/project::test"


class Registry:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.operations = OperationManager(Targets())

    def call(self, command, params, target):
        (self.root / "started").touch()
        deadline = time.monotonic() + 15
        while not (self.root / "release").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("test did not release the call")
            threading.Event().wait(0.005)
        (self.root / "finished").touch()
        return PSEUDOCODE

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds=0):
        return self.operations.get(operation_id=operation_id, request_id=request_id)


def main(root: Path, port: int | None = None) -> int:
    registry = Registry(root)
    runtime = create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("decompile_function", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
    )
    runtime.mcp.deferred_calls.defer_after = 0.2
    try:
        if port is None:
            run_mcp_server(runtime.mcp, transport="stdio")
        else:
            run_mcp_server(
                runtime.mcp,
                transport="http",
                host="127.0.0.1",
                port=port,
                stateless_http=True,
                json_response=True,
            )
    finally:
        (root / "shutdown_entered").touch()
        # What close_all does first: wait for calls still running on their threads.
        registry.operations.shutdown()
        (root / "shutdown_finished").touch()
    return 0


if __name__ == "__main__":
    cli._run_cli = lambda _argv: main(Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else None)
    sys.exit(cli.main([]))
