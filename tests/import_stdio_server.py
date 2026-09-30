"""Subprocess fixture: real MCP and locks, event-gated fake analysis only."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from ghidra_mcp.domain.policies import configure_lock_timeout_seconds
from ghidra_mcp.presentation import cli
from ghidra_mcp.presentation.transport import run_mcp_server
from import_operation_support import make_bundle


def main(root, delay_receipt, port=None):
    configure_lock_timeout_seconds(0.03)
    calls = []

    def import_body(binary_path, **options):
        path = "/" + Path(binary_path).name
        file = SimpleNamespace(getPathname=lambda: path)
        files[path] = file
        calls.append(binary_path)
        (root / "started").touch()
        deadline = time.monotonic() + 15
        while not (root / "release").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("test did not release analysis")
            threading.Event().wait(0.005)
        (root / "finished").write_text(json.dumps({"calls": len(calls), "saved": True, "closed": True}))
        return file

    bundle, files, closes = make_bundle(root, import_body)
    manager = bundle.registry.operations
    original_fail_queued = manager._fail_queued_locked

    def shutdown_barrier(error):
        original_fail_queued(error)
        # Main thread is already inside the real shutdown signal guard.
        (root / "shutdown_waiting").touch()

    manager._fail_queued_locked = shutdown_barrier
    original = bundle.runtime.mcp.bindings["import_program"]

    async def delayed(**kwargs):
        receipt = await original.function(**kwargs)
        if delay_receipt:
            # Accept first, then lose only the response to a client timeout.
            await asyncio.sleep(0.3)
        return receipt

    bundle.runtime.mcp.bindings["import_program"] = replace(original, function=delayed)
    try:
        if port is None:
            run_mcp_server(bundle.runtime.mcp, transport="stdio")
        else:
            run_mcp_server(
                bundle.runtime.mcp,
                transport="http",
                host="127.0.0.1",
                port=port,
                stateless_http=True,
                json_response=True,
            )
    finally:
        (root / "shutdown_entered").touch()
        try:
            bundle.registry.close_all()
        finally:
            # Mirror CLI provider teardown, including when an exit signal is re-raised.
            (root / "shutdown_finished").write_text(
                json.dumps(
                    {"worker_alive": manager._thread is not None and manager._thread.is_alive(), "closes": closes}
                )
            )


if __name__ == "__main__":
    cli._run_cli = lambda _argv: main(
        Path(sys.argv[1]), sys.argv[2] == "delay", int(sys.argv[3]) if len(sys.argv) > 3 else None
    )
    sys.exit(cli.main([]))
