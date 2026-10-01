"""Subprocess fixture: the relay's stdio loop in front of a scripted runtime (no JVM, no network)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from ghidra_mcp.contracts.tool_spec import filter_tool_specs
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.gui_relay import KEEPALIVE, Answer, Fallback, Relay, serve_stdio


class Runtime:
    """Answers a tool call after three reports, a ping between them, like a runtime whose call waits."""

    record = SimpleNamespace(runtime_id="r1", token="t")

    def __init__(self, marker: Path | None = None) -> None:
        self.marker = marker

    @contextlib.asynccontextmanager
    async def post(self, body: bytes, routing):
        message = json.loads(body)
        method = message.get("method")
        hangs = bool(((message.get("params") or {}).get("arguments") or {}).get("hang"))
        try:
            async with self._answer(message, method, hangs) as answer:
                yield answer
        finally:
            if hangs and self.marker is not None:
                self.marker.touch()  # the relay closed its request while the call was still running

    @contextlib.asynccontextmanager
    async def _answer(self, message, method, hangs):

        async def messages():
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "serverInfo": {"name": "r", "version": "1"},
                }
                yield {"jsonrpc": "2.0", "id": message["id"], "result": result}
            elif method == "tools/call" and hangs:
                token = message["params"]["_meta"]["progressToken"]
                params = {"progressToken": token, "progress": 1, "message": "running"}
                yield {"jsonrpc": "2.0", "method": "notifications/progress", "params": params}
                await asyncio.Event().wait()  # a call that never ends: only its cancellation stops it
            elif method == "tools/call":
                token = message["params"]["_meta"]["progressToken"]
                for step in (1, 2, 3):
                    await asyncio.sleep(0.05)
                    params = {"progressToken": token, "progress": step, "message": "running"}
                    yield {"jsonrpc": "2.0", "method": "notifications/progress", "params": params}
                    if step == 2:
                        yield KEEPALIVE
                await asyncio.sleep(0.05)
                reply = {"content": [], "structuredContent": {"result": {"from": "runtime"}}}
                yield {"jsonrpc": "2.0", "id": message["id"], "result": reply}

        yield Answer(202 if "id" not in message else 200, messages())


async def main() -> None:
    specs = filter_tool_specs(backend="gui")
    fallback = Fallback(specs, ToolPresentationConfig())
    marker = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    async with fallback.running():
        await serve_stdio(Relay(specs=specs, fallback=fallback, runtime=Runtime(marker), refusal=None))


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
