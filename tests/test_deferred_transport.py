"""Deferred calls over the real stdio and Streamable HTTP transports, in a subprocess."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from mcp import Client, StdioServerParameters

from deferred_transport_server import PSEUDOCODE

SERVER = str(Path(__file__).with_name("deferred_transport_server.py"))
DECOMPILE = {"target": "default", "address": "0x1000"}


async def wait_file(path, timeout=5):
    with anyio.fail_after(timeout):
        while not path.exists():
            await asyncio.sleep(0.005)


async def defer_then_collect(client, root):
    reply = await client.call_tool("decompile_function", DECOMPILE)
    assert not reply.is_error and reply.structured_content["deferred"] is True, reply
    operation_id = reply.structured_content["operation"]["operation_id"]
    await wait_file(root / "started")
    (root / "release").touch()
    with anyio.fail_after(5):
        status = await client.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 4})
    record = status.structured_content["result"]
    assert record["state"] == "succeeded" and record["result"] == PSEUDOCODE


def test_a_deferred_call_over_stdio(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path)])

    async def scenario():
        async with Client(params, read_timeout_seconds=5) as client:
            await defer_then_collect(client, tmp_path)

    asyncio.run(scenario())


def test_stdio_eof_waits_for_a_deferred_call_before_closing(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path)])

    async def scenario():
        async with Client(params, read_timeout_seconds=5) as client:
            reply = await client.call_tool("decompile_function", DECOMPILE)
            assert reply.structured_content["deferred"] is True
            await wait_file(tmp_path / "started")
            # Released only after the client has closed stdin and the server started stopping.
            asyncio.get_running_loop().call_later(0.5, (tmp_path / "release").touch)
        await wait_file(tmp_path / "shutdown_finished")

    asyncio.run(scenario())
    entered = (tmp_path / "shutdown_entered").stat().st_mtime_ns
    finished = (tmp_path / "finished").stat().st_mtime_ns
    closed = (tmp_path / "shutdown_finished").stat().st_mtime_ns
    # The server stopped serving first, then waited for the call before closing Ghidra.
    assert entered <= finished <= closed


def test_a_deferred_call_over_http(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"

    async def scenario():
        with anyio.fail_after(5):
            while True:
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.01)
        async with Client(url, read_timeout_seconds=5) as client:
            await defer_then_collect(client, tmp_path)

    with (tmp_path / "http.stderr").open("w") as log:
        process = subprocess.Popen([sys.executable, SERVER, str(tmp_path), str(port)], stdout=log, stderr=log)
        try:
            asyncio.run(scenario())
        finally:
            (tmp_path / "release").touch()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.returncode not in (0, -15, 143):
                pytest.fail((tmp_path / "http.stderr").read_text())
