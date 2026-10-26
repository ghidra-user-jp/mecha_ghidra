"""Deferred calls over the real stdio and Streamable HTTP transports, in a subprocess."""

from __future__ import annotations

import asyncio
import contextlib
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


async def wait_and_collect_progress(client, root):
    """A call that runs for a moment, sent with a progress callback: what it reported, and its reply."""
    reports = []

    async def on_progress(progress, total, message):
        reports.append((progress, message))

    async def release_soon():
        await wait_file(root / "started")
        await asyncio.sleep(0.4)
        (root / "release").touch()

    releasing = asyncio.ensure_future(release_soon())
    with anyio.fail_after(10):
        reply = await client.call_tool("decompile_function", DECOMPILE, progress_callback=on_progress)
    await releasing
    assert not reply.is_error and reply.structured_content == {"result": PSEUDOCODE}, reply
    values = [progress for progress, _ in reports]
    assert len(values) >= 3 and values == sorted(set(values)), reports
    assert {message for _, message in reports} == {"decompile_function: running"}
    await asyncio.sleep(0.2)
    assert len(reports) == len(values), "nothing follows the reply"


async def cancel_a_running_read(client, root):
    """Give up on a decompile while it runs: the server stops it, and goes on serving."""
    call = asyncio.ensure_future(client.call_tool("decompile_function", DECOMPILE))
    await wait_file(root / "started")
    call.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await call
    await wait_file(root / "cancelled", timeout=5)
    assert not (root / "finished").exists(), "the read was stopped, not run to its end"
    # The worker slot and the lock are free again.
    (root / "release").touch()
    with anyio.fail_after(5):
        reply = await client.call_tool("decompile_function", DECOMPILE)
    assert reply.structured_content == {"result": PSEUDOCODE}


def test_a_deferred_call_over_stdio(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path)])

    async def scenario():
        async with Client(params, read_timeout_seconds=5) as client:
            await defer_then_collect(client, tmp_path)

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_a_waiting_call_reports_progress_over_stdio(tmp_path, mode):
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path), "--defer-after", "8"])

    async def scenario():
        async with Client(params, mode=mode, read_timeout_seconds=10) as client:
            await wait_and_collect_progress(client, tmp_path)

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


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_cancelling_a_read_stops_it_over_stdio(tmp_path, mode):
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path), "--defer-after", "8"])

    async def scenario():
        async with Client(params, mode=mode, read_timeout_seconds=10) as client:
            await cancel_a_running_read(client, tmp_path)

    asyncio.run(scenario())


@contextlib.contextmanager
def serving_http(root, *extra):
    """The fixture server on a free loopback port; yields its URL once it accepts connections."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"

    async def wait_until_listening():
        with anyio.fail_after(5):
            while True:
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.01)

    with (root / "http.stderr").open("w") as log:
        process = subprocess.Popen([sys.executable, SERVER, str(root), str(port), *extra], stdout=log, stderr=log)
        try:
            asyncio.run(wait_until_listening())
            yield url
        finally:
            (root / "release").touch()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.returncode not in (0, -15, 143):
                pytest.fail((root / "http.stderr").read_text())


def test_a_deferred_call_over_http(tmp_path):
    async def scenario(url):
        async with Client(url, read_timeout_seconds=5) as client:
            await defer_then_collect(client, tmp_path)

    with serving_http(tmp_path) as url:
        asyncio.run(scenario(url))


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_a_waiting_call_reports_progress_over_http(tmp_path, mode):
    """The reply becomes an event stream only because the client sent a progressToken and the call waited."""

    async def scenario(url):
        async with Client(url, mode=mode, read_timeout_seconds=10) as client:
            await wait_and_collect_progress(client, tmp_path)

    with serving_http(tmp_path, "--defer-after", "8") as url:
        asyncio.run(scenario(url))


def test_cancelling_a_read_stops_it_over_http(tmp_path):
    """On the 2026-07-28 wire the SDK client cancels a request by closing its connection.

    On the earlier wire it posts notifications/cancelled instead, which a stateless server cannot match to the
    request, so only a client that closes the connection stops a read there (the next test).
    """

    async def scenario(url):
        async with Client(url, read_timeout_seconds=10) as client:
            await cancel_a_running_read(client, tmp_path)

    with serving_http(tmp_path, "--defer-after", "8") as url:
        asyncio.run(scenario(url))


@pytest.mark.parametrize("wire", ["2026-07-28", "2025-11-25"])
def test_a_dropped_http_connection_stops_the_read_on_both_wires(tmp_path, wire):
    import httpx2

    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": wire}
    params = {"name": "decompile_function", "arguments": DECOMPILE}
    if wire == "2026-07-28":
        headers |= {"Mcp-Method": "tools/call", "Mcp-Name": "decompile_function"}
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": wire,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}

    async def scenario(url):
        async with httpx2.AsyncClient(trust_env=False, timeout=30) as client:
            request = asyncio.ensure_future(client.post(url, json=body, headers=headers))
            await wait_file(tmp_path / "started")
            request.cancel()  # httpx closes the connection
            with contextlib.suppress(asyncio.CancelledError):
                await request
            await wait_file(tmp_path / "cancelled", timeout=5)
        assert not (tmp_path / "finished").exists()

    with serving_http(tmp_path, "--defer-after", "8") as url:
        asyncio.run(scenario(url))
