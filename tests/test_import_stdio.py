from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path
from uuid import uuid4

import anyio
import pytest
from mcp import Client, MCPError, StdioServerParameters

SERVER = str(Path(__file__).with_name("import_stdio_server.py"))


async def wait_file(path):
    with anyio.fail_after(5):
        while not path.exists():
            await asyncio.sleep(0.005)


@pytest.mark.parametrize("deadline", [0.04, 0.1])
def test_stdio_timeout_after_acceptance_can_recover_by_request_id(tmp_path, deadline):
    request_id = str(uuid4())
    args = {
        "target": "default",
        "binary_path": str(tmp_path / "benign.bin"),
        "request_id": request_id,
        "analyze_imported": True,
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER, str(tmp_path), "delay"])

    async def scenario():
        async with Client(params, read_timeout_seconds=3) as client:
            try:
                with pytest.raises(MCPError) as timeout:
                    await client.call_tool("import_program", args, read_timeout_seconds=deadline)
                assert "tim" in str(timeout.value).lower()
                await wait_file(tmp_path / "started")
                # Same MCP session processes another request while import holds target locks.
                status = await client.call_tool("get_operation", {"request_id": request_id, "wait_seconds": 0})
                operation = status.structured_content["result"]
                assert operation["state"] == "running"
                # The import holds the target locks; list_targets answers without them.
                targets = await client.call_tool("list_targets", {})
                assert not targets.is_error
                replay = await client.call_tool("import_program", {**args, "wait_seconds": 0})
                assert replay.structured_content["result"]["operation_id"] == operation["operation_id"]
                assert replay.structured_content["result"]["replayed"]
            finally:
                (tmp_path / "release").touch()
            with anyio.fail_after(5):
                status = await client.call_tool("get_operation", {"request_id": request_id, "wait_seconds": 4})
            operation = status.structured_content["result"]
            assert operation["state"] == "succeeded"
            assert operation["result"]["program"] == "/benign.bin"
            assert json.loads((tmp_path / "finished").read_text()) == {"calls": 1, "saved": True, "closed": True}
        await wait_file(tmp_path / "shutdown_finished")

    asyncio.run(scenario())


@pytest.mark.parametrize("exit_signal", [None, signal.SIGTERM, signal.SIGINT])
def test_stdio_eof_joins_worker_before_project_close(tmp_path, exit_signal):
    if exit_signal is not None and os.name == "nt":
        pytest.skip("POSIX subprocess signals; Windows EOF is covered separately")

    async def scenario():
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            SERVER,
            str(tmp_path),
            "immediate",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )

        async def send(message):
            proc.stdin.write((json.dumps(message) + "\n").encode())
            await proc.stdin.drain()

        async def reply(expected_id):
            with anyio.fail_after(5):
                while True:
                    line = await proc.stdout.readline()
                    assert line, "MCP subprocess ended without responding"
                    value = json.loads(line)
                    if value.get("id") == expected_id:
                        assert "error" not in value, value
                        return value["result"]

        try:
            await send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "import-test", "version": "1"},
                    },
                }
            )
            await reply(1)
            await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            await send(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "import_program",
                        "arguments": {
                            "target": "default",
                            "binary_path": str(tmp_path / "benign.bin"),
                            "wait_seconds": 0,
                        },
                    },
                }
            )
            accepted = await reply(2)
            assert accepted["structuredContent"]["result"]["state"] in {"queued", "running"}
            await wait_file(tmp_path / "started")
            proc.stdin.close()
            await wait_file(tmp_path / "shutdown_entered")
            await wait_file(tmp_path / "shutdown_waiting")
            if exit_signal is not None:
                proc.send_signal(exit_signal)
                await asyncio.sleep(0.05)
            assert proc.returncode is None
            assert not (tmp_path / "shutdown_finished").exists()
            (tmp_path / "release").touch()
            code = await asyncio.wait_for(proc.wait(), 5)
            assert (code == 0) is (exit_signal is None)
            assert (tmp_path / "finished").exists() and (tmp_path / "shutdown_finished").exists()
            assert json.loads((tmp_path / "shutdown_finished").read_text()) == {
                "worker_alive": False,
                "closes": ["closed"],
            }
        finally:
            (tmp_path / "release").touch()
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    asyncio.run(scenario())


def test_http_disconnect_can_reconnect_and_retrieve_same_operation(tmp_path):
    import socket
    import subprocess

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    args = {
        "target": "default",
        "binary_path": str(tmp_path / "benign.bin"),
        "request_id": str(uuid4()),
        "analyze_imported": True,
    }
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
        async with Client(url, read_timeout_seconds=3) as first:
            with pytest.raises(MCPError):
                await first.call_tool("import_program", args, read_timeout_seconds=0.05)
        await wait_file(tmp_path / "started")
        async with Client(url, read_timeout_seconds=3) as second:
            status = await second.call_tool("get_operation", {"request_id": args["request_id"], "wait_seconds": 0})
            operation = status.structured_content["result"]
            assert operation["state"] == "running"
            replay = await second.call_tool("import_program", {**args, "wait_seconds": 0})
            receipt = replay.structured_content["result"]
            assert receipt["replayed"] and receipt["operation_id"] == operation["operation_id"]
            assert receipt["server_instance_id"] == operation["server_instance_id"]
            (tmp_path / "release").touch()
            with anyio.fail_after(5):
                status = await second.call_tool(
                    "get_operation", {"operation_id": receipt["operation_id"], "wait_seconds": 4}
                )
            assert status.structured_content["result"]["state"] == "succeeded"
            assert json.loads((tmp_path / "finished").read_text())["calls"] == 1

    with (tmp_path / "http.stderr").open("w") as log:
        process = subprocess.Popen([sys.executable, SERVER, str(tmp_path), "delay", str(port)], stdout=log, stderr=log)
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
