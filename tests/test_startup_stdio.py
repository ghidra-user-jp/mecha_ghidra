"""Serving before Ghidra is up, over the real CLI and its transports, in a subprocess without a JVM."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ghidra_mcp.presentation.cli_runtime import SHUTDOWN_SIGNALS

SERVER = Path(__file__).with_name("startup_stdio_server.py")
ROOT = Path(__file__).resolve().parents[1]


class Server:
    def __init__(self, proc, log):
        self.proc = proc
        self.log = log

    async def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        await self.proc.stdin.drain()

    async def reply(self, expected_id):
        while True:
            line = await asyncio.wait_for(self.proc.stdout.readline(), 30)
            assert line, self.log.read_text()
            value = json.loads(line)
            if value.get("id") == expected_id:
                return value

    async def initialize(self):
        await self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "startup-test", "version": "1"},
                },
            }
        )
        reply = await self.reply(1)
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return reply

    async def call(self, request_id, name):
        await self.send(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": {}}}
        )
        return (await self.reply(request_id))["result"]

    async def exit_code(self):
        return await asyncio.wait_for(self.proc.wait(), 30)


def _run(tmp_path, mode, scenario):
    log = tmp_path / "server.log"
    env = dict(os.environ)
    env.pop("GHIDRA_INSTALL_DIR", None)

    async def main():
        with log.open("w") as stderr:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(SERVER),
                str(tmp_path),
                mode,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                env=env,
                cwd=ROOT,
            )
        try:
            return await scenario(Server(proc, log))
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    return asyncio.run(main())


def test_initialize_answers_before_the_jvm_is_up_and_a_call_waits_for_it(tmp_path):
    async def scenario(server):
        await server.initialize()
        # The JVM step is still running: the handshake did not wait for it.
        assert not (tmp_path / "jvm_finished").exists()
        result = await server.call(2, "list_targets")
        assert not result.get("isError"), result
        assert (tmp_path / "core_loaded").exists()
        server.proc.stdin.close()
        return await server.exit_code()

    assert _run(tmp_path, "ok", scenario) == 0
    assert "Ghidra ready in" in (tmp_path / "server.log").read_text()


def test_a_failed_startup_answers_every_call_and_exits_1_when_the_client_leaves(tmp_path):
    async def scenario(server):
        await server.initialize()
        result = await server.call(2, "list_targets")
        error = result["structuredContent"]["error"]
        assert result["isError"] and error["code"] == "STARTUP_FAILED"
        assert "Java was not found" in error["message"]
        # The server stays up and keeps answering until the client disconnects.
        again = await server.call(3, "list_targets")
        assert again["structuredContent"]["error"]["code"] == "STARTUP_FAILED"
        server.proc.stdin.close()
        return await server.exit_code()

    assert _run(tmp_path, "fail", scenario) == 1
    assert "Failed to start the Ghidra JVM: Java was not found" in (tmp_path / "server.log").read_text()


def _signal_name(signum):
    return signal.Signals(signum).name


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("signum", SHUTDOWN_SIGNALS, ids=_signal_name)
def test_a_shutdown_signal_during_the_startup_waits_for_the_step_and_exits_with_stdin_open(tmp_path, signum):
    async def scenario(server):
        await server.initialize()
        while not (tmp_path / "jvm_started").exists():
            await asyncio.sleep(0.01)
        sent = time.monotonic()
        # stdin stays open: the signal, not EOF, has to end the process.
        server.proc.send_signal(signum)
        code = await server.exit_code()
        return code, time.monotonic() - sent

    code, elapsed = _run(tmp_path, "ok", scenario)
    assert code == 128 + signum
    # The JVM step could not be interrupted, and the steps after it did not run.
    assert (tmp_path / "jvm_finished").exists() and not (tmp_path / "core_loaded").exists()
    assert elapsed < 20
    assert "Waiting for the Ghidra startup step in progress" in (tmp_path / "server.log").read_text()


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("signum", SHUTDOWN_SIGNALS, ids=_signal_name)
def test_a_shutdown_signal_after_the_startup_exits_with_stdin_open(tmp_path, signum):
    async def scenario(server):
        await server.initialize()
        result = await server.call(2, "list_targets")
        assert not result.get("isError"), result
        sent = time.monotonic()
        # SIGINT used to leave the process waiting for its stdin reader forever.
        server.proc.send_signal(signum)
        code = await server.exit_code()
        return code, time.monotonic() - sent

    code, elapsed = _run(tmp_path, "ok", scenario)
    assert code == 128 + signum
    assert elapsed < 20
    assert f"Received {_signal_name(signum)}" in (tmp_path / "server.log").read_text()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_sighup_over_http_shuts_down_as_gracefully_as_sigterm(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    log = tmp_path / "server.log"
    env = dict(os.environ)
    env.pop("GHIDRA_INSTALL_DIR", None)
    with log.open("w") as stderr:
        proc = subprocess.Popen(
            [sys.executable, str(SERVER), str(tmp_path), "ok", str(port)], stderr=stderr, env=env, cwd=ROOT
        )
    try:
        deadline = time.monotonic() + 30
        while "Ghidra ready in" not in log.read_text():
            assert proc.poll() is None and time.monotonic() < deadline, log.read_text()
            time.sleep(0.02)
        proc.send_signal(signal.SIGHUP)
        code = proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    text = log.read_text()
    assert code == 128 + signal.SIGHUP, text
    # uvicorn's graceful shutdown ran before the CLI's cleanup, as it does for SIGTERM.
    assert "Shutting down" in text and "Application shutdown complete" in text
    assert text.index("Finished server process") < text.index("Received SIGHUP")


def test_eof_during_the_startup_skips_the_remaining_steps(tmp_path):
    async def scenario(server):
        await server.initialize()
        server.proc.stdin.close()
        return await server.exit_code()

    assert _run(tmp_path, "ok", scenario) == 0
    assert (tmp_path / "jvm_finished").exists() and not (tmp_path / "core_loaded").exists()
    assert "Ghidra startup stopped" in (tmp_path / "server.log").read_text()
