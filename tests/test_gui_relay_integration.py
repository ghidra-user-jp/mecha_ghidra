"""Phase 2 acceptance tests (spec §14.3, G40 to G49): relays and the detached Ghidra GUI runtime they start.

Run only with GHIDRA_GUI_VALIDATION=1, a display (macOS, or Linux with Xvfb) and
GHIDRA_INSTALL_DIR; they open Ghidra windows.  pytest itself starts no JVM
here: the relays and the runtime are processes of their own, and the tests
are their MCP clients.  Every test uses a copy of the prepared project, a
throwaway Ghidra settings directory and a registry of its own (HOME and
XDG_STATE_HOME point into the test's directory), and stops the runtimes it
started by pid.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from ghidra_mcp.presentation.gui_registry import ProjectRegistry

ROOT = Path(__file__).resolve().parents[1]
MAIN = "import sys; from ghidra_mcp.cli import main; sys.exit(main())"

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("GHIDRA_GUI_VALIDATION") != "1" or not os.environ.get("GHIDRA_INSTALL_DIR"),
        reason="Run only when GHIDRA_GUI_VALIDATION=1 and GHIDRA_INSTALL_DIR are set (opens Ghidra GUI windows)",
    ),
    pytest.mark.skipif(os.name == "nt", reason="Windows is G50"),
]

READY_SECONDS = 180


def _free_port() -> int:
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        return reserved.getsockname()[1]


class Workspace:
    """A project copy, throwaway settings and a registry of its own; it stops the runtimes it saw."""

    def __init__(self, root: Path, prepared) -> None:
        project_source, settings_source = prepared
        self.root = root
        self.project = root / "project"
        self.settings = root / "settings"
        self.home = root / "home"
        self.state = root / "state"
        shutil.copytree(project_source, self.project)
        shutil.copytree(settings_source, self.settings)
        self.home.mkdir()
        self.state.mkdir()
        directory = (
            (self.home / "Library" / "Application Support" if sys.platform == "darwin" else self.state)
            / "mecha_ghidra"
            / "gui-runtimes"
        )
        self.registry = ProjectRegistry(self.project / "GUI.gpr", directory=directory)
        self.runtime_pids: set[int] = set()
        self.processes: list[subprocess.Popen] = []

    def env(self) -> dict[str, str]:
        """What a client's configuration gives the relay: few variables, as Claude Code and Codex do."""
        env = {
            "HOME": str(self.home),
            "XDG_STATE_HOME": str(self.state),
            "PATH": os.environ.get("PATH", ""),
            "GHIDRA_INSTALL_DIR": os.environ["GHIDRA_INSTALL_DIR"],
            "JAVA_TOOL_OPTIONS": f"-Dapplication.settingsdir={self.settings}",
            "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep),
        }
        for key in ("DISPLAY", "LANG", "LC_ALL"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    def relay_args(self, *extra: str, transport: str = "stdio") -> list[str]:
        return [
            "-c", MAIN, "--backend", "gui", "--transport", transport,
            "--project-location", str(self.project), "--project-name", "GUI",
            "--allowed-project-root", str(self.root), "--domain-path", "/WinHelloCPP.exe", *extra,
        ]  # fmt: skip

    def spawn_relay(self, *extra: str, transport: str = "stdio", **options) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, *self.relay_args(*extra, transport=transport)],
            cwd=self.root,
            env=self.env(),
            **options,
        )
        self.processes.append(process)
        return process

    def record(self):
        record = self.registry.read()
        if record is not None:
            self.runtime_pids.add(record.pid)
        return record

    def runtime_processes(self) -> list[int]:
        """Runtimes of this workspace's project, from the process table."""
        # -ww: Linux's ps cuts a piped line at 80 columns, and the project path is longer.
        listing = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True, text=True).stdout
        pids = []
        for line in listing.splitlines():
            pid, _, command = line.strip().partition(" ")
            if "ghidra_mcp.presentation.gui_runtime" in command and str(self.project) in command:
                pids.append(int(pid))
        self.runtime_pids.update(pids)
        return pids

    def stop(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.wait(10)
        self.runtime_processes()
        for pid in sorted(self.runtime_pids):
            _stop_pid(pid)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _stop_pid(pid: int) -> None:
    """Ghidra's own exit first (the tests leave nothing unsaved), then a kill."""
    if not _alive(pid):
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5  # a test's unsaved change makes Ghidra ask; its project is thrown away
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    if _alive(pid):
        os.kill(pid, signal.SIGKILL)


def _wait_dead(pid: int, seconds: float = 30) -> bool:
    deadline = time.monotonic() + seconds
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    return not _alive(pid)


@pytest.fixture
def workspace(tmp_path, prepared):
    space = Workspace(tmp_path / "w", prepared)
    try:
        yield space
    finally:
        space.stop()


# ---- MCP over a stdio relay --------------------------------------------------------------------


@contextlib.asynccontextmanager
async def session_for(workspace: Workspace, *extra: str):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=workspace.relay_args(*extra), env=workspace.env())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def structured(result) -> dict:
    return result.structured_content or {}


async def call_when_ready(session, name: str, arguments: dict | None = None) -> dict:
    """A tool call, repeated while the runtime is still starting (LOCK_TIMEOUT startup)."""
    deadline = time.monotonic() + READY_SECONDS
    while True:
        content = structured(await session.call_tool(name, arguments or {}))
        error = content.get("error") or {}
        if error.get("code") != "LOCK_TIMEOUT" or (error.get("details") or {}).get("lock") != "startup":
            return content
        assert time.monotonic() < deadline, content
        await asyncio.sleep(1)


def run(coroutine):
    return asyncio.run(coroutine)


# ---- the tests -----------------------------------------------------------------------------------


def _read_line(stream, seconds: float) -> bytes:
    ready, _, _ = select.select([stream], [], [], seconds)
    assert ready, f"no line within {seconds} s"
    return stream.readline()


def test_a_stdio_client_starts_a_detached_runtime_that_outlives_it(workspace):
    """G40, G41: initialize answers within seconds, stdout carries only JSON-RPC, and after stdin's EOF
    the relay ends while the runtime and its GUI stay."""
    relay = workspace.spawn_relay(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "g40", "version": "0"}},
    }
    started = time.monotonic()
    relay.stdin.write((json.dumps(initialize) + "\n").encode())
    relay.stdin.flush()
    first = _read_line(relay.stdout, 30)
    initialize_seconds = time.monotonic() - started
    lines = [first]
    for message in (
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ):
        relay.stdin.write((json.dumps(message) + "\n").encode())
        relay.stdin.flush()
    lines.append(_read_line(relay.stdout, 30))
    record = workspace.record()
    assert record is not None and record.pid != relay.pid
    relay.stdin.close()
    assert relay.wait(20) == 0
    lines.extend(line for line in relay.stdout.read().splitlines() if line.strip())
    replies = [json.loads(line) for line in lines]
    assert all(reply.get("jsonrpc") == "2.0" for reply in replies), lines
    assert [reply.get("id") for reply in replies] == [1, 2]
    assert initialize_seconds < 10, initialize_seconds
    # The runtime runs on in its own session, and the record says so.
    assert _alive(record.pid) and os.getsid(record.pid) == record.pid

    async def still_there():
        async with session_for(workspace) as session:
            return await call_when_ready(session, "get_program_info")

    assert (run(still_there()).get("result") or {}).get("name") == "WinHelloCPP.exe"
    assert workspace.record().state == "ready"


def test_a_second_client_uses_the_same_runtime_and_window(workspace):
    """G42: the same runtime ID, no second Ghidra process, no second CodeBrowser."""

    async def contexts():
        seen = []
        for _ in range(2):
            async with session_for(workspace) as session:
                await call_when_ready(session, "get_program_info")
                context = await call_when_ready(session, "get_gui_context")
                seen.append((workspace.record().runtime_id, len((context.get("result") or {}).get("tools", []))))
        return seen

    first, second = run(contexts())
    assert first == second and first[1] == 1
    assert len(workspace.runtime_processes()) == 1


def test_concurrent_first_starts_make_one_runtime(workspace):
    """G43: relays that start together find or start one runtime between them."""
    relays = [
        workspace.spawn_relay(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)
    ]
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "g43", "version": "0"}},
    }
    for relay in relays:
        relay.stdin.write((json.dumps(initialize) + "\n").encode())
        relay.stdin.flush()
    for relay in relays:
        assert json.loads(_read_line(relay.stdout, 90)).get("id") == 1
    for relay in relays:
        relay.stdin.close()
        relay.wait(20)
    logs = [relay.stderr.read().decode(errors="replace") for relay in relays]
    ids = {line.split("runtime ")[1].split()[0] for log in logs for line in log.splitlines() if "Relaying to" in line}
    assert len(ids) == 1, logs
    assert len(workspace.runtime_processes()) == 1


def test_a_lost_runtime_is_replaced_by_the_next_relay(workspace):
    """G44: after a forced kill, the next relay sees the free lock, clears the old record and starts a runtime
    that opens the project again (Ghidra's lock went with the process)."""

    async def program_name():
        async with session_for(workspace) as session:
            return (await call_when_ready(session, "get_program_info")).get("result", {}).get("name")

    assert run(program_name()) == "WinHelloCPP.exe"
    lost = workspace.record()
    os.kill(lost.pid, signal.SIGKILL)
    assert _wait_dead(lost.pid)
    assert workspace.registry.read().runtime_id == lost.runtime_id  # left behind
    assert not workspace.registry.runtime_alive()
    assert run(program_name()) == "WinHelloCPP.exe"
    replacement = workspace.record()
    assert replacement.runtime_id != lost.runtime_id and replacement.pid != lost.pid


def test_the_runtime_takes_requests_with_its_token_only(workspace):
    """G45: no token and a wrong token are refused; the record's token passes."""

    async def start():
        async with session_for(workspace) as session:
            await call_when_ready(session, "get_program_info")

    run(start())
    record = workspace.record()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    statuses = {}
    for label, token in (("none", None), ("wrong", "not-the-token"), ("right", record.token)):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(record.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                statuses[label] = response.status
        except urllib.error.HTTPError as exc:
            statuses[label] = exc.code
    assert statuses == {"none": 401, "wrong": 401, "right": 200}
    assert record.endpoint.startswith("http://127.0.0.1:")


def test_a_client_with_other_settings_is_refused_or_narrowed(workspace, tmp_path):
    """G46: other path roots are RUNTIME_CONFIG_MISMATCH; a narrower tool set filters tools/list and refuses the rest."""
    other_root = tmp_path / "other-root"
    other_root.mkdir()

    async def scenario():
        async with session_for(workspace) as session:
            await call_when_ready(session, "get_program_info")
        async with session_for(workspace, "--allowed-project-root", str(other_root)) as session:
            mismatch = structured(await session.call_tool("get_program_info", {}))
        async with session_for(workspace, "--tool-profile", "readonly") as session:
            tools = {tool.name for tool in (await session.list_tools()).tools}
            refused = await session.call_tool("show_in_gui", {})
            read = await call_when_ready(session, "get_program_info")
        return mismatch, tools, refused, read

    mismatch, tools, refused, read = run(scenario())
    assert mismatch["error"]["code"] == "RUNTIME_CONFIG_MISMATCH"
    assert mismatch["error"]["details"]["differs"] == ["path_policy"]
    assert "show_in_gui" not in tools and "get_program_info" in tools
    assert refused.is_error and "Unknown or unpublished tool" in json.dumps(refused.model_dump(mode="json"))
    assert read["result"]["name"] == "WinHelloCPP.exe"
    assert len(workspace.runtime_processes()) == 1


def test_stdio_and_http_relays_share_one_runtime(workspace):
    """G47: an HTTP relay beside a stdio one: the same runtime and program, and ending one leaves the other."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    port = _free_port()

    async def scenario():
        async with session_for(workspace) as stdio:
            info = await call_when_ready(stdio, "get_program_info")
            http_relay = workspace.spawn_relay("--mcp-port", str(port), transport="http", stderr=subprocess.PIPE)
            deadline = time.monotonic() + 30
            while True:
                with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
                assert time.monotonic() < deadline, "the HTTP relay did not listen"
                await asyncio.sleep(0.1)
            async with (
                streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write),
                ClientSession(read, write) as http,
            ):
                await http.initialize()
                entry = (await call_when_ready(http, "get_function", {"name": "entry"}))["result"]["entry"]
                edited = await call_when_ready(
                    http,
                    "apply_edits",
                    {"edits": [{"kind": "rename_function", "address": entry, "new_name": "g47_entry"}]},
                )
            seen_by_stdio = await call_when_ready(stdio, "get_function", {"address": entry})
            http_relay.terminate()
            http_relay.wait(20)
            after_http_ended = await call_when_ready(stdio, "get_program_info")
            return info, edited, seen_by_stdio, after_http_ended

    info, edited, seen, after = run(scenario())
    assert info["result"]["name"] == "WinHelloCPP.exe"
    assert edited["result"]["status"] == "applied"
    assert seen["result"]["name"] == "g47_entry"
    assert after["result"]["name"] == "WinHelloCPP.exe"
    assert len(workspace.runtime_processes()) == 1


def test_a_crash_during_a_call_is_an_unknown_outcome_and_no_restart(workspace):
    """G48: a write in flight when the runtime dies is RUNTIME_UNAVAILABLE with outcome unknown (output_state
    uncertain); later calls say the runtime is gone, and the relay starts none."""

    async def scenario():
        async with session_for(workspace) as session:
            # The runtime is still starting: the write waits on its startup gate, in flight.
            pending = asyncio.ensure_future(session.call_tool("create_label", {"address": "0x401000", "name": "g48"}))
            deadline = time.monotonic() + 30
            while workspace.record() is None:
                assert time.monotonic() < deadline
                await asyncio.sleep(0.1)
            await asyncio.sleep(1.5)
            pid = workspace.record().pid
            os.kill(pid, signal.SIGKILL)
            in_flight = structured(await pending)
            later = structured(await session.call_tool("get_program_info", {}))
            return pid, in_flight, later

    pid, in_flight, later = run(scenario())
    assert _wait_dead(pid)
    assert in_flight["error"]["code"] == "RUNTIME_UNAVAILABLE"
    assert in_flight["error"]["details"]["outcome"] == "unknown"
    assert in_flight["error"]["details"]["output_state"] == "uncertain"
    assert later["error"]["code"] == "RUNTIME_UNAVAILABLE" and later["error"]["details"]["reason"] == "runtime_gone"
    assert workspace.runtime_processes() == []


def test_a_resend_through_a_new_relay_gets_the_first_reply(workspace):
    """G49: the runtime keeps request_id records across relays; get_operation goes through a relay too."""
    arguments = {"address": "0x401000", "name": "g49", "request_id": "3f0a7c1e-49b0-4c8e-9a51-2d6f8b0e1c49"}

    async def scenario():
        async with session_for(workspace) as first:
            original = await call_when_ready(first, "create_label", arguments)
        async with session_for(workspace) as second:
            resent = structured(await second.call_tool("create_label", arguments))
            missing = structured(await second.call_tool("get_operation", {"operation_id": str(uuid.uuid4())}))
        return original, resent, missing

    original, resent, missing = run(scenario())
    assert "error" not in original, original
    assert resent.get("replayed") is True
    assert resent.get("result") == original.get("result")
    assert missing["error"]["code"] == "OPERATION_NOT_FOUND"
