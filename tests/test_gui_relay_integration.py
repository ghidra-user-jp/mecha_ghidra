"""Phase 2 acceptance tests (spec §14.3, G40 to G50): relays and the detached Ghidra GUI runtime they start.

Run only with GHIDRA_GUI_VALIDATION=1, a display (macOS, Windows, or Linux with
Xvfb) and GHIDRA_INSTALL_DIR; they open Ghidra windows.  pytest itself starts
no JVM here: the relays and the runtime are processes of their own, and the
tests are their MCP clients.  Every test uses a copy of the prepared project, a
throwaway Ghidra settings directory and a registry of its own (HOME,
XDG_STATE_HOME and, on Windows, LOCALAPPDATA point into the test's directory),
and stops the runtimes it started by pid.

On Windows the MCP Python SDK starts a stdio server in a job object that
forbids breaking away, so no relay it starts can detach a runtime (G50's
refusal).  The relay's own mechanics are tested with a client outside such a
job, as clients built on libuv (Node, Bun) are; the SDK's job is tested apart.
GHIDRA_GUI_TEST_TIME_SCALE stretches the waits on a slow machine.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import queue
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

import pytest

from ghidra_mcp.presentation.gui_registry import ProjectRegistry

ROOT = Path(__file__).resolve().parents[1]
MAIN = "import sys; from ghidra_mcp.cli import main; sys.exit(main())"
WINDOWS = os.name == "nt"

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_GUI_VALIDATION") != "1" or not os.environ.get("GHIDRA_INSTALL_DIR"),
    reason="Run only when GHIDRA_GUI_VALIDATION=1 and GHIDRA_INSTALL_DIR are set (opens Ghidra GUI windows)",
)

TIME_SCALE = float(os.environ.get("GHIDRA_GUI_TEST_TIME_SCALE") or "1")
READY_SECONDS = 180 * TIME_SCALE
# A request of protocol 2026-07-28 carries its version and the client's capabilities itself.
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}
# What the MCP SDKs pass a stdio server on Windows besides the configured variables (mcp.client.stdio).
_WINDOWS_CLIENT_ENV = (
    "APPDATA", "HOMEDRIVE", "HOMEPATH", "PATHEXT", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT",
    "USERNAME", "USERPROFILE",
)  # fmt: skip


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
        self.local = root / "localappdata"  # Windows: LOCALAPPDATA, the registry's (and Ghidra's cache's) base
        self.temp = root / "temp"
        shutil.copytree(project_source, self.project)
        shutil.copytree(settings_source, self.settings)
        for directory in (self.home, self.state, self.local, self.temp):
            directory.mkdir()
        if sys.platform == "darwin":
            base = self.home / "Library" / "Application Support"
        elif WINDOWS:
            base = self.local
        else:
            base = self.state
        self.registry = ProjectRegistry(self.project / "GUI.gpr", directory=base / "mecha_ghidra" / "gui-runtimes")
        self.runtime_pids: set[int] = set()
        self.processes: list[subprocess.Popen] = []

    def env(self) -> dict[str, str]:
        """What a client's configuration gives the relay: few variables, as Claude Code and Codex do."""
        env = {
            "HOME": str(self.home),
            "XDG_STATE_HOME": str(self.state),
            "PATH": os.environ.get("PATH", ""),
            "GHIDRA_INSTALL_DIR": os.environ["GHIDRA_INSTALL_DIR"],
            # Ghidra's settings, cache and temporary files are this test's, apart from the user's Ghidra.
            "JAVA_TOOL_OPTIONS": (
                f"-Dapplication.settingsdir={self.settings} -Dapplication.cachedir={self.root / 'ghidra-cache'}"
                f" -Dapplication.tempdir={self.root / 'ghidra-temp'}"
            ),
            "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep),
        }
        for key in ("DISPLAY", "LANG", "LC_ALL", *(_WINDOWS_CLIENT_ENV if WINDOWS else ())):
            if key in os.environ:
                env[key] = os.environ[key]
        if WINDOWS:
            env.update(LOCALAPPDATA=str(self.local), TEMP=str(self.temp), TMP=str(self.temp))
        return env

    def relay_args(self, *extra: str, transport: str = "stdio") -> list[str]:
        return [
            "-c", MAIN, "--backend", "gui", "--transport", transport,
            "--project-location", str(self.project), "--project-name", "GUI",
            "--allowed-project-root", str(self.root), "--domain-path", "/WinHelloCPP.exe", *extra,
        ]  # fmt: skip

    def spawn_relay(self, *extra: str, transport: str = "stdio", **options) -> subprocess.Popen:
        if WINDOWS:
            # A CI runner's steps run with Ctrl+C disabled, which children inherit; a terminal's relay takes it.
            import ctypes

            ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False)
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
        if WINDOWS:
            listing = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
                    "ForEach-Object { '{0} {1}' -f $_.ProcessId, $_.CommandLine }",
                ],
                capture_output=True,
                text=True,
            ).stdout  # fmt: skip
        else:
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
    if WINDOWS:  # os.kill(pid, 0) would send Ctrl+C there
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _kill(pid: int) -> None:
    """SIGKILL; on Windows, where os.kill of any other signal is TerminateProcess, that."""
    os.kill(pid, signal.SIGTERM if WINDOWS else signal.SIGKILL)


def _stop_pid(pid: int) -> None:
    """Ghidra's own exit first (the tests leave nothing unsaved), then a kill.

    A detached runtime on Windows has no console to hear Ctrl+Break: it is ended at once.
    """
    if not _alive(pid):
        return
    if not WINDOWS:
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5  # a test's unsaved change makes Ghidra ask; its project is thrown away
        while _alive(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
    if _alive(pid):
        _kill(pid)


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


@contextlib.contextmanager
def _without_the_sdks_job():
    """On Windows, start the stdio server outside the MCP Python SDK's job object (see the module docstring)."""
    if not WINDOWS:
        yield
        return
    with mock.patch("mcp.os.win32.utilities._create_job_object", return_value=None):
        yield


@contextlib.asynccontextmanager
async def session_for(workspace: Workspace, *extra: str, sdk_job: bool = False):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    command, env = sys.executable, workspace.env()
    if sdk_job:
        # The SDK assigns its job just after the start: the venv's redirector could start the relay before
        # that, outside the job.  The base interpreter is the relay itself, joined before it starts anything.
        command, extra_env = _base_python()
        env.update(extra_env)
    params = StdioServerParameters(command=command, args=workspace.relay_args(*extra), env=env)
    with contextlib.nullcontext() if sdk_job else _without_the_sdks_job():
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            yield session


def structured(result) -> dict:
    return result.structured_content or {}


async def call_when_ready(session, name: str, arguments: dict | None = None) -> dict:
    """A tool call, repeated while the runtime is still starting (LOCK_TIMEOUT startup).

    A call a slow machine deferred (40 s) is followed with get_operation, as a client does.
    """
    deadline = time.monotonic() + READY_SECONDS
    while True:
        content = structured(await session.call_tool(name, arguments or {}))
        if content.get("deferred") is True:
            return await _follow(session, content["operation"]["operation_id"])
        error = content.get("error") or {}
        if error.get("code") != "LOCK_TIMEOUT" or (error.get("details") or {}).get("lock") != "startup":
            return content
        assert time.monotonic() < deadline, content
        await asyncio.sleep(1)


async def _follow(session, operation_id: str) -> dict:
    """The deferred call's outcome in the shape of a direct reply."""
    deadline = time.monotonic() + 600 * TIME_SCALE
    while True:
        job = structured(await session.call_tool("get_operation", {"operation_id": operation_id, "wait_seconds": 30}))
        job = job.get("result") or {}
        if job.get("state") == "succeeded":
            return {key: job[key] for key in ("result", "source") if key in job}
        if job.get("state") == "failed":
            return {"error": job.get("operation_error")}
        assert time.monotonic() < deadline, job


def run(coroutine):
    return asyncio.run(coroutine)


# ---- the tests -----------------------------------------------------------------------------------


_line_queues: dict[int, queue.Queue] = {}


def _lines_of(stream) -> queue.Queue:
    """Windows cannot select() on a pipe: a thread reads the stream's lines (None at its end)."""
    lines = _line_queues.get(id(stream))
    if lines is None:
        lines = _line_queues[id(stream)] = queue.Queue()

        def pump() -> None:
            for line in iter(stream.readline, b""):
                lines.put(line)
            lines.put(None)

        threading.Thread(target=pump, name="relay-stdout", daemon=True).start()
    return lines


def _read_line(stream, seconds: float) -> bytes:
    if WINDOWS:
        try:
            line = _lines_of(stream).get(timeout=seconds)
        except queue.Empty:
            raise AssertionError(f"no line within {seconds} s") from None
        return line or b""
    ready, _, _ = select.select([stream], [], [], seconds)
    assert ready, f"no line within {seconds} s"
    return stream.readline()


def _rest(stream) -> list[bytes]:
    """The stream's remaining lines, to its end."""
    if not WINDOWS:
        return stream.read().splitlines()
    rest, lines = [], _lines_of(stream)
    while (line := lines.get(timeout=30)) is not None:
        rest.append(line)
    return rest


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
    first = _read_line(relay.stdout, 30 * TIME_SCALE)
    initialize_seconds = time.monotonic() - started
    lines = [first]
    for message in (
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        # A client of protocol 2026-07-28 names its version in each request; the relay tells the runtime so.
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": MODERN_META}},
    ):
        relay.stdin.write((json.dumps(message) + "\n").encode())
        relay.stdin.flush()
    lines.extend(_read_line(relay.stdout, 30 * TIME_SCALE) for _ in range(2))
    record = workspace.record()
    assert record is not None and record.pid != relay.pid
    relay.stdin.close()
    assert relay.wait(20) == 0
    lines.extend(line for line in _rest(relay.stdout) if line.strip())
    replies = [json.loads(line) for line in lines]
    assert all(reply.get("jsonrpc") == "2.0" for reply in replies), lines
    assert sorted(reply.get("id") for reply in replies) == [1, 2, 3]
    modern = next(reply for reply in replies if reply.get("id") == 3)
    assert modern["result"]["resultType"] == "complete" and modern["result"]["tools"], modern
    # The runtime runs on in its own session, and the record says so (on Windows, the job tests below
    # check what the client's job objects do to it).
    assert _alive(record.pid) and (WINDOWS or os.getsid(record.pid) == record.pid)

    async def still_there():
        async with session_for(workspace) as session:
            return await call_when_ready(session, "get_program_info")

    assert (run(still_there()).get("result") or {}).get("name") == "WinHelloCPP.exe"
    assert workspace.record().state == "ready"
    # Last, so a slow machine still gets the checks above: the first initialize, runtime start included.
    assert initialize_seconds < 10, initialize_seconds


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
        assert json.loads(_read_line(relay.stdout, 90 * TIME_SCALE)).get("id") == 1
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
    _kill(lost.pid)
    assert _wait_dead(lost.pid)
    assert workspace.registry.read().runtime_id == lost.runtime_id  # left behind
    # The OS frees the lock with the process's handles: on Windows a moment after the process reports its end.
    ended = time.monotonic()
    while workspace.registry.runtime_alive():
        assert time.monotonic() - ended < 30 * TIME_SCALE, "the runtime's lock outlived its process"
        time.sleep(0.05)
    print(f"the runtime's lock was free {time.monotonic() - ended:.3f} s after its process reported its end")
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
            deadline = time.monotonic() + 30 * TIME_SCALE
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
            # Protocol 2026-07-28: the runtime checks the routing headers, which the relay passes on.
            modern = await _modern_call(port, "get_function", {"address": entry})
            unnamed = await _modern_call(port, "get_function", {"address": entry}, name_header=False)
            seen_by_stdio = await call_when_ready(stdio, "get_function", {"address": entry})
            http_relay.terminate()
            http_relay.wait(20)
            after_http_ended = await call_when_ready(stdio, "get_program_info")
            return info, edited, modern, unnamed, seen_by_stdio, after_http_ended

    info, edited, (modern_status, modern), (unnamed_status, unnamed), seen, after = run(scenario())
    assert info["result"]["name"] == "WinHelloCPP.exe"
    assert edited["result"]["status"] == "applied"
    assert modern_status == 200 and modern["result"]["structuredContent"]["result"]["name"] == "g47_entry", modern
    # The relay answers as the runtime does, status included.
    assert unnamed_status == 400 and unnamed["error"]["code"] == -32020, unnamed
    assert seen["result"]["name"] == "g47_entry"
    assert after["result"]["name"] == "WinHelloCPP.exe"
    assert len(workspace.runtime_processes()) == 1


async def _modern_call(port: int, tool: str, arguments: dict, *, name_header: bool = True) -> tuple[int, dict]:
    """A tools/call of protocol 2026-07-28 to the HTTP relay, its routing headers as a client sends them."""
    import httpx2

    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
    }
    if name_header:
        headers["Mcp-Name"] = tool
    params = {"name": tool, "arguments": arguments, "_meta": MODERN_META}
    body = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params}
    async with httpx2.AsyncClient(trust_env=False, timeout=60 * TIME_SCALE) as client:
        response = await client.post(f"http://127.0.0.1:{port}/mcp", json=body, headers=headers)
    return response.status_code, response.json()


def test_a_crash_during_a_call_is_an_unknown_outcome_and_no_restart(workspace):
    """G48: a write in flight when the runtime dies is RUNTIME_UNAVAILABLE with outcome unknown (output_state
    uncertain); later calls say the runtime is gone, and the relay starts none."""

    async def scenario():
        async with session_for(workspace) as session:
            # The runtime is still starting: the write waits on its startup gate, in flight.
            pending = asyncio.ensure_future(session.call_tool("create_label", {"address": "0x401000", "name": "g48"}))
            deadline = time.monotonic() + 30 * TIME_SCALE
            while workspace.record() is None:
                assert time.monotonic() < deadline
                await asyncio.sleep(0.1)
            await asyncio.sleep(1.5)
            pid = workspace.record().pid
            _kill(pid)
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


# ---- Windows: the client's job objects and Ctrl+C (G50) ---------------------------------------------------

_BREAKAWAY_OK, _KILL_ON_JOB_CLOSE = 0x800, 0x2000
_GUIDANCE = "start it first in a terminal with --backend gui --transport http"
# A client that starts the relay in job objects: it joins the named jobs, then runs the relay as its child.
_IN_JOBS = """
import ctypes, os, subprocess, sys
from ctypes import wintypes
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenJobObjectW.restype = wintypes.HANDLE
kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
for name in sys.argv[1].split(","):
    job = kernel32.OpenJobObjectW(0x1F001F, False, name)
    assert job and kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()), ctypes.get_last_error()
    kernel32.CloseHandle(job)
# The interpreter drops __PYVENV_LAUNCHER__ from its environment once read: the relay gets it again.
sys.exit(subprocess.call(sys.argv[2:], env={**os.environ, "__PYVENV_LAUNCHER__": sys.executable}))
"""


class _Jobs:
    """Named job objects with the given limits; closing them ends their processes (KILL_ON_JOB_CLOSE)."""

    def __init__(self, *limits: int) -> None:
        import ctypes
        from ctypes import wintypes

        self._kernel32 = kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION: LimitFlags is the DWORD after two LARGE_INTEGERs.
        size = 144 if ctypes.sizeof(ctypes.c_void_p) == 8 else 112
        self.names: list[str] = []
        self._handles: list[int] = []
        for flags in limits:
            name = f"Local\\mecha-ghidra-test-{uuid.uuid4().hex}"
            handle = kernel32.CreateJobObjectW(None, name)
            info = (ctypes.c_ubyte * size)()
            ctypes.c_uint32.from_buffer(info, 16).value = flags
            assert kernel32.SetInformationJobObject(handle, 9, info, size), ctypes.get_last_error()
            self.names.append(name)
            self._handles.append(handle)

    def close(self) -> None:
        for handle in self._handles:
            self._kernel32.CloseHandle(handle)
        self._handles.clear()


def _base_python() -> tuple[str, dict[str, str]]:
    """This venv's interpreter without the redirector, whose own job would change the chain under test."""
    base = getattr(sys, "_base_executable", sys.executable)
    return base, {"__PYVENV_LAUNCHER__": sys.executable} if base != sys.executable else {}


def _spawn_in_jobs(workspace: Workspace, jobs: _Jobs) -> subprocess.Popen:
    python, extra_env = _base_python()
    process = subprocess.Popen(
        [python, "-c", _IN_JOBS, ",".join(jobs.names), python, *workspace.relay_args()],
        cwd=workspace.root,
        env={**workspace.env(), **extra_env},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    workspace.processes.append(process)
    return process


def _exchange(relay: subprocess.Popen, message: dict, seconds: float = 60) -> dict:
    relay.stdin.write((json.dumps(message) + "\n").encode())
    relay.stdin.flush()
    return json.loads(_read_line(relay.stdout, seconds * TIME_SCALE))


def _first_call(relay: subprocess.Popen, name: str = "get_program_info") -> dict:
    """initialize, then one tool call: its structured content."""
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "g50", "version": "0"}},
    }
    assert _exchange(relay, initialize).get("id") == 1
    relay.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": {}}}
    return _exchange(relay, call)["result"]["structuredContent"]


def _refused_with_guidance(content: dict) -> bool:
    error = content.get("error") or {}
    return error.get("code") == "RUNTIME_UNAVAILABLE" and _GUIDANCE in error.get("message", "")


@pytest.mark.skipif(not WINDOWS, reason="Windows job objects and console events (G50)")
class TestWindowsDetach:
    def test_the_python_sdks_job_forbids_breaking_away_and_gets_the_guidance(self, workspace):
        """The MCP Python SDK's job (KILL_ON_JOB_CLOSE only): no runtime starts, and the call says what to do."""

        async def first_call():
            async with session_for(workspace, sdk_job=True) as session:
                return structured(await session.call_tool("get_program_info", {}))

        content = run(first_call())
        assert _refused_with_guidance(content), content
        assert workspace.runtime_processes() == []
        assert not workspace.registry.runtime_alive()

    def test_a_job_around_the_clients_that_forbids_it_is_found_too(self, workspace):
        """Nested: the relay's own job allows breaking away, one around it that ends its processes on close does
        not; Windows then keeps the runtime in that job without an error, and the runtime ends itself before it
        opens anything."""
        jobs = _Jobs(_KILL_ON_JOB_CLOSE, _KILL_ON_JOB_CLOSE | _BREAKAWAY_OK)
        try:
            relay = _spawn_in_jobs(workspace, jobs)
            content = _first_call(relay)
            assert _refused_with_guidance(content), content
            assert "would end the Ghidra GUI runtime" in content["error"]["details"]["cause_message"]
            assert workspace.runtime_processes() == []
            assert not workspace.registry.runtime_alive()
        finally:
            jobs.close()

    def test_a_runtime_that_left_its_clients_job_outlives_the_client(self, workspace):
        """A job that allows breaking away and ends its processes on close: the relay dies with it, the GUI stays."""
        jobs = _Jobs(_KILL_ON_JOB_CLOSE | _BREAKAWAY_OK)
        try:
            relay = _spawn_in_jobs(workspace, jobs)
            _first_call(relay, "list_targets")
            first = workspace.record()
            assert first is not None
        finally:
            jobs.close()
        assert relay.wait(30) is not None
        assert _alive(first.pid)

        async def again():
            async with session_for(workspace) as session:
                await call_when_ready(session, "get_program_info")
            return workspace.record()

        assert run(again()).runtime_id == first.runtime_id
        assert len(workspace.runtime_processes()) == 1

    def test_a_client_that_ends_the_relays_process_tree_leaves_the_gui(self, workspace):
        """Claude Code ends a stdio server's process tree by parent pid when the server still runs a few seconds
        after its stdin closed, as ``taskkill /T /F`` does here.  The runtime's parent is a starter that has
        ended, so the tree does not reach the GUI (spec §10.6)."""
        relay = workspace.spawn_relay(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _first_call(relay, "list_targets")
        first = workspace.record()
        assert first is not None
        # Not checked: a process of the tree may end before taskkill reaches it, and taskkill then exits with 255.
        subprocess.run(["taskkill", "/PID", str(relay.pid), "/T", "/F"], capture_output=True, timeout=60)
        assert relay.wait(30) is not None
        assert _alive(first.pid)

        async def again():
            async with session_for(workspace) as session:
                await call_when_ready(session, "get_program_info")
            return workspace.record()

        assert run(again()).runtime_id == first.runtime_id
        assert len(workspace.runtime_processes()) == 1

    def test_ctrl_c_ends_an_http_relay_and_leaves_the_runtime(self, workspace):
        """The HTTP relay in a terminal of its own: Ctrl+C ends it, not the runtime (spec §10.5)."""

        async def start():
            async with session_for(workspace) as session:
                await call_when_ready(session, "get_program_info")

        run(start())
        runtime = workspace.record()
        port = _free_port()
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0  # SW_HIDE
        relay = workspace.spawn_relay(
            "--mcp-port", str(port), transport="http",
            creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup,
        )  # fmt: skip
        deadline = time.monotonic() + 60 * TIME_SCALE
        while True:
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
            assert time.monotonic() < deadline, "the HTTP relay did not listen"
            time.sleep(0.2)
        # Ctrl+C as the terminal sends it: to every process of the relay's console.
        subprocess.run(
            [
                sys.executable, "-c",
                "import ctypes, sys\nk = ctypes.windll.kernel32\nk.FreeConsole()\n"
                "assert k.AttachConsole(int(sys.argv[1]))\nk.SetConsoleCtrlHandler(None, True)\n"
                "k.GenerateConsoleCtrlEvent(0, 0)\n",
                str(relay.pid),
            ],
            check=True,
            timeout=60,
        )  # fmt: skip
        assert relay.wait(60) is not None
        assert _alive(runtime.pid)

        async def still_there():
            async with session_for(workspace) as session:
                return await call_when_ready(session, "get_program_info")

        assert (run(still_there()).get("result") or {}).get("name") == "WinHelloCPP.exe"
        assert workspace.record().runtime_id == runtime.runtime_id
