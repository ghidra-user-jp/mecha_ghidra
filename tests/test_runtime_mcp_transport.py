"""Exercise the real CLI/JVM across process and network boundaries."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

import anyio
import pytest
from jsonschema import Draft202012Validator
from mcp import Client, StdioServerParameters

from ghidra_mcp.presentation.cli_runtime import SHUTDOWN_SIGNALS
from test_runtime_readonly_commands import _resolve_ghidra_install_dir

pytestmark = pytest.mark.skipif(
    os.environ.get("GHIDRA_RUNTIME_VALIDATION") != "1",
    reason="Run only when GHIDRA_RUNTIME_VALIDATION=1",
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2026-07-28"


def _http_request(url, method, params):
    """A fresh connection, with no initialize, cookies, or session identifier."""
    params = dict(params)
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "runtime-test", "version": "1"},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": VERSION,
        "Mcp-Method": method,
        "Connection": "close",
        "Content-Type": "application/json",
    }
    if "name" in params or "uri" in params:
        headers["Mcp-Name"] = params.get("name", params.get("uri"))
    request = Request(
        url,
        headers=headers,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
    )
    with build_opener(ProxyHandler({})).open(request, timeout=30) as response:
        assert "mcp-session-id" not in response.headers
        assert response.headers["content-type"].startswith("application/json")
        body = json.load(response)
    assert "error" not in body, body
    return body["result"]


def _create_sample_project(tmp_path, env):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    # Finish this JVM before the MCP subprocess opens the project.
    setup = """
import sys
from ghidra_headless.launcher import start_headless_jvm
start_headless_jvm()
from ghidra.base.project import GhidraProject
GhidraProject.createProject(sys.argv[1], "sample", False).close()
"""
    with (tmp_path / "setup.log").open("w") as log:
        subprocess.run(
            [sys.executable, "-c", setup, str(project_dir)],
            env=env,
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=120,
        )
    return project_dir


@contextmanager
def _server(tmp_path, transport, script_runtime):
    env = dict(os.environ, GHIDRA_INSTALL_DIR=_resolve_ghidra_install_dir())
    snapshots = tmp_path / "temporary"
    snapshots.mkdir()
    env["TMPDIR"] = str(snapshots)
    project_dir = _create_sample_project(tmp_path, env)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "Fail.py").write_text(
        f"# @runtime {script_runtime}\n"
        "from ghidra.program.model.listing import CommentType\n"
        'currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "FAIL")\n'
        'raise RuntimeError("expected transport test failure")\n'
    )
    (scripts / "Large.py").write_text(f'# @runtime {script_runtime}\nprint("mecha runtime " * 1500)\n')
    (scripts / "Child.py").write_text(
        f"# @runtime {script_runtime}\n"
        "from ghidra.program.model.listing import CommentType\n"
        'currentProgram.getListing().setComment(currentProgram.getMinAddress(), CommentType.PLATE, "nested")\n'
        'print("child success")\n'
    )
    (scripts / "Parent.py").write_text(f'# @runtime {script_runtime}\nrunScript("Child.py")\nprint("parent success")\n')
    args = [
        "-c",
        "from ghidra_mcp.cli import main; raise SystemExit(main())",
        "--transport",
        transport,
        "--project-location",
        str(project_dir),
        "--project-name",
        "sample",
        "--tool-profile",
        "full",
        "--script-root",
        f"test={scripts}",
        "--allowed-project-root",
        str(tmp_path),
        "--allowed-import-root",
        str(tmp_path),
        "--allowed-export-root",
        str(tmp_path),
        "--large-result-threshold-chars",
        "4000",
        "--large-result-preview-chars",
        "100",
        "--log-level",
        "WARNING",
    ]
    if transport == "stdio":
        yield StdioServerParameters(command=sys.executable, args=args, env=env, cwd=str(ROOT)), None
        assert not list(snapshots.glob("mecha_ghidra_scripts_*"))
        return
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    with (tmp_path / "http-server.log").open("w") as log:
        process = subprocess.Popen(
            [sys.executable, *args, "--mcp-port", str(port)],
            env=env,
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 120
            while True:
                assert process.poll() is None, (tmp_path / "http-server.log").read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "HTTP server did not start"
                    time.sleep(0.1)
            # The first protocol request is a tool call, before any discovery.
            first = _http_request(url, "tools/call", {"name": "list_targets", "arguments": {}})
            assert not first["isError"] and first["structuredContent"]["result"]
            discover = _http_request(url, "server/discover", {})
            assert "Ghidra" in discover["instructions"]
            assert "search" in discover["instructions"].lower()
            assert list(snapshots.glob("mecha_ghidra_scripts_*"))
            yield url, url
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                pytest.fail("HTTP server failed to shut down cleanly")
            # Windows terminate() is a forced TerminateProcess, not catchable SIGTERM.
            if sys.platform != "win32":
                assert not list(snapshots.glob("mecha_ghidra_scripts_*"))


@pytest.mark.parametrize("transport", ["stdio", "http"])
@pytest.mark.parametrize(
    "script_runtime",
    [
        "PyGhidra",
        pytest.param(
            "Jython",
            marks=pytest.mark.skipif(
                os.environ.get("GHIDRA_JYTHON_RUNTIME_VALIDATION") != "1",
                reason="Run with GHIDRA_JYTHON_RUNTIME_VALIDATION=1 and the Jython extension installed",
            ),
        ),
    ],
)
def test_real_mcp_transport_preserves_results_mutations_and_rollback(tmp_path, transport, script_runtime):
    binary = tmp_path / "tiny.bin"
    binary.write_bytes(bytes.fromhex("b8 2a 00 00 00 c3"))

    async def check(endpoint, url):
        async with Client(endpoint, read_timeout_seconds=120) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            for tool in tools.values():
                Draft202012Validator.check_schema(tool.input_schema)
                Draft202012Validator.check_schema(tool.output_schema)
            calls = 0

            async def call(name, arguments, *, error=False):
                nonlocal calls
                response = await client.call_tool(name, arguments)
                calls += 1
                assert response.is_error is error, response
                Draft202012Validator(tools[name].output_schema).validate(response.structured_content)
                assert not response.structured_content.get("presentation_failed"), response
                return response

            async def script(arguments, *, failed=False):
                """Run a script job to its end and return its record."""
                reply = await call("run_script", arguments)
                record = reply.structured_content["result"]
                with anyio.fail_after(120):
                    while record["state"] in {"queued", "running"}:
                        status = await call(
                            "get_operation", {"operation_id": record["operation_id"], "wait_seconds": 20}
                        )
                        record = status.structured_content["result"]
                assert record["state"] == ("failed" if failed else "succeeded"), record
                return record

            targets = await call("list_targets", {})
            assert targets.structured_content["result"][0]["target"] == "default"
            imported = await call(
                "import_program",
                {
                    "target": "default",
                    "request_id": str(uuid4()),
                    "binary_path": str(binary),
                    "import_mode": "raw_binary",
                    "language_id": "x86:LE:64:default",
                    "base_address": "0x1000",
                    "entry_address": "0x1000",
                    "analyze_imported": True,
                },
            )
            operation_id = imported.structured_content["result"]["operation_id"]
            with anyio.fail_after(120):
                while True:
                    status = await call("get_operation", {"operation_id": operation_id})
                    operation = status.structured_content["result"]
                    if operation["state"] in {"succeeded", "failed"}:
                        break
                    await anyio.sleep(0.01)
            assert operation["state"] == "succeeded", operation
            domain = operation["result"]["program"]
            await call("load_project_program", {"target": "default", "domain_path": domain})
            functions = await call("list_functions", {"target": "default", "limit": 1})
            assert functions.structured_content["result"]
            empty = await call("list_functions", {"target": "default", "filter": "__never_matches__"})
            assert empty.structured_content["result"] == []
            assert empty.content[0].text == "[]"
            decompiled = await call("decompile_function", {"target": "default", "address": "0x1000"})
            assert "0x2a" in decompiled.structured_content["result"]
            # The first line names the function and its entry address.
            assert decompiled.structured_content["result"].splitlines()[0].endswith(" @ 00001000 */")
            edit = {"kind": "set_comment", "address": "0x1000", "comment_type": "plate", "comment": "kept"}
            await call("apply_edits", {"target": "default", "edits": [edit], "dry_run": True})
            before = await call("get_comments", {"target": "default", "address": "0x1000"})
            assert before.structured_content["result"]["plate"] != "kept"
            request_id = str(uuid4())
            applied = await call("apply_edits", {"target": "default", "edits": [edit], "request_id": request_id})
            resent = await call("apply_edits", {"target": "default", "edits": [edit], "request_id": request_id})
            assert resent.structured_content == {**applied.structured_content, "replayed": True}
            # The resend changed nothing: the program is still at the revision the edit left.
            source = applied.structured_content["source"]
            assert source["target"] == "default" and source["program"] == domain
            info = await call("get_program_info", {"target": "default"})
            assert info.structured_content["result"]["revision"] == source["revision"]
            assert info.structured_content["source"]["revision"] == source["revision"]
            refused = await call(
                "create_label", {"target": "default", "address": "0x1000", "name": "not a valid name"}, error=True
            )
            assert refused.structured_content["error"]["details"]["output_state"] == "absent"
            batch = await call(
                "batch_read",
                {
                    "target": "default",
                    "requests": [
                        {"id": "comment", "tool": "get_comments", "arguments": {"address": "0x1000"}},
                        {"id": "function", "tool": "get_function", "arguments": {"address": "0x1000"}},
                        {"id": "missing", "tool": "get_function", "arguments": {"address": "0xffff"}},
                    ],
                },
            )
            assert batch.structured_content["result"]["status"] == "partial"
            assert batch.structured_content["result"]["succeeded_count"] == 2
            nested_data = (await script({"target": "default", "script_id": "test:Parent.py"}))["result"]
            assert nested_data["runtime"] == script_runtime
            assert nested_data["transaction_outcome"] == "committed"
            assert "child success" in nested_data["stdout"]["text"]
            assert "parent success" in nested_data["stdout"]["text"]
            inline = await script(
                {"target": "default", "runtime": script_runtime, "source": 'print("inline success")\n'}
            )
            assert "inline success" in inline["result"]["stdout"]["text"]
            failed = (await script({"target": "default", "script_id": "test:Fail.py"}, failed=True))["operation_error"]
            assert failed["code"] == "SCRIPT_FAILED"
            assert failed["details"]["transaction_outcome"] == "rolled_back"
            assert failed["details"]["output_state"] == "absent"
            after = await call("get_comments", {"target": "default", "address": "0x1000"})
            assert after.structured_content["result"]["plate"] == "nested"
            normal_exit = await script(
                {"target": "default", "runtime": script_runtime, "source": "import sys\nsys.exit(0)\n"}
            )
            assert normal_exit["result"]["error"] is None
            abnormal_exit = await script(
                {"target": "default", "runtime": script_runtime, "source": "import sys\nsys.exit(3)\n"},
                failed=True,
            )
            assert '"exit_code":3' in json.dumps(abnormal_exit["operation_error"], separators=(",", ":"))
            # A large result stays out of the job record; the record carries its result_id.
            metadata = (await script({"target": "default", "script_id": "test:Large.py"}))["result"]
            assert metadata["truncated"] and metadata["result_id"]
            await call("read_result", {"result_id": metadata["result_id"], "limit_chars": 100})
            search = await call("search_result", {"result_id": metadata["result_id"], "pattern": "mecha runtime"})
            assert search.structured_content["result"]["matches"]
            resource = await client.read_resource(metadata["resource_uri"])
            payload = json.loads(resource.contents[0].text)
            assert payload["stdout"]["text"] == "mecha runtime " * 1500 + "\n"
            if url:
                # Retrieve the retained result through an independent connection.
                fresh = await asyncio.to_thread(_http_request, url, "resources/read", {"uri": metadata["resource_uri"]})
                assert fresh["contents"][0]["text"] == resource.contents[0].text
            await call("list_functions", {"target": "default", "limit": "1"}, error=True)
            await call("close_session", {"target": "default"})
            print(
                f"[runtime] transport={transport} scripts={script_runtime} tools={len(tools)} calls={calls}; "
                "schema, rollback, cache OK"
            )

    with _server(tmp_path, transport, script_runtime) as (endpoint, url):
        asyncio.run(check(endpoint, url))


# close_all is slowed down so that an early exit shows: the marker is written
# only when the Python cleanup has run to the end.
_SLOW_CLOSE_SERVER = """
import sys
import time
from pathlib import Path

from ghidra_mcp.presentation.cli_runtime import ServiceRegistryAdapter

marker = Path(sys.argv.pop(1))
close_all = ServiceRegistryAdapter.close_all


def slow_close_all(self):
    time.sleep(2)
    close_all(self)
    marker.write_text("closed")


ServiceRegistryAdapter.close_all = slow_close_all
from ghidra_mcp.cli import main

raise SystemExit(main())
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("signum", SHUTDOWN_SIGNALS, ids=lambda signum: signal.Signals(signum).name)
def test_real_stdio_shutdown_signal_runs_cleanup_before_the_process_ends(tmp_path, signum):
    env = dict(os.environ, GHIDRA_INSTALL_DIR=_resolve_ghidra_install_dir())
    project_dir = _create_sample_project(tmp_path, env)
    marker = tmp_path / "closed"

    async def scenario():
        with (tmp_path / "stdio-server.log").open("w") as log:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                _SLOW_CLOSE_SERVER,
                str(marker),
                "--transport",
                "stdio",
                "--project-location",
                str(project_dir),
                "--project-name",
                "sample",
                "--log-level",
                "WARNING",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=log,
                env=env,
                cwd=ROOT,
            )

        async def send(message):
            proc.stdin.write((json.dumps(message) + "\n").encode())
            await proc.stdin.drain()

        async def reply(expected_id):
            with anyio.fail_after(120):
                while True:
                    line = await proc.stdout.readline()
                    assert line, (tmp_path / "stdio-server.log").read_text()
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
                        "clientInfo": {"name": "signal-test", "version": "1"},
                    },
                }
            )
            await reply(1)
            await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            await send(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_targets", "arguments": {}}}
            )
            listed = await reply(2)
            assert not listed.get("isError"), listed
            # stdin stays open: the signal, not EOF, has to drive the shutdown.
            sent = time.monotonic()
            proc.send_signal(signum)
            code = await asyncio.wait_for(proc.wait(), 60)
            elapsed = time.monotonic() - sent
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            proc.stdin.close()
        log_text = (tmp_path / "stdio-server.log").read_text()
        assert marker.exists(), f"cleanup was cut off {elapsed:.2f}s after the signal (exit {code}):\n{log_text}"
        assert elapsed >= 2 and code == 128 + signum
        name = signal.Signals(signum).name
        print(f"[runtime] stdio {name}: exit {code} after {elapsed:.2f}s, cleanup finished")

    asyncio.run(scenario())


# The JVM step is held open once the real JVM has booted, so the signal lands
# where a JVM without -Xrs would have ended the process itself.
_SLOW_JVM_STEP_SERVER = """
import sys
import time
from pathlib import Path

from ghidra_mcp.presentation import cli

booted = Path(sys.argv.pop(1))
start = cli._start_pyghidra_headless


def start_then_hold(*args, **kwargs):
    start(*args, **kwargs)
    booted.write_text("booted")
    time.sleep(3)


cli._start_pyghidra_headless = start_then_hold
raise SystemExit(cli.main())
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_real_stdio_sigterm_while_the_jvm_boots_reaches_python(tmp_path):
    env = dict(os.environ, GHIDRA_INSTALL_DIR=_resolve_ghidra_install_dir())
    project_dir = _create_sample_project(tmp_path, env)
    booted = tmp_path / "booted"
    log_path = tmp_path / "stdio-server.log"

    async def scenario():
        with log_path.open("w") as log:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                _SLOW_JVM_STEP_SERVER,
                str(booted),
                "--transport",
                "stdio",
                "--project-location",
                str(project_dir),
                "--project-name",
                "sample",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=log,
                env=env,
                cwd=ROOT,
            )
        try:
            with anyio.fail_after(120):
                while not booted.exists():
                    assert proc.returncode is None, log_path.read_text()
                    await asyncio.sleep(0.01)
            # stdin stays open, and the step that re-arms the handlers has not run yet.
            proc.send_signal(signal.SIGTERM)
            return await asyncio.wait_for(proc.wait(), 60)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            proc.stdin.close()

    code = asyncio.run(scenario())
    log_text = log_path.read_text()
    assert code == 128 + signal.SIGTERM, log_text
    # Python, not the JVM, took the signal: it waited for the step, then cleaned up.
    assert "Waiting for the Ghidra startup step in progress" in log_text
    assert "Received SIGTERM" in log_text
    print("[runtime] stdio SIGTERM while the JVM boots: handled by Python")
