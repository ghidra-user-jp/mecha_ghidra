"""Exercise the real CLI/JVM across process and network boundaries."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from jsonschema import Draft202012Validator
from mcp import Client, StdioServerParameters

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


@contextmanager
def _server(tmp_path, transport, script_runtime):
    env = dict(os.environ, GHIDRA_INSTALL_DIR=_resolve_ghidra_install_dir())
    snapshots = tmp_path / "temporary"
    snapshots.mkdir()
    env["TMPDIR"] = str(snapshots)
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

            targets = await call("list_targets", {})
            assert targets.structured_content["result"][0]["target"] == "default"
            imported = await call(
                "import_program",
                {
                    "target": "default",
                    "binary_path": str(binary),
                    "import_mode": "raw_binary",
                    "language_id": "x86:LE:64:default",
                    "base_address": "0x1000",
                    "entry_address": "0x1000",
                    "analyze_imported": True,
                },
            )
            domain = imported.structured_content["result"]["program"]
            await call("load_project_program", {"target": "default", "domain_path": domain})
            functions = await call("list_functions", {"target": "default", "limit": 1})
            assert functions.structured_content["result"]
            empty = await call("list_functions", {"target": "default", "filter": "__never_matches__"})
            assert empty.structured_content == {"result": []}
            assert empty.content[0].text == "[]"
            decompiled = await call("decompile_function", {"target": "default", "address": "0x1000"})
            assert "0x2a" in decompiled.structured_content["result"]
            edit = {"kind": "set_comment", "address": "0x1000", "comment_type": "plate", "comment": "kept"}
            await call("apply_edits", {"target": "default", "edits": [edit], "dry_run": True})
            before = await call("get_comments", {"target": "default", "address": "0x1000"})
            assert before.structured_content["result"]["plate"] != "kept"
            await call("apply_edits", {"target": "default", "edits": [edit]})
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
            nested = await call("run_script", {"target": "default", "script_id": "test:Parent.py"})
            nested_data = nested.structured_content["result"]
            assert nested_data["runtime"] == script_runtime
            assert nested_data["transaction_outcome"] == "committed"
            assert "child success" in nested_data["stdout"]["text"]
            assert "parent success" in nested_data["stdout"]["text"]
            inline = await call(
                "run_script",
                {"target": "default", "runtime": script_runtime, "source": 'print("inline success")\n'},
            )
            assert "inline success" in inline.structured_content["result"]["stdout"]["text"]
            failed = await call("run_script", {"target": "default", "script_id": "test:Fail.py"}, error=True)
            assert "SCRIPT_FAILED" in failed.model_dump_json()
            assert "rolled_back" in failed.model_dump_json()
            after = await call("get_comments", {"target": "default", "address": "0x1000"})
            assert after.structured_content["result"]["plate"] == "nested"
            normal_exit = await call(
                "run_script",
                {"target": "default", "runtime": script_runtime, "source": "import sys\nsys.exit(0)\n"},
            )
            assert normal_exit.structured_content["result"]["error"] is None
            abnormal_exit = await call(
                "run_script",
                {"target": "default", "runtime": script_runtime, "source": "import sys\nsys.exit(3)\n"},
                error=True,
            )
            assert '"exit_code":3' in abnormal_exit.model_dump_json()
            large = await call("run_script", {"target": "default", "script_id": "test:Large.py"})
            metadata = large.structured_content
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
