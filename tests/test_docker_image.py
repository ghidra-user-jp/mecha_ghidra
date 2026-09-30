"""Opt-in checks of a built Docker image: its default command end to end, and shutdown on each signal.

Set MECHA_GHIDRA_DOCKER_IMAGE to the image, for example the tag ./build_docker_image.sh built.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import subprocess
import time
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener
from uuid import uuid4

import anyio
import pytest
from jsonschema import Draft202012Validator
from mcp import Client

IMAGE = os.environ.get("MECHA_GHIDRA_DOCKER_IMAGE", "")
pytestmark = pytest.mark.skipif(not IMAGE, reason="set MECHA_GHIDRA_DOCKER_IMAGE to a built image")

# The Windows program of Ghidra's own class exercises, taken from the image's Ghidra.
EXERCISE_PE = "/opt/ghidra/docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe"
CLEANUP_LOG = "Received {}: cancelling running jobs and closing Ghidra projects"


def _docker(*args: str, timeout: float = 180) -> str:
    completed = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _logs(container: str) -> str:
    # The server logs to stderr.
    return subprocess.run(
        ["docker", "logs", container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60
    ).stdout


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    """A samples directory holding the exercise PE, readable by the image's user."""
    samples = tmp_path_factory.mktemp("samples")
    holder = _docker("create", IMAGE)
    try:
        _docker("cp", f"{holder}:{EXERCISE_PE}", str(samples))
    finally:
        _docker("rm", holder)
    samples.chmod(0o755)
    (samples / "WinHelloCPP.exe").chmod(0o644)
    return samples


@contextmanager
def _server(samples):
    """Run the image's default command, as docs/docker.md does; yield the container and its endpoint."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    container = _docker(
        "run",
        "--detach",
        "--publish",
        f"127.0.0.1:{port}:8081",
        "--volume",
        f"{samples}:/samples:ro",
        "--tmpfs",
        "/data/projects:uid=10001,gid=10001,mode=0755",
        "--tmpfs",
        "/data/exports:uid=10001,gid=10001,mode=0755",
        IMAGE,
    )
    try:
        url = f"http://127.0.0.1:{port}/mcp"
        _wait_until_serving(container, url)
        yield container, url
    finally:
        subprocess.run(["docker", "rm", "--force", container], capture_output=True, timeout=120)


def _wait_until_serving(container, url):
    """The published port accepts before the server listens, so wait for any HTTP answer."""
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 180
    while True:
        try:
            opener.open(url, timeout=5).close()
            return
        except HTTPError:
            return
        except OSError:
            assert _docker("inspect", "--format", "{{.State.Running}}", container) == "true", _logs(container)
            assert time.monotonic() < deadline, _logs(container)
            time.sleep(0.5)


async def _analyze_the_exercise_pe(url) -> int:
    """Import, analyze, decompile and edit the exercise PE; return how many tools tools/list published."""
    async with Client(url, read_timeout_seconds=120) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}

        async def call(name, arguments, *, error=False):
            reply = await client.call_tool(name, arguments)
            assert reply.is_error is error, reply
            Draft202012Validator(tools[name].output_schema).validate(reply.structured_content)
            return reply.structured_content

        await call("create_project", {"project_location": "/data/projects", "project_name": "default"})
        arguments = {"target": "default", "binary_path": "/samples/WinHelloCPP.exe", "wait_seconds": 0}
        record = (await call("import_program", arguments))["result"]
        with anyio.fail_after(600):
            while record["state"] in {"queued", "running"}:
                status = await call("get_operation", {"operation_id": record["operation_id"], "wait_seconds": 20})
                record = status["result"]
        assert record["state"] == "succeeded", record
        loaded = await call("load_project_program", {"target": "default", "domain_path": record["result"]["program"]})
        assert loaded["result"]["is_analyzed"] is True
        functions = (await call("list_functions", {"target": "default", "limit": 20}))["result"]
        entry = next(function["entry"] for function in functions if not function["is_thunk"])
        assert (await call("decompile_function", {"target": "default", "address": entry}))["result"].strip()
        missing = await call("decompile_function", {"target": "default", "name": "no_such_function"}, error=True)
        assert missing["error"]["code"] == "NOT_FOUND" and "list_functions" in missing["error"]["hint"]
        edit = {"kind": "set_comment", "address": entry, "comment_type": "plate", "comment": "checked in Docker"}
        request_id = str(uuid4())
        applied = await call("apply_edits", {"target": "default", "edits": [edit], "request_id": request_id})
        # A resend gets the recorded reply, and the program stays at the revision the edit left.
        resent = await call("apply_edits", {"target": "default", "edits": [edit], "request_id": request_id})
        assert resent == {**applied, "replayed": True}
        info = await call("get_program_info", {"target": "default"})
        assert info["result"]["revision"] == applied["source"]["revision"]
        label = {"target": "default", "address": entry, "name": "not a valid name"}
        refused = await call("create_label", label, error=True)
        assert refused["error"]["details"]["output_state"] == "absent"
        return len(tools)


async def _wait_for_startup(url):
    """A tool call waits until the JVM is up and the default target is registered."""
    async with Client(url, read_timeout_seconds=120) as client:
        reply = await client.call_tool("list_targets", {})
        assert not reply.is_error, reply


def test_default_command_analyzes_the_exercise_pe_and_stops_on_sigterm(samples):
    with _server(samples) as (container, url):
        tool_count = asyncio.run(_analyze_the_exercise_pe(url))
        _docker("stop", "--time", "60", container, timeout=120)
        exit_code = _docker("inspect", "--format", "{{.State.ExitCode}}", container)
        logs = _logs(container)
    assert exit_code == str(128 + signal.SIGTERM), logs
    assert f"Starting PyGhidra MCP server with {tool_count} tools" in logs
    assert CLEANUP_LOG.format("SIGTERM") in logs


@pytest.mark.parametrize("signame", ["SIGINT", "SIGHUP"])
def test_other_shutdown_signals_also_close_the_projects(samples, signame):
    """docker kill signals uv, PID 1, which passes the signal on to the server."""
    with _server(samples) as (container, url):
        asyncio.run(_wait_for_startup(url))
        _docker("kill", "--signal", signame, container)
        exit_code = _docker("wait", container, timeout=120)
        logs = _logs(container)
    assert exit_code == str(128 + signal.Signals[signame]), logs
    assert CLEANUP_LOG.format(signame) in logs
