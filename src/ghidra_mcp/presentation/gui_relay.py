"""Relays of the Ghidra GUI backend: stdio and HTTP clients reach the project's runtime through them (spec §10).

A relay starts no JVM.  It finds the runtime of its project in the registry
(``gui_registry``), or starts one detached from itself, checks that the
runtime runs with its configuration (spec §10.3), and then forwards each
JSON-RPC message to the runtime's loopback endpoint as it is.  The runtime
(stateless Streamable HTTP) answers a request with one JSON body, or with an
event stream when the call reports progress; forwarding needs no MCP session
of its own, and a stream is passed on message by message as it arrives (a
stdio client gets one line for each, an HTTP client the same event stream).
The HTTP routing headers go
along: an HTTP client's are passed on unchanged, and for a stdio client the
relay sends what an HTTP client would (the protocol version, ``Mcp-Method``
and ``Mcp-Name``), which the runtime checks against the body from protocol
2026-07-28 on.  The HTTP relay answers with the runtime's HTTP status, which
such a client reads too.

What the runtime cannot answer, the relay's fallback answers: the same MCP
server this package builds for the relay's own tools, whose startup gate
refuses every tool call with the relay's reason (the runtime's configuration
differs, it failed to start, it went away).  ``initialize``, ``tools/list`` and
the error envelopes therefore look exactly as the runtime's would.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

import anyio
import httpx2
from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PARAM_HEADER_PREFIX,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    encode_header_value,
)
from mcp_types import PROTOCOL_VERSION_META_KEY

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_utils import sanitize_cause_message
from ghidra_mcp.domain.output_state import UNCERTAIN, with_output_state

from .gui_registry import FAILED, READY, REGISTRY_FORMAT, ProjectRegistry, RuntimeRecord
from .mcp_server import package_version
from .startup import StartupFailure, StartupGate, startup_failed_error
from .tool_registry import domain_error_result
from .transport import resolve_transport_security_for_host

logger = logging.getLogger(__name__)

# How long a relay waits for another relay's launch, and for the runtime it starts to register.
LAUNCH_WAIT_SECONDS = 60.0
# Longer than any reply of the runtime (about 50 s: the deferral, a job's wait_seconds).
RUNTIME_TIMEOUT_SECONDS = 120.0
# The module a relay starts the runtime with (spec §4.1: not a public entry point).
RUNTIME_MODULE = "ghidra_mcp.presentation.gui_runtime"
_LOG_TAIL_BYTES = 4000


# ---- the configuration a runtime runs with -----------------------------------------------------


@dataclass(frozen=True)
class RuntimeConfig:
    """What a relay compares with a runtime (spec §10.3), and what it only reports."""

    fingerprint: dict[str, Any]
    settings: dict[str, Any]


def runtime_config(args, specs: Mapping[str, ToolSpec], *, ghidra_path: str | None, path_policy) -> RuntimeConfig:
    """The runtime-wide configuration ``args`` ask for; the relay-only options (transport, host, port) are left out."""
    fingerprint = {
        "versions": {
            "registry_format": REGISTRY_FORMAT,
            "mecha": package_version(),
            "ghidra_install_dir": os.path.realpath(ghidra_path) if ghidra_path else None,
        },
        "path_policy": {
            "import_roots": sorted(str(root) for root in path_policy.allowed_import_roots),
            "project_roots": sorted(str(root) for root in path_policy.allowed_project_roots),
            "export_roots": sorted(str(root) for root in path_policy.allowed_export_roots),
        },
        "targets": {
            "target_name": args.target_name,
            "domain_path": args.domain_path,
            "sessions": sorted(args.session or []),
        },
        "tools": sorted(specs),
    }
    settings = {
        "lock_timeout_seconds": args.lock_timeout_seconds,
        "tool_description_mode": args.tool_description_mode,
        "large_result_mode": args.large_result_mode,
        "large_result_threshold_chars": args.large_result_threshold_chars,
        "large_result_preview_chars": args.large_result_preview_chars,
        "result_cache_max_entries": args.result_cache_max_entries,
        "result_cache_max_bytes": args.result_cache_max_bytes,
        "result_cache_max_memory_bytes": args.result_cache_max_memory_bytes,
    }
    return RuntimeConfig(fingerprint=fingerprint, settings=settings)


def config_mismatch(record: RuntimeRecord, config: RuntimeConfig) -> DomainError | None:
    """``RUNTIME_CONFIG_MISMATCH`` when the relay cannot use the runtime as it runs (spec §10.3)."""
    ours, theirs = config.fingerprint, record.fingerprint
    differs = [name for name in ("versions", "path_policy", "targets") if ours.get(name) != theirs.get(name)]
    missing = sorted(set(ours.get("tools", ())) - set(theirs.get("tools", ())))
    if not differs and not missing:
        return None
    details: dict[str, Any] = {"differs": differs}
    if missing:
        details["missing_tools"] = missing
    parts = [*differs, *(["tools"] if missing else [])]
    return DomainError(
        code=ErrorCode.RUNTIME_CONFIG_MISMATCH,
        message=f"the running Ghidra GUI runtime of this project differs in {', '.join(parts)}",
        details=details,
        retryable=False,
    )


def _log_setting_differences(record: RuntimeRecord, config: RuntimeConfig) -> None:
    for name, value in config.settings.items():
        if record.settings.get(name, value) != value:
            logger.warning(
                "The Ghidra GUI runtime runs with %s=%r; this client's %r does not apply to it",
                name,
                record.settings.get(name),
                value,
            )


# ---- finding and starting the runtime ------------------------------------------------------------


def _log_tail(path) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - _LOG_TAIL_BYTES))
            text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _unavailable(message: str, *, outcome: str = "not_run", **details: Any) -> DomainError:
    return DomainError(
        code=ErrorCode.RUNTIME_UNAVAILABLE,
        message=message,
        details={"outcome": outcome, **details},
        retryable=False,
    )


def _failed_to_start(record: RuntimeRecord | None, *, log_line: str = "") -> DomainError:
    if record is not None and record.failure:
        failure = record.failure
        return startup_failed_error(
            StartupFailure(
                stage=str(failure.get("stage") or "launch"),
                message=str(failure.get("message") or "The Ghidra GUI runtime did not start"),
                cause_type=str(failure.get("cause_type") or ""),
                cause_message=str(failure.get("cause_message") or ""),
            )
        )
    return startup_failed_error(
        StartupFailure(
            stage="launch",
            message="The Ghidra GUI runtime ended before it registered",
            cause_type="",
            # Its log's last line, without the host paths a public cause never shows.
            cause_message=sanitize_cause_message(log_line),
        )
    )


def _runtime_python(*, windows: bool = os.name == "nt") -> tuple[str, dict[str, str] | None]:
    """The interpreter the runtime starts with, and its environment (None: this process's).

    On Windows a venv's python.exe is a redirector that runs the base
    interpreter as its child: the runtime would not be the process started
    here (whose pid the relay waits for in the record), and a detached
    redirector gives that child a console window of its own, whose closing
    ends the runtime.  So the base interpreter starts directly, told which venv
    it runs for, as multiprocessing does (bpo-35797).
    """
    executable = sys.executable
    base = getattr(sys, "_base_executable", None) or executable
    if windows and os.path.normcase(base) != os.path.normcase(executable):
        return base, {**os.environ, "__PYVENV_LAUNCHER__": executable}
    return executable, None


# OpenProcess access right enough for IsProcessInJob.
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
# The detached runtime's exit code when a job of its client's kept it and would end it with the client.
EXIT_KEPT_BY_CLIENT_JOB = 3


def _in_a_job(pid: int) -> bool:
    """Whether the Windows process ``pid`` belongs to any job object; OSError when that cannot be read."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = wintypes.BOOL()
        if not kernel32.IsProcessInJob(handle, None, ctypes.byref(result)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(result.value)
    finally:
        kernel32.CloseHandle(handle)


def _own_job_limit_flags() -> int:
    """The limit flags of the job this Windows process is directly in; OSError outside every job."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]  # fmt: skip
    # JOBOBJECT_EXTENDED_LIMIT_INFORMATION; LimitFlags follows its two LARGE_INTEGERs.
    info = (ctypes.c_ubyte * (144 if ctypes.sizeof(ctypes.c_void_p) == 8 else 112))()
    returned = wintypes.DWORD()
    # A NULL handle is the calling process's own job (the nearest one when jobs nest).
    if not kernel32.QueryInformationJobObject(
        None, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, info, ctypes.sizeof(info), ctypes.byref(returned)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return ctypes.c_uint32.from_buffer(info, 16).value


def kept_by_a_client_job(*, in_a_job=_in_a_job, job_limit_flags=_own_job_limit_flags) -> bool:
    """Whether this runtime, just started detached, stayed in a job that would end it with the client (spec §10.6).

    When the relay's own job forbids breaking away, starting the runtime fails
    (OSError in ``locate_runtime``).  When it allows it but a job around it
    does not, Windows starts the runtime in that outer job without an error.
    Only the runtime can read that job's limits (a process reads its nearest
    job's).  A job that ends its processes when its last handle closes
    (KILL_ON_JOB_CLOSE, as the MCP Python SDK's) would end the GUI with the
    client; one that only groups processes lets the runtime outlive the client.
    """
    if not in_a_job(os.getpid()):
        return False
    return bool(job_limit_flags() & _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)


def _cannot_detach(cause: str) -> DomainError:
    return _unavailable(
        "the Ghidra GUI runtime cannot be detached from this client's job object; start it first in "
        "a terminal with --backend gui --transport http",
        cause_message=cause,
    )


# Windows: the runtime starts through this starter, which then ends, so that the runtime's parent is a
# process that is gone.  A client that ends its server's process tree by parent pid (Claude Code does, when
# the server still runs a few seconds after its stdin closed) then cannot reach the runtime (spec §10.6).
# The starter keeps the runtime's handle, and with it the pid and the exit code, until the relay holds one of
# its own: it reads its stdin to the end first.  The base interpreter takes __PYVENV_LAUNCHER__ out of its
# environment (bpo-35873), so the starter hands it on.  Where the job the starter stayed in does not let it
# leave (a job around the client's), it starts the runtime in that job, which the runtime then reads itself
# (``kept_by_a_client_job``).
_STARTER = """\
import os, subprocess, sys
flags, log, launcher, *command = sys.argv[1:]
env = dict(os.environ)
if launcher:
    env["__PYVENV_LAUNCHER__"] = launcher

def start(creationflags):
    with open(log, "ab") as out:
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                close_fds=True, creationflags=creationflags, env=env)

try:
    runtime = start(int(flags))
except PermissionError:
    runtime = start(int(flags) & ~subprocess.CREATE_BREAKAWAY_FROM_JOB)
print(runtime.pid, flush=True)
sys.stdin.read()
"""
_SYNCHRONIZE = 0x00100000
_STILL_ACTIVE = 259


class _DetachedRuntime:
    """Windows: the runtime a starter started, watched through the relay's own handle as ``Popen`` watches a child."""

    def __init__(self, pid: int, handle: int | None, returncode: int | None = None) -> None:
        self.pid = pid
        self.returncode = returncode
        self._handle = handle  # None: nothing to watch (the runtime never started, or could not be opened)

    def poll(self) -> int | None:
        if self.returncode is None and self._handle:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            code = wintypes.DWORD()
            if kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)) and code.value != _STILL_ACTIVE:
                self.returncode = code.value
                kernel32.CloseHandle(self._handle)
                self._handle = None
        return self.returncode


def _handle_to_watch(pid: int) -> int | None:
    """A handle to the Windows process ``pid`` that reads its exit code; None where it cannot be opened."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    return kernel32.OpenProcess(_SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid) or None


def _start_detached(command: list[str], env: dict[str, str] | None, log_path, log) -> _DetachedRuntime:
    """Windows: start ``command`` outside the relay's console, process group, job object and process tree.

    ``OSError`` when the relay's job does not let the starter leave it; nothing
    starts then.  A starter that could not start the runtime leaves its
    traceback in ``log`` and counts as a runtime that ended at once.
    """
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
    launcher = (env or {}).get("__PYVENV_LAUNCHER__", "")
    starter = subprocess.Popen(  # noqa: S603 - this Python, the operator's arguments
        [command[0], "-I", "-S", "-c", _STARTER, str(flags), str(log_path), launcher, *command],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=log,
        close_fds=True,
        creationflags=flags,
        env=env,
    )
    with starter:  # leaving closes the starter's stdin (it ends then) and waits for it
        line = starter.stdout.readline().strip()
        pid = int(line) if line.isdigit() else None
        handle = _handle_to_watch(pid) if pid is not None else None
    if pid is None:
        return _DetachedRuntime(starter.pid, None, returncode=starter.returncode or 1)
    return _DetachedRuntime(pid, handle)


def launch_runtime(argv: list[str], registry: ProjectRegistry) -> subprocess.Popen | _DetachedRuntime:
    """Start the runtime detached from this relay (spec §10.6); it outlives the relay and its client.

    It runs with this Python and package, reads nothing from stdin, and writes
    to the registry's log file.  On Windows it leaves the client's job object
    and process tree (``_start_detached``); where the job does not allow that,
    ``OSError`` says so and nothing starts.  A job around it that keeps the
    runtime makes the runtime end itself at once (``kept_by_a_client_job``,
    EXIT_KEPT_BY_CLIENT_JOB).
    """
    python, env = _runtime_python()
    command = [python, "-m", RUNTIME_MODULE, *argv]
    # The log may name the user's paths: for its owner only, as the rest of the registry.
    fd = os.open(registry.log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if os.name != "nt":
        os.fchmod(fd, 0o600)  # a log an older launch left keeps its mode otherwise
    with open(fd, "wb") as log:
        if os.name == "nt":
            return _start_detached(command, env, registry.log_path, log)
        # A new session: a client that ends the relay's process group does not end the runtime.
        return subprocess.Popen(  # noqa: S603 - this Python, the operator's arguments
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=env,
            start_new_session=True,
        )


def _wait_for_registration(
    registry: ProjectRegistry, process: subprocess.Popen | _DetachedRuntime
) -> RuntimeRecord | DomainError:
    deadline = time.monotonic() + LAUNCH_WAIT_SECONDS
    while True:
        record = registry.read()
        if record is not None and record.pid == process.pid and registry.runtime_alive():
            return record
        if process.poll() is not None:
            if os.name == "nt" and process.returncode == EXIT_KEPT_BY_CLIENT_JOB:
                return _cannot_detach(
                    "a job object of this client would end the Ghidra GUI runtime when the client exits"
                )
            return _failed_to_start(registry.read(), log_line=_log_tail(registry.log_path))
        if time.monotonic() >= deadline:
            return _unavailable(
                f"the Ghidra GUI runtime did not register within {LAUNCH_WAIT_SECONDS:g} s",
                log_file=str(registry.log_path),
            )
        time.sleep(0.05)


def locate_runtime(argv: list[str], registry: ProjectRegistry) -> RuntimeRecord | DomainError:
    """The project's live runtime, started if none is alive (spec §10.2, steps 2 to 5)."""
    launch_lock = registry.launch_lock()
    if not launch_lock.acquire(LAUNCH_WAIT_SECONDS):
        return _unavailable(f"another relay was still starting the Ghidra GUI runtime after {LAUNCH_WAIT_SECONDS:g} s")
    try:
        if registry.runtime_alive():
            # A runtime writes its record before it lets go of the launch lock (spec §10.1).
            record = registry.read()
            if record is None:
                return _unavailable("the Ghidra GUI runtime of this project left no record")
            return record
        registry.remove()  # a record the ended runtime left behind
        try:
            process = launch_runtime(argv, registry)
        except OSError as exc:
            if os.name == "nt":
                return _cannot_detach(str(exc))
            return _unavailable(f"the Ghidra GUI runtime did not start: {exc}")
        logger.info("Started the Ghidra GUI runtime (pid %d); its log is %s", process.pid, registry.log_path)
        return _wait_for_registration(registry, process)
    finally:
        launch_lock.release()


# ---- talking to the runtime and to the fallback --------------------------------------------------


class RuntimeGone(Exception):
    """The runtime did not answer; ``reached`` says whether the request may have reached it."""

    def __init__(self, message: str, *, reached: bool) -> None:
        super().__init__(message)
        self.reached = reached


# The MCP routing headers, as (name, value) pairs so a duplicate an HTTP client sent stays for the runtime to refuse.
Routing = list[tuple[str, str]]
_ROUTING_HEADERS = frozenset({MCP_PROTOCOL_VERSION_HEADER, MCP_METHOD_HEADER, MCP_NAME_HEADER})


def routing_headers_of(headers: Any) -> Routing:
    """The routing headers an HTTP client sent (protocol version, method, name, ``Mcp-Param-*``), to pass on unchanged."""
    param_prefix = MCP_PARAM_HEADER_PREFIX.lower()
    return [
        (name, value)
        for name, value in headers.items()
        if name.lower() in _ROUTING_HEADERS or name.lower().startswith(param_prefix)
    ]


def derived_routing_headers(message: Mapping[str, Any], negotiated: str | None) -> Routing:
    """The routing headers a Streamable HTTP client sends with ``message``, for a client that sent none (stdio).

    The protocol version is the request's own (``params._meta``, from protocol
    2026-07-28 on) or the one ``initialize`` settled.  ``Mcp-Method`` names the
    method, and ``Mcp-Name`` the tool, prompt or resource a request names.
    """
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    meta = params.get("_meta")
    version = meta.get(PROTOCOL_VERSION_META_KEY) if isinstance(meta, Mapping) else None
    version = version if isinstance(version, str) else negotiated
    headers: Routing = [(MCP_PROTOCOL_VERSION_HEADER, version)] if version else []
    method = message.get("method")
    if isinstance(method, str):
        headers.append((MCP_METHOD_HEADER, method))
        name_key = NAME_BEARING_METHODS.get(method)
        name = params.get(name_key) if name_key else None
        if isinstance(name, str):
            headers.append((MCP_NAME_HEADER, encode_header_value(name)))
    return headers


def _headers(routing: Routing) -> Routing:
    return [("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream"), *routing]


class BadReply(ValueError):
    """A reply body that is no JSON."""


class _Keepalive:
    """What a comment line of an event stream (``: ping``) turns into; it keeps an idle stream open."""

    def __repr__(self) -> str:
        return "KEEPALIVE"


KEEPALIVE = _Keepalive()


@dataclass
class Answer:
    """What a POST got back: the HTTP status, and the JSON-RPC messages the reply carries, as they arrive.

    A plain reply carries one message (none for a 202), an event stream any number of
    notifications and then the reply to the request, with ``KEEPALIVE`` for each ping in between.
    """

    status: int
    messages: AsyncIterator[Any]


@dataclass
class Reply:
    """What a relay answers with: the HTTP status and the messages of the reply (see ``Answer``)."""

    status: int
    messages: AsyncIterator[Any]


async def _only(message: dict[str, Any]) -> AsyncIterator[Any]:
    yield message


def _decode(text: str | bytes) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise BadReply(str(exc)) from exc


async def _json_messages(payload: bytes) -> AsyncIterator[Any]:
    if payload:
        yield _decode(payload)


async def _event_messages(lines: AsyncIterator[str]) -> AsyncIterator[Any]:
    """The JSON bodies of a ``text/event-stream``, one for each event that has data."""
    data: list[str] = []
    async for line in lines:
        if line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif line == "":  # the blank line that ends an event
            if data:
                yield _decode("\n".join(data))
                data = []
        elif line.startswith(":"):
            yield KEEPALIVE
        # event:, id: and retry: name nothing the runtime needs
    if data:  # the stream ended inside an event
        yield _decode("\n".join(data))


class RuntimeEndpoint:
    """The runtime's loopback endpoint, with its token."""

    def __init__(self, record: RuntimeRecord) -> None:
        self.record = record
        self._client: httpx2.AsyncClient | None = None

    @contextlib.asynccontextmanager
    async def connected(self):
        # trust_env=False: a proxy set in the environment never sees the loopback traffic or the token.
        # No kept-alive connections: one uvicorn closes when idle would look like a call broken halfway.
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {self.record.token}"},
            timeout=httpx2.Timeout(RUNTIME_TIMEOUT_SECONDS, connect=5.0),
            limits=httpx2.Limits(max_connections=None, max_keepalive_connections=0),
            trust_env=False,
        ) as client:
            self._client = client
            try:
                yield self
            finally:
                self._client = None

    @contextlib.asynccontextmanager
    async def post(self, body: bytes, routing: Routing) -> AsyncIterator[Answer]:
        """POST ``body``; the answer is there once the runtime has sent its headers, and the connection closes with the block."""
        assert self._client is not None, "RuntimeEndpoint.connected() first"
        async with contextlib.AsyncExitStack() as stack:
            try:
                response = await stack.enter_async_context(
                    self._client.stream("POST", self.record.endpoint, content=body, headers=_headers(routing))
                )
            except (httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.PoolTimeout) as exc:
                raise RuntimeGone(f"cannot connect: {exc}", reached=False) from exc
            except httpx2.TransportError as exc:
                raise RuntimeGone(f"the connection broke: {exc!r}", reached=True) from exc
            yield Answer(response.status_code, self._messages(response))

    @staticmethod
    async def _messages(response: httpx2.Response) -> AsyncIterator[Any]:
        try:
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                async with contextlib.aclosing(_event_messages(response.aiter_lines())) as events:
                    async for message in events:
                        yield message
            else:
                async for message in _json_messages(await response.aread()):
                    yield message
        except httpx2.TransportError as exc:
            raise RuntimeGone(f"the connection broke: {exc!r}", reached=True) from exc


class RelayGate(StartupGate):
    """The fallback's startup gate: every tool call gets the relay's refusal."""

    def __init__(self) -> None:
        super().__init__()
        self.refusal: DomainError = _unavailable("this relay has no Ghidra GUI runtime")

    async def wait(self, timeout: float) -> float:
        raise self.refusal


class Fallback:
    """The relay's own MCP server for its tools, answering in the runtime's place (see the module docstring)."""

    def __init__(self, specs: Mapping[str, ToolSpec], presentation_config) -> None:
        from .mcp_server import create_mcp_server

        self.gate = RelayGate()

        def no_dispatch():  # the gate refuses every call first
            raise RuntimeError("the relay's fallback runs no tool")

        runtime = create_mcp_server(
            specs=dict(specs),
            registry_provider=lambda: None,
            dispatcher_provider=lambda: no_dispatch,
            presentation_config=presentation_config,
            startup_gate=self.gate,
        )
        self.server = runtime.mcp
        self.app = self.server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            json_response=True,
            transport_security=resolve_transport_security_for_host("127.0.0.1"),
        )
        self._client: httpx2.AsyncClient | None = None

    @contextlib.asynccontextmanager
    async def running(self):
        """Run the app's session manager (its lifespan) and a client that calls the app in this process."""
        async with (
            self.server.session_manager.run(),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=self.app), base_url="http://127.0.0.1", trust_env=False
            ) as client,
        ):
            self._client = client
            try:
                yield self
            finally:
                self._client = None

    @contextlib.asynccontextmanager
    async def post(self, body: bytes, routing: Routing) -> AsyncIterator[Answer]:
        assert self._client is not None, "Fallback.running() first"
        response = await self._client.post("/mcp", content=body, headers=_headers(routing))
        yield Answer(response.status_code, _json_messages(response.content))


# ---- the relay ----------------------------------------------------------------------------------


class Relay:
    """Forward JSON-RPC to the runtime; send the fallback what the runtime cannot answer (spec §10.3, §10.4)."""

    def __init__(
        self,
        *,
        specs: Mapping[str, ToolSpec],
        fallback: Fallback,
        runtime: RuntimeEndpoint | None,
        refusal: DomainError | None,
        registry: ProjectRegistry | None = None,
    ) -> None:
        self.specs = specs
        # What this relay publishes: its specs and the result tools its presentation adds (read_result, ...).
        self.tools = frozenset(fallback.server.bindings)
        self.fallback = fallback
        self.runtime = runtime
        self.registry = registry
        self.protocol_version: str | None = None
        self._gone = runtime is None
        if refusal is not None:
            self._gone = True
            fallback.gate.refusal = refusal

    def _runtime_gone(self) -> None:
        """No auto-restart (spec §10.2): later calls hear why, as the runtime's record tells it."""
        if self._gone:
            return
        self._gone = True
        record = self.registry.read() if self.registry is not None else None
        ours = self.runtime.record if self.runtime is not None else None
        if record is not None and ours is not None and record.runtime_id == ours.runtime_id and record.state == FAILED:
            self.fallback.gate.refusal = _failed_to_start(record)
        else:
            self.fallback.gate.refusal = _unavailable(
                "the Ghidra GUI runtime of this project went away; this client does not start it again",
                reason="runtime_gone",
            )
        logger.error("The Ghidra GUI runtime is gone: %s", self.fallback.gate.refusal.message)

    def _in_flight_error(self, message: dict[str, Any], cause: str) -> dict[str, Any]:
        """A call the runtime may have run before it went away: its outcome is unknown."""
        name = str((message.get("params") or {}).get("name") or "")
        error = _unavailable(
            "the Ghidra GUI runtime went away during the call; it may have run", outcome="unknown", cause=cause
        )
        spec = self.specs.get(name)
        if spec is not None and spec.writes:
            error = with_output_state(error, UNCERTAIN)
        result = domain_error_result(error).model_dump(mode="json", by_alias=True, exclude_none=True)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": result}

    @contextlib.asynccontextmanager
    async def open(self, message: dict[str, Any], routing: Routing | None = None) -> AsyncIterator[Reply]:
        """Forward ``message``: the HTTP status, and the messages of the reply as they arrive.

        A call that waits may send notifications (progress) before its reply, and they are passed on at
        once.  A notification of the client gets no message back.  ``routing`` is what an HTTP client
        sent; without it (stdio), the relay sends the routing headers an HTTP client would.
        """
        method = message.get("method")
        if routing is None:
            routing = derived_routing_headers(message, self.protocol_version)
        body = json.dumps(message).encode()
        to_fallback = self._gone or (
            method == "tools/call" and str((message.get("params") or {}).get("name")) not in self.tools
        )
        async with contextlib.AsyncExitStack() as stack:
            reply: Reply | None = None
            if not to_fallback:
                try:
                    answer = await stack.enter_async_context(self.runtime.post(body, routing))
                except RuntimeGone as exc:
                    self._runtime_gone()
                    if method == "tools/call" and exc.reached and "id" in message:
                        reply = Reply(200, _only(self._in_flight_error(message, str(exc))))
                else:
                    if answer.status == 401:  # another runtime took the project (the token is not its)
                        self._runtime_gone()
                    else:
                        reply = Reply(answer.status, self._replies(message, answer))
            if reply is None:
                answer = await stack.enter_async_context(self.fallback.post(body, routing))
                reply = Reply(answer.status, self._replies(message, answer))
            yield reply

    async def _replies(self, message: dict[str, Any], answer: Answer) -> AsyncIterator[Any]:
        """The messages of ``answer`` for the client: notifications as they are, the reply filtered."""
        method = message.get("method")
        answered = seen = False
        try:
            async with contextlib.aclosing(answer.messages) as messages:
                async for item in messages:
                    seen = True
                    if item is KEEPALIVE or (isinstance(item, dict) and "method" in item):
                        yield item  # a ping, or a notification of the server
                    elif isinstance(item, dict):
                        answered = True
                        yield self._filtered(method, item)
                    else:
                        answered = True
                        yield self._without_json_rpc(message, answer.status)
        except BadReply:
            answered = True
            yield self._without_json_rpc(message, answer.status)
        except RuntimeGone as exc:
            self._runtime_gone()
            if "id" in message:
                answered = True
                yield self._went_away(message, str(exc))
        if seen and not answered and "id" in message:
            yield self._went_away(message, "the reply ended before it answered the request")

    def _went_away(self, message: dict[str, Any], cause: str) -> dict[str, Any]:
        """The reply for a request the runtime had begun to answer: a call may have run, anything else failed."""
        if message.get("method") == "tools/call":
            return self._in_flight_error(message, cause)
        error = {"code": -32603, "message": "the Ghidra GUI runtime went away while it answered the request"}
        return {"jsonrpc": "2.0", "id": message.get("id"), "error": error}

    @staticmethod
    def _without_json_rpc(message: dict[str, Any], status: int) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32603, "message": f"the Ghidra GUI runtime answered HTTP {status} without JSON-RPC"},
        }

    async def exchange(
        self, message: dict[str, Any], routing: Routing | None = None
    ) -> tuple[int, dict[str, Any] | None]:
        """Forward ``message``: the HTTP status and the reply (None for a notification).

        What the runtime sends before the reply (progress) has no place in one JSON body and is left out.
        """
        async with self.open(message, routing) as reply:
            answer = None
            async for item in reply.messages:
                if item is not KEEPALIVE and "method" not in item:
                    answer = item
            return reply.status, answer

    async def handle(self, message: dict[str, Any], routing: Routing | None = None) -> dict[str, Any] | None:
        return (await self.exchange(message, routing))[1]

    def _filtered(self, method: Any, reply: dict[str, Any] | None) -> dict[str, Any] | None:
        if reply is None:
            return None
        result = reply.get("result")
        if method == "initialize" and isinstance(result, dict) and result.get("protocolVersion"):
            self.protocol_version = str(result["protocolVersion"])
        if method == "tools/list" and isinstance(result, dict) and isinstance(result.get("tools"), list):
            # A narrower relay publishes its own tools only (spec §10.3).
            result["tools"] = [tool for tool in result["tools"] if tool.get("name") in self.tools]
        return reply

    async def exchange_body(self, body: bytes, routing: Routing | None = None) -> tuple[int, bytes | None]:
        """One wire message (or a batch of them): the HTTP status and the reply to write (None: notifications only)."""
        try:
            message = json.loads(body)
        except ValueError:
            reply: Any = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            return 400, json.dumps(reply).encode()
        if isinstance(message, list):
            replies = [await self.handle(item, routing) for item in message if isinstance(item, dict)]
            answered = [reply for reply in replies if reply is not None]
            return (200, json.dumps(answered).encode()) if answered else (202, None)
        if not isinstance(message, dict):
            return 400, json.dumps(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
            ).encode()
        status, reply = await self.exchange(message, routing)
        return status, None if reply is None else json.dumps(reply).encode()

    async def handle_body(self, body: bytes, routing: Routing | None = None) -> bytes | None:
        """One wire message (or a batch of them): the reply to write, or None for notifications only."""
        return (await self.exchange_body(body, routing))[1]


# ---- serving the relay ---------------------------------------------------------------------------


async def serve_stdio(relay: Relay) -> None:
    """Relay stdin to the runtime and its replies to stdout, one JSON-RPC message per line (spec §10.4).

    Requests run concurrently, so a long call does not hold up the others;
    ``initialize`` is answered before the next line is read, since the
    protocol version it settles goes with every later request.  Anything else
    that writes to fd 1 goes to stderr instead.
    """
    wire = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    loop = asyncio.get_running_loop()
    lines: asyncio.Queue[bytes | None] = asyncio.Queue()

    def read_stdin() -> None:
        for line in sys.stdin.buffer:
            loop.call_soon_threadsafe(lines.put_nowait, line)
        loop.call_soon_threadsafe(lines.put_nowait, None)

    threading.Thread(target=read_stdin, name="relay-stdin", daemon=True).start()
    write_lock = asyncio.Lock()
    pending: set[asyncio.Task] = set()

    async def write(message: Any) -> None:
        async with write_lock:
            wire.write(json.dumps(message).encode() + b"\n")

    async def answer(line: bytes) -> None:
        message = single_message(line)
        if message is None:  # a batch, or no JSON-RPC object
            reply = await relay.handle_body(line)
            if reply is not None:
                async with write_lock:
                    wire.write(reply + b"\n")
            return
        async with relay.open(message) as reply:
            async for item in reply.messages:
                if item is not KEEPALIVE:  # a stdio client needs no ping
                    await write(item)

    def is_initialize(line: bytes) -> bool:
        with contextlib.suppress(ValueError):
            message = json.loads(line)
            return isinstance(message, dict) and message.get("method") == "initialize"
        return False

    try:
        while (line := await lines.get()) is not None:
            if not line.strip():
                continue
            if is_initialize(line):
                await answer(line)
                continue
            task = asyncio.create_task(answer(line))
            pending.add(task)
            task.add_done_callback(pending.discard)
        if pending:
            await asyncio.wait(pending, timeout=5)
    finally:
        wire.close()


def single_message(body: bytes) -> dict[str, Any] | None:
    """The JSON-RPC message ``body`` holds, or None if it is a batch, not JSON or no object."""
    try:
        message = json.loads(body)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


_EVENT_STREAM_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def _event(message: Any) -> bytes:
    if message is KEEPALIVE:
        return b": ping\r\n\r\n"
    return b"event: message\r\ndata: " + json.dumps(message, separators=(",", ":")).encode() + b"\r\n\r\n"


def _http_relay_app(relay: Relay, *, path: str, host: str):
    from mcp.server.transport_security import TransportSecurityMiddleware
    from starlette.applications import Starlette
    from starlette.responses import Response, StreamingResponse
    from starlette.routing import Route

    class EventStream(StreamingResponse):
        """An event stream that closes what feeds it, whether it ends or its client goes away."""

        async def stream_response(self, send) -> None:
            try:
                await super().stream_response(send)
            finally:
                with anyio.CancelScope(shield=True):
                    await self.body_iterator.aclose()

    security = TransportSecurityMiddleware(resolve_transport_security_for_host(host))

    async def endpoint(request):
        refused = await security.validate_request(request, is_post=request.method == "POST")
        if refused is not None:
            return refused
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        body, routing = await request.body(), routing_headers_of(request.headers)
        message = single_message(body)
        if message is None:  # a batch, or no JSON-RPC object: one JSON body, however long it takes
            status, reply = await relay.exchange_body(body, routing)
            if reply is None:
                return Response(status_code=202)
            return Response(reply, status_code=status, media_type="application/json")
        # The reply is JSON unless the runtime has something to say before it (progress): then an event
        # stream, from the first notification on, like the runtime's own.  A client of protocol 2026-07-28
        # or later reads the status too (400 for an unsupported version).
        stack = contextlib.AsyncExitStack()
        try:
            reply = await stack.enter_async_context(relay.open(message, routing))
            messages = reply.messages.__aiter__()
            first = await anext(messages, None)
            while first is KEEPALIVE:
                first = await anext(messages, None)
            if first is None or "method" not in first:
                await stack.aclose()
                if first is None:
                    return Response(status_code=202)
                return Response(json.dumps(first), status_code=reply.status, media_type="application/json")
        except BaseException:
            await stack.aclose()
            raise

        async def events():
            try:
                yield _event(first)
                async for item in messages:
                    yield _event(item)
            finally:
                # The client may have gone (this then runs cancelled): the runtime's connection still closes.
                with anyio.CancelScope(shield=True):
                    await messages.aclose()
                    await stack.aclose()

        return EventStream(
            events(), status_code=reply.status, media_type="text/event-stream", headers=_EVENT_STREAM_HEADERS
        )

    return Starlette(routes=[Route(path, endpoint, methods=["GET", "POST", "DELETE"])])


async def serve_http(relay: Relay, *, host: str, port: int, path: str, log_level: str) -> None:
    """``--transport http`` while the project's runtime runs already: a relay at the user's address (spec §10.5)."""
    import uvicorn

    from .transport import uvicorn_log_level

    app = _http_relay_app(relay, path=path, host=host)
    config = uvicorn.Config(app, host=host, port=port, log_level=uvicorn_log_level(log_level))
    await uvicorn.Server(config).serve()


def run_relay(
    *,
    argv: list[str],
    registry: ProjectRegistry,
    specs: Mapping[str, ToolSpec],
    config: RuntimeConfig,
    presentation_config,
    transport: str,
    http_options: dict[str, Any] | None = None,
    log_level: str = "INFO",
) -> int:
    """Find or start the runtime, check its configuration, then relay until the client ends (spec §10)."""
    # One line per forwarded request, and the fallback's session manager, are noise in a client's log.
    for noisy in ("httpx2", "httpcore2", "mcp.server.streamable_http_manager"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    located = locate_runtime(argv, registry)
    runtime: RuntimeEndpoint | None = None
    refusal: DomainError | None = None
    if isinstance(located, DomainError):
        refusal = located
        logger.error("%s: %s", located.code.value, located.message)
    else:
        refusal = config_mismatch(located, config)
        if refusal is None:
            _log_setting_differences(located, config)
            runtime = RuntimeEndpoint(located)
            logger.info("Relaying to the Ghidra GUI runtime %s (pid %d)", located.runtime_id, located.pid)
        else:
            logger.error("%s: %s", refusal.message, refusal.details)

    async def serve() -> None:
        fallback = Fallback(specs, presentation_config)
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(fallback.running())
            if runtime is not None:
                await stack.enter_async_context(runtime.connected())
            relay = Relay(specs=specs, fallback=fallback, runtime=runtime, refusal=refusal, registry=registry)
            if transport == "stdio":
                await serve_stdio(relay)
            else:
                await serve_http(relay, log_level=log_level, **(http_options or {}))

    asyncio.run(serve())
    return 0


# ---- the runtime's side --------------------------------------------------------------------------


class RuntimeRegistration:
    """This process as the project's runtime: it holds the lock and keeps its record current (spec §10.1)."""

    def __init__(self, registry: ProjectRegistry, lock, launch_lock=None) -> None:
        self.registry = registry
        self._lock = lock
        # Held from the claim until the record is written (a runtime in the foreground); see release_launch.
        self.launch_lock = launch_lock
        self.record: RuntimeRecord | None = None
        self.token = secrets.token_urlsafe(32)
        self.runtime_id = uuid.uuid4().hex
        self._closed = False
        self._write = threading.Lock()

    def publish(
        self,
        *,
        endpoint: str,
        public: bool,
        config: RuntimeConfig,
        ghidra_path: str | None,
    ) -> RuntimeRecord:
        self.record = RuntimeRecord(
            runtime_id=self.runtime_id,
            pid=os.getpid(),
            endpoint=endpoint,
            token=self.token,
            public=public,
            project_file=self.registry.project_file,
            ghidra_install_dir=os.path.realpath(ghidra_path) if ghidra_path else None,
            mecha_version=package_version(),
            fingerprint=config.fingerprint,
            settings=config.settings,
            log_file=str(self.registry.log_path) if not public else None,
        )
        self.registry.write(self.record)
        return self.record

    def on_startup_end(self, state: str, failure: StartupFailure | None) -> None:
        """The startup gate's listener: relays read ``ready``, or ``failed`` with the reason."""
        with self._write:
            if self.record is None or self._closed:
                return
            self.record.state = READY if state == READY else FAILED
            if failure is not None:
                self.record.failure = {
                    "stage": failure.stage,
                    "message": failure.message,
                    "cause_type": failure.cause_type,
                    "cause_message": failure.cause_message,
                }
            self.registry.write(self.record)

    def close(self) -> None:
        """The runtime is CLOSED (the human closed its project): new relays start a new one (spec §5.1)."""
        with self._write:
            if self._closed:
                return
            self._closed = True
            record = self.registry.read()
            if record is not None and record.runtime_id == self.runtime_id:
                self.registry.remove()
            self._lock.release()


def claim_runtime(registry: ProjectRegistry, *, wait_for_launch: bool) -> RuntimeRegistration | None:
    """Take the project's runtime lock; None when another runtime holds it.

    A runtime started in the foreground takes the launch lock around the claim,
    as relays do, so it never races one that is starting a runtime; the
    detached runtime is started while its relay holds that lock.  The caller
    releases the launch lock once the record is written (``release_launch``).
    """
    launch_lock = None
    if wait_for_launch:
        launch_lock = registry.launch_lock()
        if not launch_lock.acquire(LAUNCH_WAIT_SECONDS):
            raise TimeoutError(
                f"another relay was still starting the Ghidra GUI runtime after {LAUNCH_WAIT_SECONDS:g} s"
            )
    lock = registry.runtime_lock()
    if not lock.try_acquire():
        if launch_lock is not None:
            launch_lock.release()
        return None
    return RuntimeRegistration(registry, lock, launch_lock)


def release_launch(registration: RuntimeRegistration) -> None:
    if registration.launch_lock is not None:
        registration.launch_lock.release()
        registration.launch_lock = None


def free_loopback_socket() -> socket.socket:
    """A listening socket on a free loopback port, for the detached runtime's endpoint (spec §10.7)."""
    sock = socket.create_server(("127.0.0.1", 0), backlog=128)
    sock.set_inheritable(False)
    return sock


__all__ = [
    "EXIT_KEPT_BY_CLIENT_JOB",
    "LAUNCH_WAIT_SECONDS",
    "Fallback",
    "Relay",
    "RelayGate",
    "RuntimeConfig",
    "RuntimeEndpoint",
    "RuntimeGone",
    "RuntimeRegistration",
    "claim_runtime",
    "config_mismatch",
    "free_loopback_socket",
    "kept_by_a_client_job",
    "launch_runtime",
    "locate_runtime",
    "release_launch",
    "run_relay",
    "runtime_config",
]
