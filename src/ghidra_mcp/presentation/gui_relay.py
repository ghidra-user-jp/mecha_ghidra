"""Relays of the Ghidra GUI backend: stdio and HTTP clients reach the project's runtime through them (spec §10).

A relay starts no JVM.  It finds the runtime of its project in the registry
(``gui_registry``), or starts one detached from itself, checks that the
runtime runs with its configuration (spec §10.3), and then forwards each
JSON-RPC message to the runtime's loopback endpoint as it is.  The runtime
answers every request with one JSON body (stateless Streamable HTTP), so
forwarding needs no MCP session of its own.

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
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx2

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


def launch_runtime(argv: list[str], registry: ProjectRegistry) -> subprocess.Popen:
    """Start the runtime detached from this relay (spec §10.6); it outlives the relay and its client.

    It runs with this Python and package, reads nothing from stdin, and writes
    to the registry's log file.  On Windows it leaves the client's job object;
    where the job does not allow that, ``OSError`` says so and nothing starts.
    """
    command = [sys.executable, "-m", RUNTIME_MODULE, *argv]
    options: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT, "close_fds": True}
    if os.name == "nt":
        options["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
        )
    else:
        # A new session: a client that ends the relay's process group does not end the runtime.
        options["start_new_session"] = True
    # The log may name the user's paths: for its owner only, as the rest of the registry.
    fd = os.open(registry.log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if os.name != "nt":
        os.fchmod(fd, 0o600)  # a log an older launch left keeps its mode otherwise
    with open(fd, "wb") as log:
        return subprocess.Popen(command, stdout=log, **options)  # noqa: S603 - this Python, the operator's arguments


def _wait_for_registration(registry: ProjectRegistry, process: subprocess.Popen) -> RuntimeRecord | DomainError:
    deadline = time.monotonic() + LAUNCH_WAIT_SECONDS
    while True:
        record = registry.read()
        if record is not None and record.pid == process.pid and registry.runtime_alive():
            return record
        if process.poll() is not None:
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
                return _unavailable(
                    "the Ghidra GUI runtime cannot be detached from this client's job object; start it first in "
                    "a terminal with --backend gui --transport http",
                    cause_message=str(exc),
                )
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


def _headers(protocol_version: str | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if protocol_version:
        headers["MCP-Protocol-Version"] = protocol_version
    return headers


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

    async def post(self, body: bytes, protocol_version: str | None) -> tuple[int, bytes]:
        assert self._client is not None, "RuntimeEndpoint.connected() first"
        try:
            response = await self._client.post(self.record.endpoint, content=body, headers=_headers(protocol_version))
        except (httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.PoolTimeout) as exc:
            raise RuntimeGone(f"cannot connect: {exc}", reached=False) from exc
        except httpx2.TransportError as exc:
            raise RuntimeGone(f"the connection broke: {exc!r}", reached=True) from exc
        return response.status_code, response.content


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

    async def post(self, body: bytes, protocol_version: str | None) -> tuple[int, bytes]:
        assert self._client is not None, "Fallback.running() first"
        response = await self._client.post("/mcp", content=body, headers=_headers(protocol_version))
        return response.status_code, response.content


# ---- the relay ----------------------------------------------------------------------------------


def _parse_reply(status: int, payload: bytes, message_id: Any) -> dict[str, Any] | None:
    if not payload:
        return None
    try:
        reply = json.loads(payload)
    except ValueError:
        reply = None
    if isinstance(reply, dict):
        return reply
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": -32603, "message": f"the Ghidra GUI runtime answered HTTP {status} without JSON-RPC"},
    }


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

    async def handle(self, message: dict[str, Any], protocol_version: str | None = None) -> dict[str, Any] | None:
        method = message.get("method")
        version = protocol_version or self.protocol_version
        body = json.dumps(message).encode()
        to_fallback = self._gone or (
            method == "tools/call" and str((message.get("params") or {}).get("name")) not in self.tools
        )
        if not to_fallback:
            try:
                status, payload = await self.runtime.post(body, version)
            except RuntimeGone as exc:
                self._runtime_gone()
                if method == "tools/call" and exc.reached and "id" in message:
                    return self._in_flight_error(message, str(exc))
            else:
                if status == 401:  # another runtime took the project (the token is not its)
                    self._runtime_gone()
                else:
                    reply = _parse_reply(status, payload, message.get("id"))
                    return self._filtered(method, reply)
        status, payload = await self.fallback.post(body, version)
        return self._filtered(method, _parse_reply(status, payload, message.get("id")))

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

    async def handle_body(self, body: bytes, protocol_version: str | None = None) -> bytes | None:
        """One wire message (or a batch of them): the reply to write, or None for notifications only."""
        try:
            message = json.loads(body)
        except ValueError:
            reply: Any = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            return json.dumps(reply).encode()
        if isinstance(message, list):
            replies = [await self.handle(item, protocol_version) for item in message if isinstance(item, dict)]
            answered = [reply for reply in replies if reply is not None]
            return json.dumps(answered).encode() if answered else None
        if not isinstance(message, dict):
            return json.dumps(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
            ).encode()
        reply = await self.handle(message, protocol_version)
        return None if reply is None else json.dumps(reply).encode()


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

    async def answer(line: bytes) -> None:
        reply = await relay.handle_body(line)
        if reply is not None:
            async with write_lock:
                wire.write(reply + b"\n")

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


def _http_relay_app(relay: Relay, *, path: str, host: str):
    from mcp.server.transport_security import TransportSecurityMiddleware
    from starlette.applications import Starlette
    from starlette.responses import Response
    from starlette.routing import Route

    security = TransportSecurityMiddleware(resolve_transport_security_for_host(host))

    async def endpoint(request):
        refused = await security.validate_request(request, is_post=request.method == "POST")
        if refused is not None:
            return refused
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        reply = await relay.handle_body(await request.body(), request.headers.get("mcp-protocol-version"))
        if reply is None:
            return Response(status_code=202)
        return Response(reply, media_type="application/json")

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
    "launch_runtime",
    "locate_runtime",
    "release_launch",
    "run_relay",
    "runtime_config",
]
