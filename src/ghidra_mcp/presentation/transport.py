"""Run the low-level MCP server over stdio or stateless Streamable HTTP."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import signal
import threading
from dataclasses import dataclass
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

from ghidra_mcp.presentation.mcp_server import normalize_server_log_level

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
DEFAULT_HTTP_PORT = 8081


def normalize_transport(transport: str) -> str:
    return "streamable-http" if transport == "http" else transport


def normalize_streamable_http_path(path: str) -> str:
    normalized = (path or "").strip()
    if not normalized:
        return "/mcp"
    if not normalized.startswith("/"):
        return "/" + normalized
    return normalized


def normalize_host(host: str) -> str:
    return (host or "").strip().lower()


def _transport_security_for_hosts(hosts: tuple[str, ...]) -> TransportSecuritySettings:
    allowed_hosts: list[str] = []
    allowed_origins: list[str] = []
    for host in hosts:
        # Host headers omit the port for a transport's default port and include
        # it otherwise.  Origin may use HTTPS when a reverse proxy terminates
        # TLS, even though the backend itself listens over HTTP.
        allowed_hosts.extend((host, f"{host}:*"))
        for scheme in ("http", "https"):
            origin = f"{scheme}://{host}"
            allowed_origins.extend((origin, f"{origin}:*"))
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def resolve_transport_security_for_host(host: str) -> TransportSecuritySettings:
    normalized = normalize_host(host)
    if normalized in {"127.0.0.1", "localhost", "::1"}:
        return _transport_security_for_hosts(_LOOPBACK_HOSTS)
    if normalized in {"0.0.0.0", "::"}:  # noqa: S104 - detecting, not binding
        # A wildcard listen address is necessary inside the Docker container,
        # but it must not imply that every Host/Origin is trusted.  Keep the
        # listener reachable through the loopback-published Compose port while
        # rejecting DNS-rebinding and LAN Host headers.  Operators that need
        # remote access must bind a fixed IP/hostname explicitly.
        return _transport_security_for_hosts(_LOOPBACK_HOSTS)
    if ":" in normalized and not normalized.startswith("["):
        normalized = f"[{normalized}]"
    return _transport_security_for_hosts((normalized,))


def transport_security_for_host(*, host: str, logger: logging.Logger) -> TransportSecuritySettings:
    settings = resolve_transport_security_for_host(host)
    if normalize_host(host) in {"0.0.0.0", "::"}:  # noqa: S104 - detecting, not binding
        logger.warning(
            "MCP is listening on wildcard host %s, but DNS rebinding protection "
            "accepts only loopback Host/Origin values. Bind a fixed IP/hostname "
            "and use TLS plus access controls for intentional remote access.",
            host,
        )
    return settings


def _apply_log_level(args: Any) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))


def streamable_http_run_kwargs(*, args: Any, logger: logging.Logger) -> dict[str, Any]:
    """HTTP listener and public ``Server.streamable_http_app`` options."""

    _apply_log_level(args)
    host = args.mcp_host
    port = args.mcp_port or DEFAULT_HTTP_PORT
    path = normalize_streamable_http_path(args.mcp_path)
    logger.info("Starting MCP in stateless Streamable HTTP mode (JSON responses): http://%s:%s%s", host, port, path)
    return {
        "host": host,
        "port": port,
        "streamable_http_path": path,
        # Official Python SDK's recommended Streamable HTTP configuration.
        # Application state (Ghidra targets and result cache) outlives requests.
        "stateless_http": True,
        "json_response": True,
        "transport_security": transport_security_for_host(host=host, logger=logger),
    }


def run_kwargs_for_transport(*, transport: str, args: Any, logger: logging.Logger) -> dict[str, Any]:
    normalized = normalize_transport(transport)
    if normalized == "streamable-http":
        return streamable_http_run_kwargs(args=args, logger=logger)
    if normalized == "stdio":
        return {}
    raise ValueError(f"Unsupported transport: {transport}")


@dataclass(frozen=True)
class RuntimeAuth:
    """The token a Ghidra GUI runtime's relays send (spec §10.7).

    ``public``: the runtime was started in the foreground with the user's HTTP
    listener, which takes requests without a token as before; a request that
    sends a token must still send the right one.
    """

    token: str
    public: bool = False


class BearerToken:
    """ASGI middleware: refuse HTTP requests without ``Authorization: Bearer <token>`` (unless public)."""

    def __init__(self, app, auth: RuntimeAuth) -> None:
        self.app = app
        self._expected = f"Bearer {auth.token}".encode()
        self._public = auth.public

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            values = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
            if values:
                allowed = len(values) == 1 and hmac.compare_digest(values[0], self._expected)
            else:
                allowed = self._public
            if not allowed:
                body = json.dumps({"error": "unauthorized"}).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"www-authenticate", b"Bearer"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def uvicorn_log_level(log_level: str | None) -> str:
    """Lower-case uvicorn level name for a free-form ``--log-level`` value."""

    return normalize_server_log_level(log_level).lower()


@contextlib.contextmanager
def _graceful_hangup(http_server):
    """Give SIGHUP the graceful shutdown uvicorn gives only SIGINT and SIGTERM.

    uvicorn stops accepting, finishes the requests in flight and then replays
    the signals it caught; SIGHUP is replayed the same way once serving ends,
    so the CLI's handler cleans up and exits with 128 + SIGHUP.
    """
    sighup = getattr(signal, "SIGHUP", None)
    if (
        sighup is None
        or threading.current_thread() is not threading.main_thread()
        or signal.getsignal(sighup) is signal.SIG_IGN
    ):
        yield
        return
    hangups: list[int] = []

    def hang_up(signum, frame):
        hangups.append(signum)
        http_server.handle_exit(signum, frame)

    previous = signal.signal(sighup, hang_up)
    try:
        yield
    finally:
        signal.signal(sighup, signal.SIG_DFL if previous is None else previous)
    if hangups:
        signal.raise_signal(sighup)


def run_mcp_server(server, *, transport: str, log_level: str = "INFO", startup=None, **kwargs) -> None:
    """Serve ``server`` until the transport ends.

    ``startup`` (a ``presentation.startup.BackgroundStartup``) begins once the
    transport accepts requests, with the event loop for its main-thread steps.
    A failed startup ends an HTTP server; a stdio server keeps answering, with
    the failure, until its client disconnects.
    """
    normalized = normalize_transport(transport)

    async def serve_stdio():
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            # fd 1 now points at stderr, so nothing the startup prints reaches the wire.
            if startup is not None:
                startup.start(loop=asyncio.get_running_loop())
            await server.run(read_stream, write_stream, server.create_initialization_options())

    async def serve_http():
        import uvicorn

        options = dict(kwargs)
        port = options.pop("port", DEFAULT_HTTP_PORT)
        # A listening socket the caller bound already (a detached GUI runtime's free loopback port).
        sock = options.pop("sock", None)
        auth = options.pop("auth", None)
        host = options.get("host", "127.0.0.1")
        app = server.streamable_http_app(**options)
        if auth is not None:
            app = BearerToken(app, auth)
        # uvicorn accepts only its own level names: the CLI's WARN/FATAL
        # aliases must be normalised first, exactly as the MCP server does.
        config = uvicorn.Config(app, host=host, port=port, log_level=uvicorn_log_level(log_level))
        http_server = uvicorn.Server(config)
        if startup is not None:

            def stop_serving() -> None:
                http_server.should_exit = True

            startup.start(loop=asyncio.get_running_loop(), stop_serving=stop_serving)
        with _graceful_hangup(http_server):
            if sock is None:
                await http_server.serve()
            else:
                await http_server.serve(sockets=[sock])

    if normalized == "stdio":
        asyncio.run(serve_stdio())
    elif normalized == "streamable-http":
        asyncio.run(serve_http())
    else:
        raise ValueError(f"Unsupported transport: {transport}")


__all__ = [
    "DEFAULT_HTTP_PORT",
    "BearerToken",
    "RuntimeAuth",
    "normalize_host",
    "normalize_streamable_http_path",
    "normalize_transport",
    "resolve_transport_security_for_host",
    "run_kwargs_for_transport",
    "run_mcp_server",
    "streamable_http_run_kwargs",
    "transport_security_for_host",
    "uvicorn_log_level",
]
