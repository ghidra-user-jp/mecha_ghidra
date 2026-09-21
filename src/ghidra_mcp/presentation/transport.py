"""Run the low-level MCP server over stdio or stateless Streamable HTTP."""

from __future__ import annotations

import asyncio
import logging
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


def uvicorn_log_level(log_level: str | None) -> str:
    """Lower-case uvicorn level name for a free-form ``--log-level`` value."""

    return normalize_server_log_level(log_level).lower()


def run_mcp_server(server, *, transport: str, log_level: str = "INFO", **kwargs) -> None:
    normalized = normalize_transport(transport)

    async def serve_stdio():
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    async def serve_http():
        import uvicorn

        options = dict(kwargs)
        port = options.pop("port", DEFAULT_HTTP_PORT)
        host = options.get("host", "127.0.0.1")
        app = server.streamable_http_app(**options)
        # uvicorn accepts only its own level names: the CLI's WARN/FATAL
        # aliases must be normalised first, exactly as the MCP server does.
        config = uvicorn.Config(app, host=host, port=port, log_level=uvicorn_log_level(log_level))
        await uvicorn.Server(config).serve()

    if normalized == "stdio":
        asyncio.run(serve_stdio())
    elif normalized == "streamable-http":
        asyncio.run(serve_http())
    else:
        raise ValueError(f"Unsupported transport: {transport}")


__all__ = [
    "DEFAULT_HTTP_PORT",
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
