"""Transport configuration helpers for the MCP presentation layer.

mcp 2.x passes host/port/path/security to ``MCPServer.run()`` instead of a
mutable ``settings`` object, so these helpers build that keyword mapping.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

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


def sse_run_kwargs(*, args: Any, logger: logging.Logger) -> dict[str, Any]:
    """Keyword arguments for ``MCPServer.run("sse", **kwargs)``."""

    _apply_log_level(args)
    host = args.mcp_host
    port = args.mcp_port or DEFAULT_HTTP_PORT
    logger.info("Starting MCP in SSE mode: http://%s:%s/sse", host, port)
    return {
        "host": host,
        "port": port,
        "transport_security": transport_security_for_host(host=host, logger=logger),
    }


def streamable_http_run_kwargs(*, args: Any, logger: logging.Logger) -> dict[str, Any]:
    """Keyword arguments for ``MCPServer.run("streamable-http", **kwargs)``."""

    _apply_log_level(args)
    host = args.mcp_host
    port = args.mcp_port or DEFAULT_HTTP_PORT
    path = normalize_streamable_http_path(args.mcp_path)
    logger.info("Starting MCP in Streamable HTTP mode: http://%s:%s%s", host, port, path)
    return {
        "host": host,
        "port": port,
        "streamable_http_path": path,
        "transport_security": transport_security_for_host(host=host, logger=logger),
    }


def run_kwargs_for_transport(*, transport: str, args: Any, logger: logging.Logger) -> dict[str, Any]:
    normalized = normalize_transport(transport)
    if normalized == "sse":
        return sse_run_kwargs(args=args, logger=logger)
    if normalized == "streamable-http":
        return streamable_http_run_kwargs(args=args, logger=logger)
    return {}


__all__ = [
    "DEFAULT_HTTP_PORT",
    "normalize_host",
    "normalize_streamable_http_path",
    "normalize_transport",
    "resolve_transport_security_for_host",
    "run_kwargs_for_transport",
    "sse_run_kwargs",
    "streamable_http_run_kwargs",
    "transport_security_for_host",
]
