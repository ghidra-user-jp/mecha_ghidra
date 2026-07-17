"""Transport configuration helpers for MCP presentation layer."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")


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
    if normalized in {"0.0.0.0", "::"}:
        # A wildcard listen address is necessary inside the Docker container,
        # but it must not imply that every Host/Origin is trusted.  Keep the
        # listener reachable through the loopback-published Compose port while
        # rejecting DNS-rebinding and LAN Host headers.  Operators that need
        # remote access must bind a fixed IP/hostname explicitly.
        return _transport_security_for_hosts(_LOOPBACK_HOSTS)
    if ":" in normalized and not normalized.startswith("["):
        normalized = f"[{normalized}]"
    return _transport_security_for_hosts((normalized,))


def configure_transport_security_for_host(*, mcp: FastMCP, host: str, logger: logging.Logger) -> None:
    settings = resolve_transport_security_for_host(host)
    if normalize_host(host) in {"0.0.0.0", "::"}:
        logger.warning(
            "MCP is listening on wildcard host %s, but DNS rebinding protection "
            "accepts only loopback Host/Origin values. Bind a fixed IP/hostname "
            "and use TLS plus access controls for intentional remote access.",
            host,
        )
    mcp.settings.transport_security = settings


def configure_mcp_for_sse(*, mcp: FastMCP, args: Any, logger: logging.Logger) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    configure_transport_security_for_host(mcp=mcp, host=mcp.settings.host, logger=logger)
    logger.info("Starting MCP in SSE mode: http://%s:%s/sse", mcp.settings.host, mcp.settings.port)


def configure_mcp_for_streamable_http(*, mcp: FastMCP, args: Any, logger: logging.Logger) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    mcp.settings.streamable_http_path = normalize_streamable_http_path(args.mcp_path)
    configure_transport_security_for_host(mcp=mcp, host=mcp.settings.host, logger=logger)
    logger.info(
        "Starting MCP in Streamable HTTP mode: http://%s:%s%s",
        mcp.settings.host,
        mcp.settings.port,
        mcp.settings.streamable_http_path,
    )


__all__ = [
    "configure_mcp_for_sse",
    "configure_mcp_for_streamable_http",
    "configure_transport_security_for_host",
    "normalize_host",
    "normalize_streamable_http_path",
    "normalize_transport",
    "resolve_transport_security_for_host",
]
