"""Transport configuration helpers for MCP presentation layer."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings


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


def resolve_transport_security_for_host(host: str) -> TransportSecuritySettings:
    normalized = normalize_host(host)
    if normalized in {"127.0.0.1", "localhost", "::1"}:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        )
    if normalized in {"0.0.0.0", "::"}:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    if ":" in normalized and not normalized.startswith("["):
        host_pattern = f"[{normalized}]:*"
        origin_pattern = f"http://[{normalized}]:*"
    else:
        host_pattern = f"{normalized}:*"
        origin_pattern = f"http://{normalized}:*"
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host_pattern],
        allowed_origins=[origin_pattern],
    )


def configure_transport_security_for_host(*, mcp: FastMCP, host: str, logger: logging.Logger) -> None:
    settings = resolve_transport_security_for_host(host)
    if not settings.enable_dns_rebinding_protection:
        logger.warning(
            "mcp-host=%s のため DNS rebinding protection を無効化します。"
            " 本番運用では固定ホスト名/IPでの起動を推奨します。",
            host,
        )
    mcp.settings.transport_security = settings


def configure_mcp_for_sse(*, mcp: FastMCP, args: Any, logger: logging.Logger) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    configure_transport_security_for_host(mcp=mcp, host=mcp.settings.host, logger=logger)
    logger.info("MCPをSSEモードで起動: http://%s:%s/sse", mcp.settings.host, mcp.settings.port)


def configure_mcp_for_streamable_http(*, mcp: FastMCP, args: Any, logger: logging.Logger) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    mcp.settings.streamable_http_path = normalize_streamable_http_path(args.mcp_path)
    configure_transport_security_for_host(mcp=mcp, host=mcp.settings.host, logger=logger)
    logger.info(
        "MCPをStreamable HTTPモードで起動: http://%s:%s%s",
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
