"""Helpers for masking credentials in BSim URLs."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def mask_bsim_url(url: str | None) -> str | None:
    """Mask credentials embedded in a BSim URL."""

    if not url:
        return url
    try:
        parts = urlsplit(url)
        if not parts.username and not parts.password:
            return url
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, f"***:***@{host}", parts.path, parts.query, parts.fragment))
    except Exception:
        return url


__all__ = ["mask_bsim_url"]
