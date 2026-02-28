"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError


def map_exception(exc: Exception, *, fallback_message: str | None = None, details: dict[str, Any] | None = None) -> Exception:
    if isinstance(exc, DomainError):
        payload = {"code": exc.code.value, "retryable": exc.retryable}
        if exc.hint is not None:
            payload["hint"] = exc.hint
        if exc.details:
            payload["details"] = exc.details
        if details:
            payload.update(details)
        mapped = RuntimeError(exc.message if fallback_message is None else fallback_message)
        setattr(mapped, "domain_error", payload)
        mapped.__cause__ = exc
        return mapped
    return exc


__all__ = ["map_exception"]
