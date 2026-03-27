"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode

_PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.CHECKOUT_REQUIRED: "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects",
    ErrorCode.NOT_SHARED_PROJECT: "NOT_SHARED_PROJECT: target program is not under shared-project version control",
    ErrorCode.NOT_CHECKED_OUT: "NOT_CHECKED_OUT: program is not checked out",
    ErrorCode.LOCAL_CHANGES_EXIST: "LOCAL_CHANGES_EXIST: operation aborted due to local changes",
    ErrorCode.MERGE_REQUIRED: "MERGE_REQUIRED: automatic merge is disabled; reopen the latest version or re-checkout before retrying",
    ErrorCode.LOCK_TIMEOUT: "LOCK_TIMEOUT: failed to acquire lock",
    ErrorCode.SESSION_NOT_FOUND: "SESSION_NOT_FOUND: session not found",
    ErrorCode.TARGET_NOT_REGISTERED: "TARGET_NOT_REGISTERED: target is not registered",
    ErrorCode.PROGRAM_NOT_FOUND: "PROGRAM_NOT_FOUND: program not found",
    ErrorCode.VALIDATION_ERROR: "VALIDATION_ERROR: input validation failed",
    ErrorCode.REOPEN_FAILED: "REOPEN_FAILED: failed to reopen program",
    ErrorCode.SAVE_FAILED: "SAVE_FAILED: save operation failed",
    ErrorCode.SYNC_OPERATION_FAILED: "SYNC_OPERATION_FAILED: operation failed",
    ErrorCode.CORE_EXECUTOR_UNAVAILABLE: "CORE_EXECUTOR_UNAVAILABLE: core command dispatcher is unavailable",
}


def map_exception(exc: Exception, *, fallback_message: str | None = None, details: dict[str, Any] | None = None) -> Exception:
    if isinstance(exc, DomainError):
        payload = {"code": exc.code.value, "retryable": exc.retryable}
        if exc.hint is not None:
            payload["hint"] = exc.hint
        if exc.details:
            payload["details"] = exc.details
        if details:
            payload.update(details)
        public_message = fallback_message if fallback_message is not None else _PUBLIC_MESSAGES.get(exc.code, exc.code.value)
        mapped = RuntimeError(public_message)
        setattr(mapped, "domain_error", payload)
        mapped.__cause__ = exc
        return mapped
    return exc


__all__ = ["map_exception"]
