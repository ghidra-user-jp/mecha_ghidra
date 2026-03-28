"""Runtime error normalization helpers."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode


def to_domain_error(
    exc: Exception,
    *,
    operation: str,
    target: str | None = None,
    domain_path: str | None = None,
) -> DomainError:
    if isinstance(exc, DomainError):
        details = dict(exc.details or {})
        details.setdefault("operation", operation)
        if target is not None:
            details.setdefault("target", target)
        if domain_path is not None:
            details.setdefault("domain_path", domain_path)
        return DomainError(
            code=exc.code,
            message=exc.message,
            hint=exc.hint,
            retryable=exc.retryable,
            details=details,
        )

    message = str(exc)
    code = ErrorCode.VALIDATION_ERROR if isinstance(exc, ValueError) else ErrorCode.SYNC_OPERATION_FAILED
    retryable = False

    if message.startswith("CHECKOUT_REQUIRED"):
        code = ErrorCode.CHECKOUT_REQUIRED
    elif message.startswith("NOT_SHARED_PROJECT"):
        code = ErrorCode.NOT_SHARED_PROJECT
    elif message.startswith("NOT_CHECKED_OUT"):
        code = ErrorCode.NOT_CHECKED_OUT
    elif message.startswith("LOCAL_CHANGES_EXIST"):
        code = ErrorCode.LOCAL_CHANGES_EXIST
    elif message.startswith("UNSAFE_MERGE_REQUIRED"):
        code = ErrorCode.MERGE_REQUIRED
    elif message.startswith("LOCK_TIMEOUT"):
        code = ErrorCode.LOCK_TIMEOUT
        retryable = True
    elif "Session '" in message and ("does not exist" in message or "is not initialized" in message):
        code = ErrorCode.SESSION_NOT_FOUND
    elif "Target '" in message and "is not initialized" in message:
        code = ErrorCode.TARGET_NOT_REGISTERED
    elif "DomainFile" in message or "failed to resolve domain path" in message:
        code = ErrorCode.PROGRAM_NOT_FOUND
    elif message.startswith("REOPEN_FAILED"):
        code = ErrorCode.REOPEN_FAILED
        retryable = True
    elif message.startswith("SAVE_FAILED"):
        code = ErrorCode.SAVE_FAILED
    elif "CORE_EXECUTOR_UNAVAILABLE" in message:
        code = ErrorCode.CORE_EXECUTOR_UNAVAILABLE

    details: dict[str, Any] = {"operation": operation}
    if target is not None:
        details["target"] = target
    if domain_path is not None:
        details["domain_path"] = domain_path

    return DomainError(
        code=code,
        message=message,
        hint="Check runtime state",
        retryable=retryable,
        details=details,
    )


__all__ = ["to_domain_error"]
