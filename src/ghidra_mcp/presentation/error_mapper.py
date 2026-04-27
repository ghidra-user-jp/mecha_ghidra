"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode

_PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.OPERATION_FAILED: "OPERATION_FAILED: operation failed",
    ErrorCode.CHECKOUT_REQUIRED: "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects",
    ErrorCode.NOT_SHARED_PROJECT: "NOT_SHARED_PROJECT: target program is not under shared-project version control",
    ErrorCode.NOT_CHECKED_OUT: "NOT_CHECKED_OUT: program is not checked out",
    ErrorCode.LOCAL_CHANGES_EXIST: "LOCAL_CHANGES_EXIST: operation aborted due to local changes",
    ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE: (
        "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: active checkout cannot be terminated; "
        "use undo_checkout_project_program instead"
    ),
    ErrorCode.UNSAFE_PROGRAM_REMOVE: (
        "UNSAFE_PROGRAM_REMOVE: refusing to remove a versioned shared-project program"
    ),
    ErrorCode.MERGE_REQUIRED: "MERGE_REQUIRED: automatic merge is disabled; reopen the latest version or re-checkout before retrying",
    ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED: (
        "ADD_TO_VERSION_CONTROL_REQUIRED: run add_project_program_to_version_control first"
    ),
    ErrorCode.LOCK_TIMEOUT: "LOCK_TIMEOUT: failed to acquire lock",
    ErrorCode.TARGET_ALREADY_LOADED: "TARGET_ALREADY_LOADED: program is already loaded; use the existing target",
    ErrorCode.PROGRAM_ALREADY_IMPORTED: "PROGRAM_ALREADY_IMPORTED: program already exists in project; use load_project_program",
    ErrorCode.SESSION_NOT_FOUND: "SESSION_NOT_FOUND: session not found",
    ErrorCode.TARGET_NOT_REGISTERED: "TARGET_NOT_REGISTERED: target is not registered",
    ErrorCode.PROGRAM_NOT_FOUND: "PROGRAM_NOT_FOUND: program not found",
    ErrorCode.VALIDATION_ERROR: "VALIDATION_ERROR: input validation failed",
    ErrorCode.REOPEN_FAILED: "REOPEN_FAILED: failed to reopen program",
    ErrorCode.SAVE_FAILED: "SAVE_FAILED: save operation failed",
    ErrorCode.SYNC_OPERATION_FAILED: "SYNC_OPERATION_FAILED: operation failed",
    ErrorCode.PROJECT_LOCKED: "PROJECT_LOCKED: project is locked by another process",
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
        public_message = _with_safe_cause(public_message, exc)
        mapped = RuntimeError(public_message)
        setattr(mapped, "domain_error", payload)
        mapped.__cause__ = exc
        return mapped
    return exc


def _with_safe_cause(message: str, exc: DomainError) -> str:
    if exc.code not in {ErrorCode.OPERATION_FAILED, ErrorCode.SYNC_OPERATION_FAILED, ErrorCode.PROJECT_LOCKED}:
        return message
    details = exc.details or {}
    cause_type = str(details.get("cause_type") or "").strip()
    cause_message = str(details.get("cause_message") or "").strip()
    if not cause_type and not cause_message:
        return message
    if not cause_type:
        return f"{message} ({cause_message})"
    if not cause_message:
        return f"{message} ({cause_type})"
    if cause_message.startswith(f"{cause_type}:"):
        return f"{message} ({cause_message})"
    return f"{message} ({cause_type}: {cause_message})"


__all__ = ["map_exception"]
