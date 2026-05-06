"""Runtime error normalization helpers."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_utils import is_project_lock_error, safe_cause_details


_SYNC_OPERATIONS = frozenset(
    {
        "get_project_sync_status",
        "checkout_project_program",
        "add_project_program_to_version_control",
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "delete_shared_project_file",
        "reload_project_program",
        "get_version_history",
        "get_version_diff",
    }
)


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
    code = ErrorCode.VALIDATION_ERROR if isinstance(exc, ValueError) else ErrorCode.OPERATION_FAILED
    retryable = False

    if is_project_lock_error(exc):
        code = ErrorCode.PROJECT_LOCKED
        retryable = True
    elif message.startswith("OPERATION_FAILED"):
        code = ErrorCode.OPERATION_FAILED
    elif message.startswith("SYNC_OPERATION_FAILED"):
        code = ErrorCode.SYNC_OPERATION_FAILED
    elif message.startswith("SYNC_STATUS_UNAVAILABLE"):
        code = ErrorCode.SYNC_OPERATION_FAILED
    elif message.startswith("CHECKOUT_REQUIRED"):
        code = ErrorCode.CHECKOUT_REQUIRED
    elif message.startswith("NOT_SHARED_PROJECT"):
        code = ErrorCode.NOT_SHARED_PROJECT
    elif message.startswith("NOT_CHECKED_OUT"):
        code = ErrorCode.NOT_CHECKED_OUT
    elif message.startswith("LOCAL_CHANGES_EXIST"):
        code = ErrorCode.LOCAL_CHANGES_EXIST
    elif message.startswith("UNSAFE_ACTIVE_CHECKOUT_TERMINATE"):
        code = ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE
    elif message.startswith("UNSAFE_PROGRAM_REMOVE"):
        code = ErrorCode.UNSAFE_PROGRAM_REMOVE
    elif message.startswith("UNSAFE_MERGE_REQUIRED"):
        code = ErrorCode.MERGE_REQUIRED
    elif message.startswith("ADD_TO_VERSION_CONTROL_REQUIRED"):
        code = ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED
    elif message.startswith("LOCK_TIMEOUT"):
        code = ErrorCode.LOCK_TIMEOUT
        retryable = True
    elif message.startswith("TARGET_ALREADY_LOADED"):
        code = ErrorCode.TARGET_ALREADY_LOADED
    elif message.startswith("PROGRAM_ALREADY_IMPORTED"):
        code = ErrorCode.PROGRAM_ALREADY_IMPORTED
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
    elif code is ErrorCode.OPERATION_FAILED and operation in _SYNC_OPERATIONS:
        code = ErrorCode.SYNC_OPERATION_FAILED

    details: dict[str, Any] = {"operation": operation}
    if target is not None:
        details["target"] = target
    if domain_path is not None:
        details["domain_path"] = domain_path
    if code in {ErrorCode.OPERATION_FAILED, ErrorCode.SYNC_OPERATION_FAILED, ErrorCode.PROJECT_LOCKED}:
        details.update(safe_cause_details(exc))

    return DomainError(
        code=code,
        message=message,
        hint="Check runtime state",
        retryable=retryable,
        details=details,
    )

__all__ = ["to_domain_error"]
