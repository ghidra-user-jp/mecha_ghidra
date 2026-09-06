"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode

_PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.OPERATION_FAILED: "OPERATION_FAILED: operation failed",
    ErrorCode.CHECKOUT_REQUIRED: "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects",
    ErrorCode.CHECKOUT_UNAVAILABLE: (
        "CHECKOUT_UNAVAILABLE: the repository refused the requested checkout "
        "(another user may hold an exclusive checkout); retry later or inspect get_project_sync_status checkouts"
    ),
    ErrorCode.HIJACKED_PROGRAM: (
        "HIJACKED_PROGRAM: a private local file shadows the repository version; recover it before mutating"
    ),
    ErrorCode.NOT_SHARED_PROJECT: "NOT_SHARED_PROJECT: target program is not under shared-project version control",
    ErrorCode.NOT_CHECKED_OUT: "NOT_CHECKED_OUT: program is not checked out",
    ErrorCode.LOCAL_CHANGES_EXIST: "LOCAL_CHANGES_EXIST: operation aborted due to local changes",
    ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE: (
        "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: active checkout cannot be terminated; "
        "use undo_checkout_project_program instead"
    ),
    ErrorCode.UNSAFE_VERSIONED_DELETE: (
        "UNSAFE_VERSIONED_DELETE: versioned delete is non-atomic; explicitly acknowledge the risk first"
    ),
    ErrorCode.UNSAFE_PROGRAM_REMOVE: ("UNSAFE_PROGRAM_REMOVE: refusing to remove a versioned shared-project program"),
    ErrorCode.MERGE_REQUIRED: (
        "MERGE_REQUIRED: the repository moved ahead of this checkout and automatic merge is disabled; "
        "pull_project_program refreshes an unmodified checkout, and commit_project_program(on_conflict='discard') "
        "drops the local changes and follows the latest version"
    ),
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
    ErrorCode.PATH_NOT_ALLOWED: "PATH_NOT_ALLOWED: path is outside the roots allowed by the server operator",
    ErrorCode.CHECKOUT_NOT_FOUND: "CHECKOUT_NOT_FOUND: no checkout with that id exists for the program",
    ErrorCode.SHARED_PROJECT_UNAVAILABLE: "SHARED_PROJECT_UNAVAILABLE: the shared project repository is not reachable",
    ErrorCode.PRIVATE_FILE_DELETE_NOT_ALLOWED: "PRIVATE_FILE_DELETE_NOT_ALLOWED: deleting a private file requires allow_private=true",
    ErrorCode.SHARED_FILE_DELETE_BLOCKED: "SHARED_FILE_DELETE_BLOCKED: the shared file is checked out or in use and cannot be deleted",
    ErrorCode.LATEST_VERSION_MISMATCH: "LATEST_VERSION_MISMATCH: the repository latest version changed; re-read it before retrying",
    ErrorCode.ADD_TO_VERSION_CONTROL_NOT_ALLOWED: "ADD_TO_VERSION_CONTROL_NOT_ALLOWED: the program cannot be added to version control",
    ErrorCode.CHECKIN_NOT_ALLOWED: "CHECKIN_NOT_ALLOWED: the program cannot be checked in in its current state",
    ErrorCode.KEEP_FILE_NOT_FOUND: "KEEP_FILE_NOT_FOUND: the .keep copy of the discarded checkout was not found",
    ErrorCode.VERSION_NOT_FOUND: "VERSION_NOT_FOUND: requested version does not exist in the history",
    ErrorCode.VERSION_DIFF_TIMEOUT: "VERSION_DIFF_TIMEOUT: version diff exceeded its time limit",
    ErrorCode.PROGRAM_NOT_OPEN: "PROGRAM_NOT_OPEN: the program is not open in this project handle",
    ErrorCode.PROGRAM_OPEN_FAILED: "PROGRAM_OPEN_FAILED: the program could not be opened",
    ErrorCode.IMPORT_FAILED: "IMPORT_FAILED: the import did not complete cleanly; check partial_import details",
    ErrorCode.SESSION_CLOSE_FAILED: "SESSION_CLOSE_FAILED: the session could not be closed cleanly",
    ErrorCode.PROGRAM_CLOSE_FAILED: "PROGRAM_CLOSE_FAILED: the program could not be closed",
    ErrorCode.REMOVE_PROGRAM_FAILED: "REMOVE_PROGRAM_FAILED: the program could not be removed from the project",
    ErrorCode.PROJECT_CLOSE_FAILED: "PROJECT_CLOSE_FAILED: the project could not be closed",
    ErrorCode.PROJECT_ALREADY_EXISTS: "PROJECT_ALREADY_EXISTS: a project already exists at that location; pass overwrite=true to replace it",
    ErrorCode.PROJECT_IN_USE: "PROJECT_IN_USE: the project is open or registered by another target",
    ErrorCode.SESSION_CHANGED: "SESSION_CHANGED: the target session changed during the operation; retry",
    ErrorCode.HEADLESS_UNSUPPORTED: "HEADLESS_UNSUPPORTED: this Ghidra operation needs a display and is not available in the headless server",
    ErrorCode.JVM_NOT_HEADLESS: "JVM_NOT_HEADLESS: the JVM was started without java.awt.headless=true",
    ErrorCode.READ_ONLY_PROGRAM: (
        "READ_ONLY_PROGRAM: the target holds a past version opened read-only; "
        "load the current version with load_project_program before mutating"
    ),
}


def map_exception(
    exc: Exception, *, fallback_message: str | None = None, details: dict[str, Any] | None = None
) -> Exception:
    if isinstance(exc, DomainError):
        payload = {"code": exc.code.value, "retryable": exc.retryable}
        if exc.hint is not None:
            payload["hint"] = exc.hint
        if exc.details:
            payload["details"] = exc.details
        if details:
            payload.update(details)
        public_message = (
            fallback_message if fallback_message is not None else _PUBLIC_MESSAGES.get(exc.code, exc.code.value)
        )
        public_message = _with_safe_cause(public_message, exc)
        mapped = RuntimeError(public_message)
        mapped.domain_error = payload
        mapped.__cause__ = exc
        return mapped
    return exc


def _with_safe_cause(message: str, exc: DomainError) -> str:
    if exc.code not in {
        ErrorCode.OPERATION_FAILED,
        ErrorCode.SYNC_OPERATION_FAILED,
        ErrorCode.PROJECT_LOCKED,
        ErrorCode.HEADLESS_UNSUPPORTED,
    }:
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
