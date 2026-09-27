"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_hints import recovery_hint
from ghidra_mcp.domain.error_utils import sanitize_cause_message

_PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.REQUEST_ID_CONFLICT: (
        "REQUEST_ID_CONFLICT: request_id already identifies an earlier call with different arguments"
    ),
    ErrorCode.IMPORT_IN_PROGRESS: (
        "IMPORT_IN_PROGRESS: another import job is writing this program; see details.operation_id"
    ),
    ErrorCode.ANALYSIS_IN_PROGRESS: (
        "ANALYSIS_IN_PROGRESS: another analysis job for this program is queued or running; see details.operation_id"
    ),
    ErrorCode.IMPORT_OUTPUT_UNCERTAIN: (
        "IMPORT_OUTPUT_UNCERTAIN: an earlier import of this program did not clean up; "
        "inspect details.operation_id and the project"
    ),
    ErrorCode.OPERATION_QUEUE_FULL: "OPERATION_QUEUE_FULL: the job queue is full and nothing was accepted; retry later",
    ErrorCode.OPERATION_NOT_FOUND: (
        "OPERATION_NOT_FOUND: no job record in this server process; inspect the project before submitting the job again"
    ),
    ErrorCode.OPERATION_WORKER_UNAVAILABLE: "OPERATION_WORKER_UNAVAILABLE: the job worker is stopping or unavailable",
    ErrorCode.OPERATION_WORKER_FAILED: "OPERATION_WORKER_FAILED: the job worker failed; inspect the project before retrying",
    ErrorCode.OPERATION_SHUTDOWN: (
        "OPERATION_SHUTDOWN: the server stopped before the job finished; the details say what was left behind"
    ),
    ErrorCode.OPERATION_CANCELLED: (
        "OPERATION_CANCELLED: cancel_operation stopped the job; details.output_state says what was left behind"
    ),
    ErrorCode.TARGET_REBOUND: "TARGET_REBOUND: the target's project changed before the import started; nothing was written",
    ErrorCode.AMBIGUOUS_FUNCTION: "AMBIGUOUS_FUNCTION: use a function address or a unique qualified name",
    ErrorCode.AMBIGUOUS_DATA_TYPE: "AMBIGUOUS_DATA_TYPE: use the full data type path",
    ErrorCode.BSIM_MATCH_STALE: "BSIM_MATCH_STALE: the loaded program does not match the BSim reference",
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
    ErrorCode.SESSION_NOT_FOUND: "SESSION_NOT_FOUND: the target has no loaded program",
    ErrorCode.TARGET_NOT_REGISTERED: "TARGET_NOT_REGISTERED: target is not registered",
    ErrorCode.PROGRAM_NOT_FOUND: "PROGRAM_NOT_FOUND: program not found",
    ErrorCode.NOT_FOUND: "NOT_FOUND: the named item was not found",
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
    ErrorCode.PROGRAM_NOT_OPEN: "PROGRAM_NOT_OPEN: the program is not open",
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
    ErrorCode.GUI_UNSUPPORTED: "GUI_UNSUPPORTED: this operation or argument is not available with the Ghidra GUI backend",
    ErrorCode.GUI_NAVIGATION_FAILED: (
        "GUI_NAVIGATION_FAILED: the program is shown in the Ghidra GUI, but moving to the location failed"
    ),
    ErrorCode.PROGRAM_NOT_ANALYZED: (
        "PROGRAM_NOT_ANALYZED: the program has not been analyzed, so the decompiler's variables are unavailable"
    ),
    ErrorCode.RAW_LOADER_OPTION_UNAVAILABLE: (
        "RAW_LOADER_OPTION_UNAVAILABLE: Ghidra's raw binary loader has no option this import needs "
        "for the chosen language or compiler"
    ),
    ErrorCode.READ_ONLY_PROGRAM: (
        "READ_ONLY_PROGRAM: the target holds a past version opened read-only; "
        "load the current version with load_project_program before mutating"
    ),
    ErrorCode.SCRIPTS_DISABLED: (
        "SCRIPTS_DISABLED: no script root is configured on this server (start it with --script-root DIR)"
    ),
    ErrorCode.SCRIPT_NOT_FOUND: "SCRIPT_NOT_FOUND: no script with that script_id is in the catalog; use list_scripts",
    ErrorCode.AMBIGUOUS_SCRIPT: "AMBIGUOUS_SCRIPT: several catalog entries match; pass the full root-qualified script_id",
    ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS: (
        "SCRIPT_RUNTIME_AMBIGUOUS: the .py script has no '@runtime Jython' or '@runtime PyGhidra' header "
    ),
    ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE: (
        "SCRIPT_RUNTIME_UNAVAILABLE: the script runtime is not available in this Ghidra installation"
    ),
    ErrorCode.SCRIPT_COMPILE_FAILED: "SCRIPT_COMPILE_FAILED: the script did not compile; see details.diagnostics",
    ErrorCode.SCRIPT_LOAD_FAILED: "SCRIPT_LOAD_FAILED: the script class could not be loaded or instantiated",
    ErrorCode.SCRIPT_FAILED: (
        "SCRIPT_FAILED: the script did not complete successfully; details.transaction_outcome says what was kept"
    ),
    ErrorCode.SCRIPT_TIMEOUT: (
        "SCRIPT_TIMEOUT: the script exceeded timeout_seconds; program changes were rolled back where possible"
    ),
    ErrorCode.SCRIPT_CANCELLED: "SCRIPT_CANCELLED: the script was cancelled before completion",
    ErrorCode.TARGET_EXECUTION_INVALID: (
        "TARGET_EXECUTION_INVALID: the target is quarantined after a failed script run; "
        "close_session(discard_changes=true) then reload the program"
    ),
    ErrorCode.TARGET_ORPHAN_UNRELEASED: (
        "TARGET_ORPHAN_UNRELEASED: a program consumer could not be released; the target stays quarantined"
    ),
    ErrorCode.RUNTIME_DEGRADED: (
        "RUNTIME_DEGRADED: the runtime is degraded after a script run left work running; restart the server process"
    ),
    ErrorCode.STARTUP_FAILED: (
        "STARTUP_FAILED: Ghidra did not start, so no tool can run; fix the server configuration and restart it"
    ),
}


# BsimService writes these messages itself, from its own checks and from backend
# text with credentials masked, and each starts with its code: they are public
# as they are.  BSIM_MATCH_STALE, which the core raises, keeps its text above.
_MESSAGE_IS_PUBLIC: frozenset[ErrorCode] = frozenset(
    code for code in ErrorCode if code.value.startswith("BSIM_") and code not in _PUBLIC_MESSAGES
)

# Our own code writes these messages to say which argument was wrong or what is
# missing ("Invalid address: 0xZZZ", "Function not found: main"), from what
# the caller sent: they follow the code instead of the fixed text above.  Java
# exceptions never get these codes (see error_mapping._code_by_type).
_DETAIL_IS_PUBLIC: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.VALIDATION_ERROR,
        ErrorCode.NOT_FOUND,
        ErrorCode.PROGRAM_NOT_OPEN,
        ErrorCode.TARGET_NOT_REGISTERED,
        # Our checks say which argument or operation the GUI backend refuses.
        ErrorCode.GUI_UNSUPPORTED,
        ErrorCode.GUI_NAVIGATION_FAILED,
    }
)
# A validation message can quote a file path the caller sent (binary_path);
# like a cause message it shows <path> for it.  The others name program items
# and domain paths, which are not host paths and would be lost to that rule.
_DETAIL_MAY_QUOTE_HOST_PATHS: frozenset[ErrorCode] = frozenset({ErrorCode.VALIDATION_ERROR})
_MAX_PUBLIC_DETAIL_CHARS = 500


def map_exception(
    exc: Exception, *, fallback_message: str | None = None, details: dict[str, Any] | None = None
) -> Exception:
    if isinstance(exc, DomainError):
        payload = {"code": exc.code.value, "retryable": exc.retryable}
        hint = exc.hint if exc.hint is not None else recovery_hint(exc.code, exc.message)
        if hint is not None:
            payload["hint"] = hint
        if exc.details:
            payload["details"] = exc.details
        if details:
            payload.update(details)
        if fallback_message is not None:
            public_message = fallback_message
        elif exc.code in _MESSAGE_IS_PUBLIC:
            public_message = exc.message
        elif exc.code in _DETAIL_IS_PUBLIC and _public_detail(exc):
            public_message = f"{exc.code.value}: {_public_detail(exc)}"
        else:
            public_message = _PUBLIC_MESSAGES.get(exc.code, exc.code.value)
        public_message = _with_safe_cause(public_message, exc)
        mapped = RuntimeError(public_message)
        mapped.domain_error = payload
        mapped.__cause__ = exc
        return mapped
    return exc


def _public_detail(exc: DomainError) -> str:
    """The message of a ``_DETAIL_IS_PUBLIC`` error without its code prefix, capped in length."""
    detail = exc.message.strip().removeprefix(f"{exc.code.value}:").strip()
    if exc.code in _DETAIL_MAY_QUOTE_HOST_PATHS:
        return sanitize_cause_message(detail)
    if len(detail) <= _MAX_PUBLIC_DETAIL_CHARS:
        return detail
    return detail[: _MAX_PUBLIC_DETAIL_CHARS - 3] + "..."


def _with_safe_cause(message: str, exc: DomainError) -> str:
    if exc.code not in {
        ErrorCode.OPERATION_FAILED,
        ErrorCode.SYNC_OPERATION_FAILED,
        ErrorCode.PROJECT_LOCKED,
        ErrorCode.HEADLESS_UNSUPPORTED,
        ErrorCode.STARTUP_FAILED,
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


def operation_error_payload(error: DomainError) -> dict[str, Any]:
    """Use the same public error wording for a stored operation as for a tool failure."""
    mapped = map_exception(error)
    return {"message": str(mapped), **mapped.domain_error}


__all__ = ["map_exception"]
