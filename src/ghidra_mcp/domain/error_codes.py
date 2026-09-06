"""Classification of ``CODE: detail`` runtime failures into domain error codes.

The headless layer raises ``HeadlessError`` with a ``code`` attribute; older
call sites still raise plain ``RuntimeError`` whose message starts with the
same ``CODE:`` prefix.  Both are classified here from a single table so the
application and infrastructure layers agree on the mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import ErrorCode

_CODE_PREFIX_RE = re.compile(r"^([A-Z][A-Z0-9_]+):")


@dataclass(frozen=True, slots=True)
class ErrorClassification:
    code: ErrorCode
    retryable: bool = False


_RETRYABLE_SYNC = ErrorClassification(ErrorCode.SYNC_OPERATION_FAILED, retryable=True)
_SYNC_FAILED = ErrorClassification(ErrorCode.SYNC_OPERATION_FAILED)

_CODE_TABLE: dict[str, ErrorClassification] = {
    "OPERATION_FAILED": ErrorClassification(ErrorCode.OPERATION_FAILED),
    "SYNC_OPERATION_FAILED": _SYNC_FAILED,
    "SYNC_STATUS_UNAVAILABLE": _SYNC_FAILED,
    "VERSION_LOAD_FAILED": _SYNC_FAILED,
    "HIJACK_STATE_CHANGED": _SYNC_FAILED,
    "DELETE_POSTCONDITION_FAILED": _SYNC_FAILED,
    # Refresh/connection failures happen before any sync side effect, so a retry
    # is safe once the repository connection recovers.
    "SYNC_REFRESH_FAILED": _RETRYABLE_SYNC,
    "REPOSITORY_CONNECT_FAILED": _RETRYABLE_SYNC,
    "PROJECT_DATA_REFRESH_FAILED": _RETRYABLE_SYNC,
    "CHECKOUT_REQUIRED": ErrorClassification(ErrorCode.CHECKOUT_REQUIRED),
    "CHECKOUT_UNAVAILABLE": ErrorClassification(ErrorCode.CHECKOUT_UNAVAILABLE),
    "AUTO_CHECKOUT_FAILED": ErrorClassification(ErrorCode.CHECKOUT_UNAVAILABLE),
    "CHECKOUT_NOT_FOUND": ErrorClassification(ErrorCode.CHECKOUT_NOT_FOUND),
    "HIJACKED_PROGRAM": ErrorClassification(ErrorCode.HIJACKED_PROGRAM),
    "NOT_SHARED_PROJECT": ErrorClassification(ErrorCode.NOT_SHARED_PROJECT),
    "SHARED_PROJECT_UNAVAILABLE": ErrorClassification(ErrorCode.SHARED_PROJECT_UNAVAILABLE),
    "NOT_CHECKED_OUT": ErrorClassification(ErrorCode.NOT_CHECKED_OUT),
    "LOCAL_CHANGES_EXIST": ErrorClassification(ErrorCode.LOCAL_CHANGES_EXIST),
    "UNSAFE_ACTIVE_CHECKOUT_TERMINATE": ErrorClassification(ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE),
    "UNSAFE_VERSIONED_DELETE": ErrorClassification(ErrorCode.UNSAFE_VERSIONED_DELETE),
    "PRIVATE_FILE_DELETE_NOT_ALLOWED": ErrorClassification(ErrorCode.PRIVATE_FILE_DELETE_NOT_ALLOWED),
    "SHARED_FILE_DELETE_BLOCKED": ErrorClassification(ErrorCode.SHARED_FILE_DELETE_BLOCKED),
    "LATEST_VERSION_MISMATCH": ErrorClassification(ErrorCode.LATEST_VERSION_MISMATCH),
    "UNSAFE_PROGRAM_REMOVE": ErrorClassification(ErrorCode.UNSAFE_PROGRAM_REMOVE),
    "UNSAFE_MERGE_REQUIRED": ErrorClassification(ErrorCode.MERGE_REQUIRED),
    "ADD_TO_VERSION_CONTROL_REQUIRED": ErrorClassification(ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED),
    "ADD_TO_VERSION_CONTROL_NOT_ALLOWED": ErrorClassification(ErrorCode.ADD_TO_VERSION_CONTROL_NOT_ALLOWED),
    "CHECKIN_NOT_ALLOWED": ErrorClassification(ErrorCode.CHECKIN_NOT_ALLOWED),
    "KEEP_FILE_NOT_FOUND": ErrorClassification(ErrorCode.KEEP_FILE_NOT_FOUND),
    "VERSION_NOT_FOUND": ErrorClassification(ErrorCode.VERSION_NOT_FOUND),
    "VERSION_DIFF_TIMEOUT": ErrorClassification(ErrorCode.VERSION_DIFF_TIMEOUT, retryable=True),
    "LOCK_TIMEOUT": ErrorClassification(ErrorCode.LOCK_TIMEOUT, retryable=True),
    "TARGET_ALREADY_LOADED": ErrorClassification(ErrorCode.TARGET_ALREADY_LOADED),
    "PROGRAM_ALREADY_IMPORTED": ErrorClassification(ErrorCode.PROGRAM_ALREADY_IMPORTED),
    "PROGRAM_NOT_OPEN": ErrorClassification(ErrorCode.PROGRAM_NOT_OPEN),
    "PROGRAM_OPEN_FAILED": ErrorClassification(ErrorCode.PROGRAM_OPEN_FAILED),
    "IMPORT_CLOSE_FAILED": ErrorClassification(ErrorCode.IMPORT_FAILED),
    "IMPORT_POST_PROCESS_FAILED": ErrorClassification(ErrorCode.IMPORT_FAILED),
    "RAW_LOADER_OPTION_UNAVAILABLE": ErrorClassification(ErrorCode.IMPORT_FAILED),
    "REOPEN_FAILED": ErrorClassification(ErrorCode.REOPEN_FAILED),
    "SAVE_FAILED": ErrorClassification(ErrorCode.SAVE_FAILED),
    "SESSION_CLOSE_FAILED": ErrorClassification(ErrorCode.SESSION_CLOSE_FAILED),
    "PROGRAM_CLOSE_FAILED": ErrorClassification(ErrorCode.PROGRAM_CLOSE_FAILED),
    "REMOVE_PROGRAM_FAILED": ErrorClassification(ErrorCode.REMOVE_PROGRAM_FAILED),
    "PROJECT_CLOSE_FAILED": ErrorClassification(ErrorCode.PROJECT_CLOSE_FAILED),
    "PROJECT_CLOSE_REJECTED": ErrorClassification(ErrorCode.PROJECT_CLOSE_FAILED),
    "CLOSE_ALL_FAILED": ErrorClassification(ErrorCode.SESSION_CLOSE_FAILED),
    "PROJECT_ALREADY_EXISTS": ErrorClassification(ErrorCode.PROJECT_ALREADY_EXISTS),
    "PROJECT_IN_USE": ErrorClassification(ErrorCode.PROJECT_IN_USE),
    "SESSION_CHANGED": ErrorClassification(ErrorCode.SESSION_CHANGED, retryable=True),
    "CORE_EXECUTOR_UNAVAILABLE": ErrorClassification(ErrorCode.CORE_EXECUTOR_UNAVAILABLE),
    "PATH_NOT_ALLOWED": ErrorClassification(ErrorCode.PATH_NOT_ALLOWED),
    "JVM_NOT_HEADLESS": ErrorClassification(ErrorCode.JVM_NOT_HEADLESS),
    "HEADLESS_UNSUPPORTED": ErrorClassification(ErrorCode.HEADLESS_UNSUPPORTED),
    "READ_ONLY_PROGRAM": ErrorClassification(ErrorCode.READ_ONLY_PROGRAM),
}


def error_code_prefix(message: str) -> str | None:
    match = _CODE_PREFIX_RE.match(message or "")
    return match.group(1) if match else None


def classify_error_code(code: str | None) -> ErrorClassification | None:
    if not code:
        return None
    return _CODE_TABLE.get(code)


def classify_runtime_error(exc: BaseException) -> ErrorClassification | None:
    """Classify by the structured ``code`` attribute first, then by message prefix."""

    structured = getattr(exc, "code", None)
    if isinstance(structured, str):
        classification = classify_error_code(structured)
        if classification is not None:
            return classification
    return classify_error_code(error_code_prefix(str(exc)))


__all__ = [
    "ErrorClassification",
    "classify_error_code",
    "classify_runtime_error",
    "error_code_prefix",
]
