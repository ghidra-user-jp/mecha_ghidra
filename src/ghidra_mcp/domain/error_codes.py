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
_VALIDATION = ErrorClassification(ErrorCode.VALIDATION_ERROR)
_NOT_FOUND = ErrorClassification(ErrorCode.NOT_FOUND)
_FAILED = ErrorClassification(ErrorCode.OPERATION_FAILED)

# A code that names an ErrorCode member classifies as that member (see
# classify_error_code).  This table holds the rest: the headless codes that
# share a public code, and the codes a retry can fix.
_CODE_TABLE: dict[str, ErrorClassification] = {
    "SYNC_STATUS_UNAVAILABLE": _SYNC_FAILED,
    "VERSION_LOAD_FAILED": _SYNC_FAILED,
    "HIJACK_STATE_CHANGED": _SYNC_FAILED,
    "DELETE_POSTCONDITION_FAILED": _SYNC_FAILED,
    # Refresh/connection failures happen before any sync side effect, so a retry
    # is safe once the repository connection recovers.
    "SYNC_REFRESH_FAILED": _RETRYABLE_SYNC,
    "REPOSITORY_CONNECT_FAILED": _RETRYABLE_SYNC,
    "PROJECT_DATA_REFRESH_FAILED": _RETRYABLE_SYNC,
    "AUTO_CHECKOUT_FAILED": ErrorClassification(ErrorCode.CHECKOUT_UNAVAILABLE),
    "UNSAFE_MERGE_REQUIRED": ErrorClassification(ErrorCode.MERGE_REQUIRED),
    "VERSION_DIFF_TIMEOUT": ErrorClassification(ErrorCode.VERSION_DIFF_TIMEOUT, retryable=True),
    "LOCK_TIMEOUT": ErrorClassification(ErrorCode.LOCK_TIMEOUT, retryable=True),
    "SESSION_CHANGED": ErrorClassification(ErrorCode.SESSION_CHANGED, retryable=True),
    "BSIM_DATABASE_UNREACHABLE": ErrorClassification(ErrorCode.BSIM_DATABASE_UNREACHABLE, retryable=True),
    "IMPORT_CLOSE_FAILED": ErrorClassification(ErrorCode.IMPORT_FAILED),
    "IMPORT_POST_PROCESS_FAILED": ErrorClassification(ErrorCode.IMPORT_FAILED),
    "IMPORT_CANCELLED": ErrorClassification(ErrorCode.OPERATION_CANCELLED),
    "PROJECT_CLOSE_REJECTED": ErrorClassification(ErrorCode.PROJECT_CLOSE_FAILED),
    "CLOSE_ALL_FAILED": ErrorClassification(ErrorCode.SESSION_CLOSE_FAILED),
    # Refusals of the arguments: export_program's output path, a C declaration,
    # a namespace path that names something else.
    "EXPORT_TARGET_EXISTS": _VALIDATION,
    "EXPORT_TARGET_IS_DIRECTORY": _VALIDATION,
    "EXPORT_DIRECTORY_MISSING": _VALIDATION,
    "C_PARSE_FAILED": _VALIDATION,
    "INVALID_NAMESPACE_TYPE": _VALIDATION,
    "NAMESPACE_NOT_FOUND": _NOT_FOUND,
    "REPOSITORY_NOT_FOUND": _NOT_FOUND,
    # Failures inside Ghidra; batch_read reports the decompiler and read
    # budget ones as item errors under their own codes.
    "EXPORT_FAILED": _FAILED,
    "FUNCTION_RENAME_FAILED": _FAILED,
    "DECOMPILE_FAILED": _FAILED,
    "DECOMPILE_TIMEOUT": _FAILED,
    "READ_TIMEOUT": _FAILED,
}


# Codes that refuse a call before it changes anything: a bad argument, a
# missing item, or a guard on the target, project or repository state, and
# for BSim a connection, login or read that failed before the database write.
# With a retryable code (raised only before any side effect) they tell a
# failed write left nothing behind; any other failure may have done part of
# its work.
REFUSED_BEFORE_ANY_CHANGE: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.VALIDATION_ERROR,
        ErrorCode.NOT_FOUND,
        ErrorCode.PROGRAM_NOT_FOUND,
        ErrorCode.TARGET_NOT_REGISTERED,
        ErrorCode.PROGRAM_NOT_OPEN,
        ErrorCode.SESSION_NOT_FOUND,
        ErrorCode.PATH_NOT_ALLOWED,
        ErrorCode.CORE_EXECUTOR_UNAVAILABLE,
        ErrorCode.PROJECT_ALREADY_EXISTS,
        ErrorCode.PROJECT_IN_USE,
        ErrorCode.TARGET_ALREADY_LOADED,
        ErrorCode.PROGRAM_ALREADY_IMPORTED,
        ErrorCode.READ_ONLY_PROGRAM,
        ErrorCode.TARGET_EXECUTION_INVALID,
        ErrorCode.CHECKOUT_REQUIRED,
        ErrorCode.CHECKOUT_NOT_FOUND,
        ErrorCode.NOT_CHECKED_OUT,
        ErrorCode.NOT_SHARED_PROJECT,
        ErrorCode.HIJACKED_PROGRAM,
        ErrorCode.LOCAL_CHANGES_EXIST,
        ErrorCode.MERGE_REQUIRED,
        ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED,
        ErrorCode.ADD_TO_VERSION_CONTROL_NOT_ALLOWED,
        ErrorCode.CHECKIN_NOT_ALLOWED,
        ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE,
        ErrorCode.UNSAFE_VERSIONED_DELETE,
        ErrorCode.UNSAFE_PROGRAM_REMOVE,
        ErrorCode.PRIVATE_FILE_DELETE_NOT_ALLOWED,
        ErrorCode.SHARED_FILE_DELETE_BLOCKED,
        ErrorCode.LATEST_VERSION_MISMATCH,
        ErrorCode.VERSION_NOT_FOUND,
        # Refused before the transaction starts (spec §7.4).
        ErrorCode.GUI_UNSUPPORTED,
        ErrorCode.BSIM_URL_REQUIRED,
        ErrorCode.BSIM_URL_INVALID,
        ErrorCode.BSIM_PARAMETER_INVALID,
        ErrorCode.BSIM_PASSWORD_CONFIG_INVALID,
        ErrorCode.BSIM_INVALID_MATCHED_REF,
        ErrorCode.BSIM_MATCH_STALE,
        ErrorCode.BSIM_REMOTE_PROJECT_LOAD_UNSUPPORTED,
        ErrorCode.BSIM_UNSAVED_PROGRAM,
        ErrorCode.BSIM_NO_FUNCTIONS,
        ErrorCode.BSIM_FUNCTION_NOT_FOUND,
        ErrorCode.BSIM_TARGET_METADATA_INVALID,
        ErrorCode.BSIM_EXECUTABLE_LOOKUP_REQUIRED,
        ErrorCode.BSIM_EXECUTABLE_LOOKUP_INVALID,
        ErrorCode.BSIM_EXECUTABLE_LOOKUP_TRUNCATED,
        ErrorCode.BSIM_EXECUTABLE_AMBIGUOUS,
        ErrorCode.BSIM_EXECUTABLE_NOT_FOUND,
        ErrorCode.BSIM_EXECUTABLE_CATEGORY_INVALID,
        ErrorCode.BSIM_EXECUTABLE_CATEGORY_NOT_CONFIGURED,
        ErrorCode.BSIM_EXECUTABLE_METADATA_INVALID,
        ErrorCode.BSIM_EXECUTABLE_UPDATE_UNSUPPORTED,
        ErrorCode.BSIM_DELETE_CONFIRMATION_MISMATCH,
        ErrorCode.BSIM_AUTHENTICATION_FAILED,
        ErrorCode.BSIM_DATABASE_INIT_FAILED,
        ErrorCode.BSIM_GET_EXECUTABLE_FAILED,
        ErrorCode.BSIM_LIST_CATEGORIES_FAILED,
    }
)


_MEMBER_VALUES = frozenset(code.value for code in ErrorCode)


def error_code_prefix(message: str) -> str | None:
    match = _CODE_PREFIX_RE.match(message or "")
    return match.group(1) if match else None


def classify_error_code(code: str | None) -> ErrorClassification | None:
    if not code:
        return None
    classification = _CODE_TABLE.get(code)
    if classification is None and code in _MEMBER_VALUES:
        classification = ErrorClassification(ErrorCode(code))
    return classification


def classify_runtime_error(exc: BaseException) -> ErrorClassification | None:
    """Classify by the structured ``code`` attribute first, then by message prefix."""

    structured = getattr(exc, "code", None)
    if isinstance(structured, str):
        classification = classify_error_code(structured)
        if classification is not None:
            return classification
    return classify_error_code(error_code_prefix(str(exc)))


__all__ = [
    "REFUSED_BEFORE_ANY_CHANGE",
    "ErrorClassification",
    "classify_error_code",
    "classify_runtime_error",
    "error_code_prefix",
]
