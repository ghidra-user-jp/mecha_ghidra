"""Turn arbitrary runtime failures into ``DomainError`` values.

One mapping serves the runtime backend and the application services; callers
only choose the hint text, the default code, and which codes carry sanitized
cause details.  A code with its own recovery hint (``error_hints``) gets that
hint instead of the caller's.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .error_codes import classify_runtime_error
from .error_hints import recovery_hint
from .error_utils import is_project_lock_error, safe_cause_details
from .errors import DomainError, ErrorCode

DEFAULT_CAUSE_DETAIL_CODES: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.OPERATION_FAILED,
        ErrorCode.SYNC_OPERATION_FAILED,
        ErrorCode.PROJECT_LOCKED,
        ErrorCode.HEADLESS_UNSUPPORTED,
        # Their public text is fixed; the cause says which option, or what the decompiler reported.
        ErrorCode.PROGRAM_NOT_ANALYZED,
        ErrorCode.RAW_LOADER_OPTION_UNAVAILABLE,
    }
)

# Codes whose HeadlessError.details are copied into the DomainError verbatim.
# Script execution results (diagnostics, transaction outcome, quarantine state)
# are only meaningful with those details.
DETAIL_PRESERVING_CODES: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.AMBIGUOUS_FUNCTION,
        ErrorCode.AMBIGUOUS_DATA_TYPE,
        ErrorCode.BSIM_MATCH_STALE,
        ErrorCode.SCRIPTS_DISABLED,
        ErrorCode.SCRIPT_NOT_FOUND,
        ErrorCode.AMBIGUOUS_SCRIPT,
        ErrorCode.SCRIPT_RUNTIME_AMBIGUOUS,
        ErrorCode.SCRIPT_RUNTIME_UNAVAILABLE,
        ErrorCode.SCRIPT_COMPILE_FAILED,
        ErrorCode.SCRIPT_LOAD_FAILED,
        ErrorCode.SCRIPT_FAILED,
        ErrorCode.SCRIPT_TIMEOUT,
        ErrorCode.SCRIPT_CANCELLED,
        ErrorCode.TARGET_EXECUTION_INVALID,
        ErrorCode.TARGET_ORPHAN_UNRELEASED,
        ErrorCode.RUNTIME_DEGRADED,
    }
)


def _has_class(exc: BaseException, simple_name: str) -> bool:
    # JPype names a Java class in full ("java.awt.HeadlessException").
    return any(type_.__name__.rsplit(".", 1)[-1] == simple_name for type_ in type(exc).__mro__)


def _is_headless_exception(exc: BaseException) -> bool:
    return _has_class(exc, "HeadlessException")


def _is_java_exception(exc: BaseException) -> bool:
    # JPype makes some Java exceptions Python ones as well (NullPointerException
    # is a ValueError, IndexOutOfBoundsException an IndexError); they are
    # failures inside Ghidra, not a caller's bad argument or missing item.
    return any(type_.__name__ == "java.lang.Throwable" for type_ in type(exc).__mro__)


def _code_by_type(exc: BaseException, default_code: ErrorCode) -> ErrorCode:
    """The code of a Python exception that our own code raised for a bad argument or a missing item."""
    if _is_java_exception(exc):
        return default_code
    if isinstance(exc, ValueError):
        return ErrorCode.VALIDATION_ERROR
    # KeyError and IndexError are programming errors, as batch_read treats them.
    if isinstance(exc, LookupError) and not isinstance(exc, (KeyError, IndexError)):
        return ErrorCode.NOT_FOUND
    return default_code


def _is_exclusive_checkout_exception(exc: BaseException) -> bool:
    # ghidra.framework.store.ExclusiveCheckoutException: another project holds an
    # exclusive checkout, so the requested checkout cannot be granted right now.
    return _has_class(exc, "ExclusiveCheckoutException") or "ExclusiveCheckoutException" in str(exc)


def to_domain_error(
    exc: Exception,
    *,
    operation: str,
    target: str | None = None,
    domain_path: str | None = None,
    hint: str = "Check runtime state",
    default_code: ErrorCode = ErrorCode.OPERATION_FAILED,
    cause_detail_codes: Iterable[ErrorCode] = DEFAULT_CAUSE_DETAIL_CODES,
    keep_none_details: Iterable[str] = (),
) -> DomainError:
    """Map ``exc`` to a ``DomainError`` tagged with operation/target/domain_path.

    A ``DomainError`` passes through with the context merged into its details.
    Other exceptions are classified, first match wins, by a project another
    process has locked (the exception's text: retryable PROJECT_LOCKED), by
    Java's HeadlessException, by an exclusive checkout held elsewhere (its
    class or text: retryable CHECKOUT_UNAVAILABLE), then by structured code
    (``HeadlessError.code`` or a ``CODE:`` message prefix), and finally by
    type (a ValueError is VALIDATION_ERROR and a LookupError NOT_FOUND, which
    our own checks raise before changing anything) or ``default_code``.  No
    other text is read: a message that mentions a missing program is no
    refusal unless it names the code.
    """

    keep_none = set(keep_none_details)
    context = {"target": target, "domain_path": domain_path}

    if isinstance(exc, DomainError):
        details = dict(exc.details or {})
        details.setdefault("operation", operation)
        for key, value in context.items():
            if value is not None or key in keep_none:
                details.setdefault(key, value)
        return DomainError(
            code=exc.code,
            message=exc.message,
            hint=exc.hint,
            retryable=exc.retryable,
            details=details,
        )

    message = str(exc)
    code = _code_by_type(exc, default_code)
    retryable = False
    if is_project_lock_error(exc):
        code = ErrorCode.PROJECT_LOCKED
        retryable = True
    elif _is_headless_exception(exc):
        # The JVM runs headless so worker threads never block on AWT; a Ghidra
        # API that needs a display fails fast here instead of hanging.
        code = ErrorCode.HEADLESS_UNSUPPORTED
    elif _is_exclusive_checkout_exception(exc):
        code = ErrorCode.CHECKOUT_UNAVAILABLE
        retryable = True
    else:
        classification = classify_runtime_error(exc)
        if classification is not None:
            code = classification.code
            retryable = classification.retryable

    details: dict[str, Any] = {"operation": operation}
    if code in DETAIL_PRESERVING_CODES:
        details.update(getattr(exc, "details", None) or {})
    for key, value in context.items():
        if value is not None or key in keep_none:
            details[key] = value
    if code in set(cause_detail_codes):
        details.update(safe_cause_details(exc))

    return DomainError(
        code=code,
        message=message,
        hint=recovery_hint(code, message) or hint,
        retryable=retryable,
        details=details,
    )


__all__ = ["DEFAULT_CAUSE_DETAIL_CODES", "DETAIL_PRESERVING_CODES", "to_domain_error"]
