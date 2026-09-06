"""Turn arbitrary runtime failures into ``DomainError`` values.

One mapping serves the runtime backend and the application services; callers
only choose the hint text, the default code, and which codes carry sanitized
cause details.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .error_codes import classify_runtime_error
from .error_utils import is_project_lock_error, safe_cause_details
from .errors import DomainError, ErrorCode

DEFAULT_CAUSE_DETAIL_CODES: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.OPERATION_FAILED,
        ErrorCode.SYNC_OPERATION_FAILED,
        ErrorCode.PROJECT_LOCKED,
        ErrorCode.HEADLESS_UNSUPPORTED,
    }
)


def _classify_by_message_shape(message: str) -> ErrorCode | None:
    """Last-resort heuristics for messages without a ``CODE:`` prefix."""

    if "Session '" in message and ("does not exist" in message or "is not initialized" in message):
        return ErrorCode.SESSION_NOT_FOUND
    if "Target '" in message and "is not initialized" in message:
        return ErrorCode.TARGET_NOT_REGISTERED
    if (
        "DomainFile" in message
        or "failed to resolve domain path" in message
        or message.startswith(("Program not found:", "Domain file not found:"))
    ):
        return ErrorCode.PROGRAM_NOT_FOUND
    if "CORE_EXECUTOR_UNAVAILABLE" in message:
        return ErrorCode.CORE_EXECUTOR_UNAVAILABLE
    return None


def _is_headless_exception(exc: BaseException) -> bool:
    return any(type_.__name__ == "HeadlessException" for type_ in type(exc).__mro__)


def _is_exclusive_checkout_exception(exc: BaseException) -> bool:
    # ghidra.framework.store.ExclusiveCheckoutException: another project holds an
    # exclusive checkout, so the requested checkout cannot be granted right now.
    return any(type_.__name__ == "ExclusiveCheckoutException" for type_ in type(exc).__mro__) or (
        "ExclusiveCheckoutException" in str(exc)
    )


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
    Other exceptions are classified by structured code (``HeadlessError.code``
    or a ``CODE:`` message prefix), then by project-lock detection, then by a
    few message heuristics, and finally fall back to ``default_code``.
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
    code = ErrorCode.VALIDATION_ERROR if isinstance(exc, ValueError) else default_code
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
        else:
            heuristic = _classify_by_message_shape(message)
            if heuristic is not None:
                code = heuristic

    details: dict[str, Any] = {"operation": operation}
    for key, value in context.items():
        if value is not None or key in keep_none:
            details[key] = value
    if code in set(cause_detail_codes):
        details.update(safe_cause_details(exc))

    return DomainError(code=code, message=message, hint=hint, retryable=retryable, details=details)


__all__ = ["DEFAULT_CAUSE_DETAIL_CODES", "to_domain_error"]
