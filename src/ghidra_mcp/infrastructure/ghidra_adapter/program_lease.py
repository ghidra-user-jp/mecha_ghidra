"""Program lease helper for close/save/reopen lifecycle."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode


@dataclass(slots=True)
class ProgramLease:
    """Wrap an operation with optional save/close/reopen lifecycle hooks."""

    before_close: Callable[[], None]
    do_operation: Callable[[], Any]
    reopen: Callable[[], Any]

    def run(self, *, save: bool = False, save_hook: Callable[[], None] | None = None) -> Any:
        try:
            if save and save_hook is not None:
                save_hook()
        except Exception as exc:
            raise DomainError(
                code=ErrorCode.SAVE_FAILED,
                message=f"Save failed: {exc}",
                hint="Check the target program's modified state",
                retryable=False,
            ) from exc

        self.before_close()

        operation_error: Exception | None = None
        operation_completed = False
        result: Any = None
        try:
            result = self.do_operation()
            operation_completed = True
        except Exception as exc:
            operation_error = exc

        try:
            self.reopen()
        except Exception as exc:
            details: dict[str, Any] | None = None
            if operation_error is not None:
                details = {"operation_error": str(operation_error)}
                # If the wrapped operation already reported a non-retryable
                # partial success, reopening must not erase that fact.  This
                # can happen after an undo/delete succeeds but its required
                # postcondition refresh fails, followed by a reopen failure.
                if isinstance(operation_error, DomainError):
                    operation_details = operation_error.details or {}
                    for key in ("operation", "operation_completed", "partial_success"):
                        if key in operation_details:
                            details[key] = operation_details[key]
            elif operation_completed:
                details = {"operation_completed": True, "partial_success": True}
                if result is not None:
                    details["operation_result"] = result
            raise DomainError(
                code=ErrorCode.REOPEN_FAILED,
                message=f"Failed to reopen program: {exc}",
                hint=(
                    "Recreate the session and inspect the remote operation state before deciding "
                    "whether it is safe to retry"
                ),
                # The wrapped operation may already have completed, or may have failed after a
                # remote side effect.  Retrying a commit/delete-style operation automatically is
                # therefore unsafe even when no operation result was returned.
                retryable=False,
                details=details,
            ) from exc

        if operation_error is not None:
            raise operation_error
        return result


__all__ = ["ProgramLease"]
