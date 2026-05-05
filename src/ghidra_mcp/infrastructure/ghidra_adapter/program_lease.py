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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            operation_error = exc

        try:
            self.reopen()
        except Exception as exc:  # noqa: BLE001
            details: dict[str, Any] | None = None
            if operation_error is not None:
                details = {"operation_error": str(operation_error)}
            elif operation_completed:
                details = {"operation_completed": True}
                if result is not None:
                    details["partial_success"] = True
                    details["operation_result"] = result
            raise DomainError(
                code=ErrorCode.REOPEN_FAILED,
                message=f"Failed to reopen program: {exc}",
                hint="Recreate the session and retry",
                retryable=True,
                details=details,
            ) from exc

        if operation_error is not None:
            raise operation_error
        return result


__all__ = ["ProgramLease"]
