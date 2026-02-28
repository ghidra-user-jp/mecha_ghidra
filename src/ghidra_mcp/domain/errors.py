"""Domain-level error contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    CHECKOUT_REQUIRED = "CHECKOUT_REQUIRED"
    NOT_SHARED_PROJECT = "NOT_SHARED_PROJECT"
    NOT_CHECKED_OUT = "NOT_CHECKED_OUT"
    LOCAL_CHANGES_EXIST = "LOCAL_CHANGES_EXIST"
    LOCK_TIMEOUT = "LOCK_TIMEOUT"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    TARGET_NOT_REGISTERED = "TARGET_NOT_REGISTERED"
    PROGRAM_NOT_FOUND = "PROGRAM_NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    REOPEN_FAILED = "REOPEN_FAILED"
    SAVE_FAILED = "SAVE_FAILED"
    SYNC_OPERATION_FAILED = "SYNC_OPERATION_FAILED"
    CORE_EXECUTOR_UNAVAILABLE = "CORE_EXECUTOR_UNAVAILABLE"


@dataclass(slots=True)
class DomainError(Exception):
    code: ErrorCode
    message: str
    hint: str | None = None
    retryable: bool = False
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


__all__ = ["ErrorCode", "DomainError"]
