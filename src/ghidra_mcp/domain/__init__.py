"""Domain layer exports."""

from .error_codes import ErrorClassification, classify_error_code, classify_runtime_error, error_code_prefix
from .errors import DomainError, ErrorCode
from .models import LockKey, ProgramRef, TargetRef
from .policies import (
    DEFAULT_EXCLUSIVE_CHECKOUT,
    DEFAULT_LOCK_TIMEOUT_SECONDS,
    LOCK_ORDER,
    configure_exclusive_checkout_default,
    configure_lock_timeout_seconds,
    get_exclusive_checkout_default,
    get_lock_timeout_seconds,
)

__all__ = [
    "DEFAULT_EXCLUSIVE_CHECKOUT",
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "DomainError",
    "ErrorClassification",
    "ErrorCode",
    "LOCK_ORDER",
    "LockKey",
    "ProgramRef",
    "TargetRef",
    "classify_error_code",
    "classify_runtime_error",
    "error_code_prefix",
    "configure_exclusive_checkout_default",
    "configure_lock_timeout_seconds",
    "get_exclusive_checkout_default",
    "get_lock_timeout_seconds",
]
