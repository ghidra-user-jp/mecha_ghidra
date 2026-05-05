"""Helpers for safe public error details."""

from __future__ import annotations

import re

_POSIX_PATH_RE = re.compile(r"(?<![\w:/\\])/(?:[^:;,'\")\]\r\n]+/)*[^:;,'\")\]\r\n]+")
_WINDOWS_DRIVE_PATH_RE = re.compile(r"(?<![\w])(?:[A-Za-z]:\\(?:[^:;,'\")\]\r\n]+\\)*[^:;,'\")\]\r\n]+)")
_WINDOWS_UNC_PATH_RE = re.compile(r"(?<![\w\\])(?:\\\\[^\\:;,'\")\]\r\n]+(?:\\[^\\:;,'\")\]\r\n]+)+)")
_PATH_RES = (_WINDOWS_UNC_PATH_RE, _WINDOWS_DRIVE_PATH_RE, _POSIX_PATH_RE)
_MAX_CAUSE_MESSAGE_LENGTH = 240


def safe_cause_details(exc: Exception) -> dict[str, str]:
    exc_type = type(exc)
    module = getattr(exc_type, "__module__", "")
    name = getattr(exc_type, "__name__", exc_type.__class__.__name__)
    if "." in name and (not module or name.startswith(f"{module}.")):
        cause_type = name
    else:
        cause_type = name if module in {"", "builtins"} else f"{module}.{name}"
    cause_message = sanitize_cause_message(str(exc).strip() or name)
    return {
        "cause_type": cause_type,
        "cause_message": cause_message,
    }


def sanitize_cause_message(message: str) -> str:
    redacted = message
    for path_re in _PATH_RES:
        redacted = path_re.sub("<path>", redacted)
    if len(redacted) <= _MAX_CAUSE_MESSAGE_LENGTH:
        return redacted
    return redacted[: _MAX_CAUSE_MESSAGE_LENGTH - 3] + "..."


def is_project_lock_error(exc: Exception) -> bool:
    details = safe_cause_details(exc)
    cause_type = details["cause_type"]
    cause_message = details["cause_message"]
    return (
        "LockException" in cause_type
        and "Unable to lock project" in cause_message
    ) or "Unable to lock project" in cause_message


__all__ = ["is_project_lock_error", "safe_cause_details", "sanitize_cause_message"]
