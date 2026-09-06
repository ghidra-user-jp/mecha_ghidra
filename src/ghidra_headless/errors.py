"""Structured errors raised by the in-JVM headless layer.

Every message keeps the historical ``CODE: detail`` shape so existing string
consumers keep working, while ``code`` gives the outer layers a stable field to
classify on instead of parsing message prefixes.
"""

from __future__ import annotations

import re

_CODE_PREFIX_RE = re.compile(r"^([A-Z][A-Z0-9_]+):")


def error_code_prefix(message: str) -> str | None:
    """Return the ``CODE`` prefix of a ``CODE: detail`` message, if present."""

    match = _CODE_PREFIX_RE.match(message or "")
    return match.group(1) if match else None


def error_code_of(exc: BaseException) -> str | None:
    """Return the structured code of ``exc`` (``HeadlessError.code`` or a ``CODE:`` prefix)."""

    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code
    return error_code_prefix(str(exc))


class HeadlessError(RuntimeError):
    """A failure with a machine-readable ``code`` and a human-readable message."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or error_code_prefix(message) or "OPERATION_FAILED"


__all__ = ["HeadlessError", "error_code_of", "error_code_prefix"]
