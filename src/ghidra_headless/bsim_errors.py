"""The error a failed BSim database call raises, from the database's own last error.

``FunctionDatabase.getLastError()`` holds a category besides the text.  A
refused login is named by its category (Ghidra's text for it, "Could not
authenticate with database", matches no keyword); an unreachable server is
reported as ``Initialization``, so BsimService tells that one from the text,
which here is the database's own.
"""

from __future__ import annotations

from ghidra_headless.errors import HeadlessError

_AUTHENTICATION_CATEGORIES = frozenset({"Authentication", "AuthenticationCancelled"})


def database_error(code: str, last_error, *, fallback: BaseException | None = None) -> HeadlessError:
    """``code: <database message>``, or BSIM_AUTHENTICATION_FAILED when the database refused the login."""
    if last_error is None:
        message = str(fallback).strip() if fallback is not None else ""
        return HeadlessError("%s: %s" % (code, message or "unknown error"))
    message = str(last_error.message or "").strip() or "unknown error"
    if str(last_error.category) in _AUTHENTICATION_CATEGORIES:
        code = "BSIM_AUTHENTICATION_FAILED"
    return HeadlessError("%s: %s" % (code, message))


__all__ = ["database_error"]
