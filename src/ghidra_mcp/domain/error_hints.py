"""What a client can do next about a failure, by error code.

A call site that converts an unexpected exception passes a generic hint
("Check runtime state"); when the failure's code says more, the hint here
replaces it.  A hint written for one failure (``DomainError(hint=...)``) is
kept.  For ``NOT_FOUND`` the hint also depends on what was missing, which the
core names at the start of its message ("Function not found: ...").
"""

from __future__ import annotations

from .errors import ErrorCode

_LOAD_A_PROGRAM = (
    "Load a program with load_project_program; list_project_programs shows the project's programs, "
    "and import_program adds a binary"
)

RECOVERY_HINTS: dict[ErrorCode, str] = {
    ErrorCode.TARGET_NOT_REGISTERED: "list_targets shows the registered targets; register_target adds one for a project",
    ErrorCode.PROGRAM_NOT_OPEN: _LOAD_A_PROGRAM,
    ErrorCode.SESSION_NOT_FOUND: _LOAD_A_PROGRAM,
    ErrorCode.PROGRAM_NOT_FOUND: "list_project_programs shows the domain paths in the target's project",
    ErrorCode.NOT_FOUND: (
        "Look the name or address up with list_functions, search_symbols or list_data_types, then call again"
    ),
    ErrorCode.VALIDATION_ERROR: "Correct the argument the message names, then call again",
    ErrorCode.CHECKOUT_REQUIRED: "Check the program out with checkout_project_program, then call again",
    ErrorCode.PROGRAM_NOT_ANALYZED: "Run analyze_program on the target and wait for the job, then call again",
    ErrorCode.RAW_LOADER_OPTION_UNAVAILABLE: (
        "Check language_id, compiler_spec_id and the loader options; details.cause_message names what this "
        "Ghidra version's raw binary loader lacks"
    ),
    ErrorCode.PROJECT_LOCKED: (
        "Another process, such as a Ghidra GUI or another server, has the project open; close it there, then retry"
    ),
}

_NOT_FOUND_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        ("Function not found", "No function found"),
        "list_functions (filter by name) or search_symbols finds a function's name and entry address",
    ),
    (
        ("Data type not found", "Struct not found", "Enum not found"),
        "list_data_types (filter by name) finds a data type's full path",
    ),
    (
        ("Variable not found",),
        "decompile_function shows the decompiler's variable names; get_function lists the stored parameters and locals",
    ),
    (("No data symbol",), "list_data_items shows the defined data and its labels"),
    (("Bookmark not found",), "list_bookmarks shows the bookmarks and their addresses"),
)


def recovery_hint(code: ErrorCode, message: str = "") -> str | None:
    """The next step for a failure with ``code``, or None when the code says nothing more."""
    if code is ErrorCode.NOT_FOUND:
        missing = message.removeprefix(f"{code.value}:").strip()
        for prefixes, hint in _NOT_FOUND_HINTS:
            if missing.startswith(prefixes):
                return hint
    return RECOVERY_HINTS.get(code)


__all__ = ["RECOVERY_HINTS", "recovery_hint"]
