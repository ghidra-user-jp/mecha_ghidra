"""What a client can do next about a failure, by error code.

A call site that converts an unexpected exception passes a generic hint
("Check runtime state"); when the failure's code says more, the hint here
replaces it.  A hint written for one failure (``DomainError(hint=...)``) is
kept.  For ``NOT_FOUND`` the hint also depends on what was missing, which the
core names at the start of its message ("Function not found: ...", or a code
such as "NAMESPACE_NOT_FOUND: ...").
"""

from __future__ import annotations

from .errors import ErrorCode

_LOAD_A_PROGRAM = (
    "Load a program with load_project_program; list_project_programs shows the project's programs, "
    "and import_program adds a binary"
)
_FIND_A_FUNCTION = "list_functions (filter by name) or search_symbols finds a function's name and entry address"

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
    ErrorCode.RESULT_DISCARDED: "Inspect the program for what the first call changed instead of sending it again",
    ErrorCode.REQUEST_ID_CONFLICT: "Send these arguments with a new request_id; this one belongs to the earlier call",
    ErrorCode.RAW_LOADER_OPTION_UNAVAILABLE: (
        "Check language_id, compiler_spec_id and the loader options; details.cause_message names what this "
        "Ghidra version's raw binary loader lacks"
    ),
    ErrorCode.PROJECT_LOCKED: (
        "Another process, such as a Ghidra GUI or another server, has the project open; close it there, then retry"
    ),
    ErrorCode.GUI_UNSUPPORTED: (
        "details.reason says what the Ghidra GUI backend refused; use the alternative it names, or do it in the GUI"
    ),
    ErrorCode.GUI_NAVIGATION_FAILED: "Check the address or name, then call show_in_gui again",
    ErrorCode.BSIM_DATABASE_UNREACHABLE: "Check that the BSim database is running and reachable, then retry",
    ErrorCode.BSIM_AUTHENTICATION_FAILED: "Check the BSim user and password",
    ErrorCode.BSIM_FUNCTION_NOT_FOUND: _FIND_A_FUNCTION,
    ErrorCode.BSIM_EXECUTABLE_NOT_FOUND: "list_bsim_executables shows the executables in the database",
    ErrorCode.BSIM_EXECUTABLE_AMBIGUOUS: "Pass md5 to select one executable",
    ErrorCode.BSIM_UNSAVED_PROGRAM: "Save the program with save_project_program first",
}

_NOT_FOUND_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("Function not found", "No function found"), _FIND_A_FUNCTION),
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
    (
        ("NAMESPACE_NOT_FOUND",),
        "list_namespaces shows the namespaces; create_namespace=true creates the missing parents",
    ),
    (
        ("REPOSITORY_NOT_FOUND",),
        "Check the repository name: the Ghidra Server the message names has no such repository",
    ),
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
