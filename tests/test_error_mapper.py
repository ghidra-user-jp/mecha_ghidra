from __future__ import annotations

import pytest

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_mapping import to_domain_error
from ghidra_mcp.presentation.error_mapper import map_exception


def test_map_exception_masks_internal_domain_message_for_operation_failed():
    exc = DomainError(
        code=ErrorCode.OPERATION_FAILED,
        message="internal failure: /tmp/secret/path/app.gpr",
        details={"target": "fw"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "OPERATION_FAILED: operation failed"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.OPERATION_FAILED.value
    assert getattr(mapped, "domain_error")["details"]["target"] == "fw"


def test_map_exception_masks_internal_domain_message_for_sync_operation_failed():
    exc = DomainError(
        code=ErrorCode.SYNC_OPERATION_FAILED,
        message="internal failure: /tmp/secret/path/app.gpr",
        details={"target": "fw"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "SYNC_OPERATION_FAILED: operation failed"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.SYNC_OPERATION_FAILED.value
    assert getattr(mapped, "domain_error")["details"]["target"] == "fw"


def test_map_exception_appends_safe_generic_cause_summary():
    exc = DomainError(
        code=ErrorCode.SYNC_OPERATION_FAILED,
        message="internal failure: /tmp/secret/path/app.gpr",
        details={
            "target": "fw",
            "cause_type": "RuntimeError",
            "cause_message": "internal failure: <path>",
        },
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "SYNC_OPERATION_FAILED: operation failed (RuntimeError: internal failure: <path>)"
    assert getattr(mapped, "domain_error")["details"]["cause_message"] == "internal failure: <path>"


def test_map_exception_does_not_duplicate_cause_type_prefix():
    exc = DomainError(
        code=ErrorCode.OPERATION_FAILED,
        message="project lock failed",
        details={
            "cause_type": "ghidra.framework.store.LockException",
            "cause_message": "ghidra.framework.store.LockException: Unable to lock project! <path>",
        },
    )

    mapped = map_exception(exc)

    assert (
        str(mapped) == "OPERATION_FAILED: operation failed "
        "(ghidra.framework.store.LockException: Unable to lock project! <path>)"
    )


def test_map_exception_exposes_project_locked_with_safe_cause():
    exc = DomainError(
        code=ErrorCode.PROJECT_LOCKED,
        message="Unable to lock project! /tmp/private/project",
        retryable=True,
        details={
            "cause_type": "RuntimeError",
            "cause_message": "Unable to lock project! <path>",
        },
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert (
        str(mapped)
        == "PROJECT_LOCKED: project is locked by another process (RuntimeError: Unable to lock project! <path>)"
    )
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.PROJECT_LOCKED.value


def test_map_exception_exposes_merge_required_guidance():
    exc = DomainError(
        code=ErrorCode.MERGE_REQUIRED,
        message="UNSAFE_MERGE_REQUIRED: automatic merge is disabled",
        details={"target": "fw"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert (
        str(mapped)
        == "MERGE_REQUIRED: the repository moved ahead of this checkout and automatic merge is disabled; pull_project_program refreshes an unmodified checkout, and commit_project_program(on_conflict='discard') drops the local changes and follows the latest version"
    )
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.MERGE_REQUIRED.value


def test_map_exception_exposes_active_checkout_terminate_guidance():
    exc = DomainError(
        code=ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE,
        message=(
            "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: terminating the active checkout would hijack the local file; "
            "use undo_checkout_project_program instead"
        ),
        details={"target": "fw", "domain_path": "/main"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert (
        str(mapped) == "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: active checkout cannot be terminated; "
        "use undo_checkout_project_program instead"
    )
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE.value
    assert getattr(mapped, "domain_error")["details"] == {"target": "fw", "domain_path": "/main"}


def test_map_exception_exposes_program_remove_guard():
    exc = DomainError(
        code=ErrorCode.UNSAFE_PROGRAM_REMOVE,
        message="UNSAFE_PROGRAM_REMOVE: refusing to remove versioned program",
        details={"target": "fw", "domain_path": "/main"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "UNSAFE_PROGRAM_REMOVE: refusing to remove a versioned shared-project program"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.UNSAFE_PROGRAM_REMOVE.value


def test_map_exception_exposes_add_to_version_control_guidance():
    exc = DomainError(
        code=ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED,
        message="ADD_TO_VERSION_CONTROL_REQUIRED: run add first",
        details={"target": "fw", "domain_path": "/main", "required_action": "add_project_program_to_version_control"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "ADD_TO_VERSION_CONTROL_REQUIRED: run add_project_program_to_version_control first"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED.value


def test_map_exception_masks_internal_details_for_target_already_loaded():
    exc = DomainError(
        code=ErrorCode.TARGET_ALREADY_LOADED,
        message="TARGET_ALREADY_LOADED: program already loaded: /tmp/secret/project/main",
        details={"target": "fw-shadow", "domain_path": "/main", "owner_target": "fw-primary"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "TARGET_ALREADY_LOADED: program is already loaded; use the existing target"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.TARGET_ALREADY_LOADED.value
    assert getattr(mapped, "domain_error")["details"] == {
        "target": "fw-shadow",
        "domain_path": "/main",
        "owner_target": "fw-primary",
    }


def test_map_exception_masks_internal_details_for_program_already_imported():
    exc = DomainError(
        code=ErrorCode.PROGRAM_ALREADY_IMPORTED,
        message="PROGRAM_ALREADY_IMPORTED: program already exists: /tmp/secret/project/sample.exe",
        details={"target": "fw", "binary_path": "/tmp/sample.exe", "existing_domain_path": "/sample.exe"},
    )

    mapped = map_exception(exc)

    assert isinstance(mapped, RuntimeError)
    assert str(mapped) == "PROGRAM_ALREADY_IMPORTED: program already exists in project; use load_project_program"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.PROGRAM_ALREADY_IMPORTED.value
    assert getattr(mapped, "domain_error")["details"] == {
        "target": "fw",
        "binary_path": "/tmp/sample.exe",
        "existing_domain_path": "/sample.exe",
    }


def test_map_exception_keeps_the_message_a_bsim_tool_wrote():
    # BsimService writes these messages itself and masks credentials in them.
    exc = DomainError(
        code=ErrorCode.BSIM_URL_INVALID,
        message="BSIM_URL_INVALID: unsupported BSim URL scheme 'ftp' (supported: elastic, file, https, postgresql)",
    )

    mapped = map_exception(exc)

    assert str(mapped) == exc.message
    assert getattr(mapped, "domain_error") == {"code": "BSIM_URL_INVALID", "retryable": False}


def test_map_exception_keeps_the_fixed_text_of_bsim_match_stale():
    # The core raises this one, so its message is not public.
    mapped = map_exception(DomainError(code=ErrorCode.BSIM_MATCH_STALE, message="internal: /tmp/secret"))

    assert str(mapped) == "BSIM_MATCH_STALE: the loaded program does not match the BSim reference"


def _public(exc):
    """What a client sees for ``exc`` raised by a core command."""
    mapped = map_exception(to_domain_error(exc, operation="decompile_function", target="fw"))
    return str(mapped), mapped.domain_error


def test_a_missing_item_is_named_with_a_way_to_find_it():
    message, error = _public(LookupError("Function not found: main"))
    assert message == "NOT_FOUND: Function not found: main"
    assert error["code"] == "NOT_FOUND" and error["retryable"] is False
    assert "list_functions" in error["hint"]
    # A data type path is no host path: it stays as the caller wrote it.
    message, error = _public(LookupError("Data type not found: /windef.h/RECT"))
    assert message == "NOT_FOUND: Data type not found: /windef.h/RECT"
    assert "list_data_types" in error["hint"]
    assert "decompile_function" in _public(LookupError("Variable not found: local_10"))[1]["hint"]
    assert _public(LookupError("Enum values not found: A, B"))[1]["hint"].startswith("Look the name")


def test_a_bad_argument_keeps_its_reason_but_not_host_paths():
    message, error = _public(ValueError("Invalid address: 0xZZZ"))
    assert message == "VALIDATION_ERROR: Invalid address: 0xZZZ"
    assert error["hint"] == "Correct the argument the message names, then call again"
    assert _public(ValueError("Binary is not a file: /Users/someone/a.bin"))[0] == (
        "VALIDATION_ERROR: Binary is not a file: <path>"
    )


@pytest.mark.parametrize(
    ("message", "hint"),
    [
        ("PROGRAM_NOT_OPEN: target 'fw' has no program loaded", "load_project_program"),
        ("TARGET_NOT_REGISTERED: target 'fw' is not registered", "list_targets"),
    ],
)
def test_a_target_without_a_program_says_which_is_missing(message, hint):
    public, error = _public(RuntimeError(message))
    assert public == message
    assert error["code"] == message.split(":")[0] and hint in error["hint"]


def test_a_code_hint_fills_in_only_where_the_error_has_none():
    mapped = map_exception(DomainError(ErrorCode.TARGET_NOT_REGISTERED, "Target is not registered"))
    assert str(mapped) == "TARGET_NOT_REGISTERED: Target is not registered"
    assert "register_target" in mapped.domain_error["hint"]
    written = map_exception(DomainError(ErrorCode.VALIDATION_ERROR, "binary_path is missing", hint="Pass binary_path"))
    assert written.domain_error["hint"] == "Pass binary_path"
    assert "hint" not in map_exception(DomainError(ErrorCode.OPERATION_FAILED, "boom")).domain_error


def test_java_and_programming_errors_are_not_blamed_on_the_caller():
    # JPype makes NullPointerException a ValueError and IndexOutOfBoundsException an IndexError.
    throwable = type("java.lang.Throwable", (Exception,), {})
    null_pointer = type("java.lang.NullPointerException", (ValueError, throwable), {})
    out_of_bounds = type("java.lang.IndexOutOfBoundsException", (IndexError, throwable), {})
    for exc in (null_pointer("x is null"), out_of_bounds("7"), KeyError("k"), IndexError("i")):
        assert to_domain_error(exc, operation="rename_function").code is ErrorCode.OPERATION_FAILED, exc


def test_an_unanalyzed_program_is_its_own_code_with_the_step_that_fixes_it():
    from ghidra_headless.errors import HeadlessError

    cause = "PROGRAM_NOT_ANALYZED: the program has not been analyzed, so decompiler symbols are unavailable; "
    message, error = _public(HeadlessError(cause + "run analyze_program first (Decompilation failed: /tmp/x)"))
    assert message == (
        "PROGRAM_NOT_ANALYZED: the program has not been analyzed, so the decompiler's variables are unavailable"
    )
    assert error["code"] == "PROGRAM_NOT_ANALYZED" and "analyze_program" in error["hint"]
    # What the decompiler reported stays in the details, without host paths.
    assert error["details"]["cause_message"].endswith("(Decompilation failed: <path>)")


def test_a_missing_raw_loader_option_is_named_in_the_details():
    from ghidra_headless.errors import HeadlessError

    message, error = _public(HeadlessError("RAW_LOADER_OPTION_UNAVAILABLE: Base Address"))
    assert message.startswith("RAW_LOADER_OPTION_UNAVAILABLE: Ghidra's raw binary loader has no option")
    assert error["code"] == "RAW_LOADER_OPTION_UNAVAILABLE" and "language_id" in error["hint"]
    assert error["details"]["cause_message"] == "RAW_LOADER_OPTION_UNAVAILABLE: Base Address"
