from __future__ import annotations

from ghidra_mcp.domain import ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.errors import to_domain_error


def test_to_domain_error_maps_target_already_loaded_prefix():
    err = to_domain_error(
        RuntimeError("TARGET_ALREADY_LOADED: program already loaded: /main"),
        operation="load_program",
        target="fw-shadow",
        domain_path="/main",
    )

    assert err.code == ErrorCode.TARGET_ALREADY_LOADED
    assert err.details == {
        "operation": "load_program",
        "target": "fw-shadow",
        "domain_path": "/main",
    }


def test_to_domain_error_maps_program_already_imported_prefix():
    err = to_domain_error(
        RuntimeError("PROGRAM_ALREADY_IMPORTED: program already exists: /sample.exe"),
        operation="import_program",
        target="fw",
    )

    assert err.code == ErrorCode.PROGRAM_ALREADY_IMPORTED
    assert err.details == {
        "operation": "import_program",
        "target": "fw",
    }


def test_to_domain_error_maps_unsafe_active_checkout_terminate_prefix():
    err = to_domain_error(
        RuntimeError(
            "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: terminating the active checkout would hijack the local file; "
            "use undo_checkout_project_program instead"
        ),
        operation="terminate_project_program_checkout",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.UNSAFE_ACTIVE_CHECKOUT_TERMINATE
    assert err.details == {
        "operation": "terminate_project_program_checkout",
        "target": "fw",
        "domain_path": "/main",
    }


def test_to_domain_error_maps_unsafe_program_remove_prefix():
    err = to_domain_error(
        RuntimeError("UNSAFE_PROGRAM_REMOVE: refusing to remove versioned program"),
        operation="close_session",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.UNSAFE_PROGRAM_REMOVE
    assert err.details == {
        "operation": "close_session",
        "target": "fw",
        "domain_path": "/main",
    }


def test_to_domain_error_maps_add_to_version_control_required_prefix():
    err = to_domain_error(
        RuntimeError("ADD_TO_VERSION_CONTROL_REQUIRED: run add first"),
        operation="checkout_project_program",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED
    assert err.details == {
        "operation": "checkout_project_program",
        "target": "fw",
        "domain_path": "/main",
    }


def test_to_domain_error_maps_checkout_unavailable_and_hijacked_program_prefixes():
    cases = (
        ("CHECKOUT_UNAVAILABLE: exclusive checkout refused", ErrorCode.CHECKOUT_UNAVAILABLE),
        ("HIJACKED_PROGRAM: local file shadows repository", ErrorCode.HIJACKED_PROGRAM),
    )

    for message, expected in cases:
        err = to_domain_error(
            RuntimeError(message),
            operation="checkout_project_program",
            target="fw",
            domain_path="/main",
        )

        assert err.code == expected
        assert err.retryable is False


def test_to_domain_error_maps_reopen_failure_as_non_retryable():
    err = to_domain_error(
        RuntimeError("REOPEN_FAILED: remote operation may already have completed"),
        operation="commit_project_program",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.retryable is False


def test_to_domain_error_maps_save_failed_prefix():
    err = to_domain_error(
        RuntimeError("SAVE_FAILED: failed to save program before close: disk full"),
        operation="close_session",
        target="fw",
    )

    assert err.code == ErrorCode.SAVE_FAILED
    assert err.details == {
        "operation": "close_session",
        "target": "fw",
    }


def test_to_domain_error_defaults_to_operation_failed_for_non_sync_operation():
    err = to_domain_error(
        RuntimeError("unexpected failure"),
        operation="load_program",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.OPERATION_FAILED
    assert err.details == {
        "operation": "load_program",
        "target": "fw",
        "domain_path": "/main",
        "cause_type": "RuntimeError",
        "cause_message": "unexpected failure",
    }


def test_to_domain_error_defaults_to_sync_operation_failed_for_sync_operation():
    err = to_domain_error(
        RuntimeError("unexpected failure"),
        operation="commit_project_program",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.details == {
        "operation": "commit_project_program",
        "target": "fw",
        "domain_path": "/main",
        "cause_type": "RuntimeError",
        "cause_message": "unexpected failure",
    }


def test_to_domain_error_maps_sync_status_unavailable_as_sync_failure():
    message = "SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.isVersioned: backend unavailable"
    err = to_domain_error(
        RuntimeError(message),
        operation="get_project_sync_status",
        target="fw",
        domain_path="/main",
    )

    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.details == {
        "operation": "get_project_sync_status",
        "target": "fw",
        "domain_path": "/main",
        "cause_type": "RuntimeError",
        "cause_message": message,
    }


def test_to_domain_error_marks_pre_operation_sync_refresh_failures_retryable():
    messages = (
        "SYNC_REFRESH_FAILED: repository refresh failed",
        "REPOSITORY_CONNECT_FAILED: server unavailable",
        "PROJECT_DATA_REFRESH_FAILED: repository disconnected",
    )

    for message in messages:
        err = to_domain_error(
            RuntimeError(message),
            operation="checkout_project_program",
            target="fw",
            domain_path="/main",
        )

        assert err.code == ErrorCode.SYNC_OPERATION_FAILED
        assert err.retryable is True
        assert err.details and err.details["cause_message"] == message


def test_to_domain_error_maps_missing_program_message_prefixes():
    cases = (
        ("Program not found: /main", "get_project_sync_status"),
        ("Domain file not found: /main", "delete_shared_project_file"),
    )

    for message, operation in cases:
        err = to_domain_error(
            RuntimeError(message),
            operation=operation,
            target="fw",
            domain_path="/main",
        )

        assert err.code == ErrorCode.PROGRAM_NOT_FOUND
        assert err.retryable is False
        assert err.details == {
            "operation": operation,
            "target": "fw",
            "domain_path": "/main",
        }


def test_to_domain_error_maps_project_lock_and_redacts_paths():
    err = to_domain_error(
        RuntimeError("Unable to lock project! /home/ghidra/shared_user"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.retryable is True
    assert err.details == {
        "operation": "list_programs",
        "target": "shared_user",
        "cause_type": "RuntimeError",
        "cause_message": "Unable to lock project! <path>",
    }


def test_to_domain_error_redacts_windows_drive_project_lock_paths():
    err = to_domain_error(
        RuntimeError(r"Unable to lock project! C:\Users\alice\secret.gpr"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.details["cause_message"] == "Unable to lock project! <path>"


def test_to_domain_error_redacts_windows_unc_project_lock_paths():
    err = to_domain_error(
        RuntimeError(r"Unable to lock project! \\server\share\secret.gpr"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.details["cause_message"] == "Unable to lock project! <path>"


def test_to_domain_error_redacts_windows_project_lock_paths_with_spaces():
    err = to_domain_error(
        RuntimeError(r"Unable to lock project! C:\Users\alice\Project With Spaces\secret.gpr"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.details["cause_message"] == "Unable to lock project! <path>"


def test_to_domain_error_redacts_posix_project_lock_paths_with_spaces():
    err = to_domain_error(
        RuntimeError("Unable to lock project! /home/alice/Project With Spaces/secret.gpr"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.details["cause_message"] == "Unable to lock project! <path>"


def test_to_domain_error_does_not_redact_urls_as_paths():
    err = to_domain_error(
        RuntimeError("http://127.0.0.1:8081/mcp failed"),
        operation="commit_project_program",
        target="shared_user",
    )

    assert err.code == ErrorCode.SYNC_OPERATION_FAILED
    assert err.details["cause_message"] == "http://127.0.0.1:8081/mcp failed"


def test_to_domain_error_does_not_duplicate_java_exception_module():
    lock_exception_type = type(
        "ghidra.framework.store.LockException",
        (Exception,),
        {"__module__": "ghidra.framework.store"},
    )
    err = to_domain_error(
        lock_exception_type("ghidra.framework.store.LockException: Unable to lock project! /home/ghidra/shared_user"),
        operation="list_programs",
        target="shared_user",
    )

    assert err.code == ErrorCode.PROJECT_LOCKED
    assert err.details == {
        "operation": "list_programs",
        "target": "shared_user",
        "cause_type": "ghidra.framework.store.LockException",
        "cause_message": "ghidra.framework.store.LockException: Unable to lock project! <path>",
    }
