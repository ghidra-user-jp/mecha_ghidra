from __future__ import annotations

from ghidra_mcp.domain import DomainError, ErrorCode
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
        str(mapped)
        == "OPERATION_FAILED: operation failed "
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
    assert str(mapped) == "PROJECT_LOCKED: project is locked by another process (RuntimeError: Unable to lock project! <path>)"
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
        == "MERGE_REQUIRED: automatic merge is disabled; reopen the latest version or re-checkout before retrying"
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
        str(mapped)
        == "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: active checkout cannot be terminated; "
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
