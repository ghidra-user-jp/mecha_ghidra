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
    }
