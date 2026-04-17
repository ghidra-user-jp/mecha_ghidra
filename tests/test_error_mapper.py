from __future__ import annotations

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.error_mapper import map_exception


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
