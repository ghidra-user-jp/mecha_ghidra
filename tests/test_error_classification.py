from __future__ import annotations

import pytest

from ghidra_headless.errors import HeadlessError, error_code_prefix
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.domain import ErrorCode, classify_runtime_error
from ghidra_mcp.infrastructure.ghidra_adapter.runtime.errors import to_domain_error


def test_headless_error_extracts_its_code_from_the_message_prefix():
    exc = HeadlessError("SAVE_FAILED: failed to save program: DomainFile is read-only")
    assert exc.code == "SAVE_FAILED"
    assert str(exc).startswith("SAVE_FAILED:")
    assert isinstance(exc, RuntimeError)
    assert HeadlessError("no prefix here").code == "OPERATION_FAILED"
    assert HeadlessError("detail", code="CUSTOM").code == "CUSTOM"
    assert error_code_prefix("lowercase: nope") is None


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        # Prefix classification must win over the "DomainFile" substring heuristic.
        ("SAVE_FAILED: failed to save program before close: DomainFile is read-only", ErrorCode.SAVE_FAILED),
        ("SESSION_CLOSE_FAILED: failed to close project: DomainFile still in use", ErrorCode.SESSION_CLOSE_FAILED),
        ("PROJECT_ALREADY_EXISTS: /tmp/x.gpr", ErrorCode.PROJECT_ALREADY_EXISTS),
        (
            "IMPORT_POST_PROCESS_FAILED: rolled back imported program /a after post-processing failed",
            ErrorCode.IMPORT_FAILED,
        ),
        ("VERSION_DIFF_TIMEOUT: version diff exceeded 60 seconds", ErrorCode.VERSION_DIFF_TIMEOUT),
        ("PROGRAM_NOT_OPEN: program '/a' is not open in this project handle", ErrorCode.PROGRAM_NOT_OPEN),
        (
            "ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed",
            ErrorCode.ADD_TO_VERSION_CONTROL_NOT_ALLOWED,
        ),
        ("CHECKIN_NOT_ALLOWED: checkin is not allowed", ErrorCode.CHECKIN_NOT_ALLOWED),
        ("PROJECT_IN_USE: cannot overwrite", ErrorCode.PROJECT_IN_USE),
        ("SESSION_CHANGED: target 'x' session changed", ErrorCode.SESSION_CHANGED),
    ],
)
def test_to_domain_error_uses_the_shared_prefix_table(message, expected):
    for exc in (RuntimeError(message), HeadlessError(message)):
        mapped = to_domain_error(exc, operation="x", target="fw")
        assert mapped.code is expected, message
        assert mapped.details["target"] == "fw"


def test_to_domain_error_keeps_heuristics_for_unprefixed_messages():
    assert to_domain_error(RuntimeError("Program not found: /main"), operation="x").code is ErrorCode.PROGRAM_NOT_FOUND
    assert (
        to_domain_error(RuntimeError("Session 'fw' does not exist"), operation="x").code is ErrorCode.SESSION_NOT_FOUND
    )
    assert (
        to_domain_error(RuntimeError("boom"), operation="commit_project_program").code
        is ErrorCode.SYNC_OPERATION_FAILED
    )
    assert to_domain_error(RuntimeError("boom"), operation="rename_function").code is ErrorCode.OPERATION_FAILED
    assert to_domain_error(ValueError("bad"), operation="rename_function").code is ErrorCode.VALIDATION_ERROR


def test_structured_code_wins_over_message_text():
    exc = HeadlessError("Program not found: DomainFile", code="SAVE_FAILED")
    classification = classify_runtime_error(exc)
    assert classification is not None and classification.code is ErrorCode.SAVE_FAILED
    assert to_domain_error(exc, operation="x").code is ErrorCode.SAVE_FAILED


def test_retryable_flags_follow_the_table():
    assert to_domain_error(RuntimeError("REPOSITORY_CONNECT_FAILED: down"), operation="x").retryable is True
    assert to_domain_error(RuntimeError("LOCK_TIMEOUT: busy"), operation="x").retryable is True
    assert to_domain_error(RuntimeError("REOPEN_FAILED: nope"), operation="x").retryable is False


def test_target_service_classifies_through_the_same_table():
    class _Runtime:
        def project_lock_key(self, name):
            return None

        def load_program(self, name, domain_path, *, version=None):
            raise HeadlessError("PROJECT_ALREADY_EXISTS: /x.gpr")

    service = TargetService(_Runtime())
    from ghidra_mcp.domain import DomainError

    with pytest.raises(DomainError) as exc_info:
        service.load_program("fw", "/main")
    assert exc_info.value.code is ErrorCode.PROJECT_ALREADY_EXISTS


def test_exclusive_checkout_exception_maps_to_checkout_unavailable():
    class ExclusiveCheckoutException(Exception):  # mirrors ghidra.framework.store.ExclusiveCheckoutException
        pass

    mapped = to_domain_error(
        ExclusiveCheckoutException("File checked out exclusively to another project by: mecha"),
        operation="checkout_project_program",
    )
    assert mapped.code is ErrorCode.CHECKOUT_UNAVAILABLE
    assert mapped.retryable is True
    wrapped = to_domain_error(
        RuntimeError("ghidra.framework.store.ExclusiveCheckoutException: File checked out exclusively"),
        operation="checkout_project_program",
    )
    assert wrapped.code is ErrorCode.CHECKOUT_UNAVAILABLE
