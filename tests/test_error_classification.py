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
        # The code prefix decides, whatever the rest of the message says.
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


def test_to_domain_error_reads_no_code_from_the_text_of_an_uncoded_message():
    # Only a code names a refusal: an uncoded message is the operation's default failure.
    assert to_domain_error(RuntimeError("Program not found: /main"), operation="x").code is ErrorCode.OPERATION_FAILED
    assert (
        to_domain_error(RuntimeError("Session 'fw' does not exist"), operation="x").code is ErrorCode.OPERATION_FAILED
    )
    missing = HeadlessError("PROGRAM_NOT_FOUND: Program not found: /main")
    assert to_domain_error(missing, operation="x").code is ErrorCode.PROGRAM_NOT_FOUND
    assert (
        to_domain_error(RuntimeError("boom"), operation="commit_project_program").code
        is ErrorCode.SYNC_OPERATION_FAILED
    )
    assert to_domain_error(RuntimeError("boom"), operation="rename_function").code is ErrorCode.OPERATION_FAILED
    assert to_domain_error(ValueError("bad"), operation="rename_function").code is ErrorCode.VALIDATION_ERROR


def test_a_structured_code_decides_over_a_message_that_names_another():
    exc = HeadlessError("PROGRAM_NOT_FOUND: Program not found: /main", code="SAVE_FAILED")
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


def test_a_java_headless_exception_is_named_in_full_by_jpype():
    # JPype gives a Java class its full name; the check reads the last part.
    java_headless = type("java.awt.HeadlessException", (Exception,), {})
    mapped = to_domain_error(java_headless("No X11 DISPLAY variable was set"), operation="decompile_function")
    assert mapped.code is ErrorCode.HEADLESS_UNSUPPORTED
    checkout = type("ghidra.framework.store.ExclusiveCheckoutException", (Exception,), {})
    assert to_domain_error(checkout("held"), operation="x").code is ErrorCode.CHECKOUT_UNAVAILABLE


def test_a_message_that_mentions_a_domain_file_is_not_a_missing_program():
    # A coded message keeps its code even when it mentions a DomainFile.
    unsaved = HeadlessError("BSIM_UNSAVED_PROGRAM: current program has no DomainFile")
    assert to_domain_error(unsaved, operation="bsim_register_target").code is ErrorCode.BSIM_UNSAVED_PROGRAM
    # So does a failure inside Ghidra.
    throwable = type("java.lang.Throwable", (Exception,), {})
    npe = type("java.lang.NullPointerException", (throwable, ValueError), {})
    java_failure = npe('Cannot invoke "ghidra.framework.model.DomainFile.getName()" because "file" is null')
    assert to_domain_error(java_failure, operation="x").code is ErrorCode.OPERATION_FAILED
    # A programming error during a write is a failure, never a refusal that would report output_state absent.
    for bug in (
        AttributeError("'NoneType' object has no attribute 'getDomainFile'"),
        RuntimeError("Current program has no DomainFile"),
    ):
        assert to_domain_error(bug, operation="x").code is ErrorCode.OPERATION_FAILED


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (HeadlessError("EXPORT_TARGET_EXISTS: /out.gzf exists; pass overwrite=true to replace it"), "VALIDATION_ERROR"),
        (HeadlessError("EXPORT_DIRECTORY_MISSING: /missing does not exist"), "VALIDATION_ERROR"),
        (HeadlessError("C_PARSE_FAILED: line 1: syntax error"), "VALIDATION_ERROR"),
        (HeadlessError("NAMESPACE_NOT_FOUND: Foo::Bar"), "NOT_FOUND"),
        (HeadlessError("REPOSITORY_NOT_FOUND: repository 'x' does not exist on host:13100"), "NOT_FOUND"),
        (HeadlessError("IMPORT_CANCELLED: analysis was cancelled before it finished"), "OPERATION_CANCELLED"),
        # A code that names an ErrorCode member needs no table entry, whatever type raised it.
        (ValueError("BSIM_TARGET_METADATA_INVALID: category values must be scalar"), "BSIM_TARGET_METADATA_INVALID"),
        (HeadlessError("BSIM_DATABASE_UNREACHABLE: refused"), "BSIM_DATABASE_UNREACHABLE"),
    ],
)
def test_headless_codes_reach_their_public_code(exc, expected):
    assert to_domain_error(exc, operation="x").code.value == expected


def test_a_missing_namespace_or_repository_names_its_next_step():
    namespace = to_domain_error(HeadlessError("NAMESPACE_NOT_FOUND: Foo::Bar"), operation="rename_function")
    assert namespace.hint.startswith("list_namespaces")
    repository = to_domain_error(HeadlessError("REPOSITORY_NOT_FOUND: 'x' on h:1"), operation="create_project")
    assert "repository name" in repository.hint


def test_every_code_the_runtime_raises_has_a_public_code():
    """A code the table does not know becomes OPERATION_FAILED and reports a refusal as uncertain."""
    import re
    from pathlib import Path

    from ghidra_mcp.domain import classify_error_code

    source = Path(__file__).resolve().parents[1] / "src"
    raised = re.compile(
        r"""(?:Error|Exception)\(\s*f?["']([A-Z][A-Z0-9_]{3,}):|code\s*=\s*["']([A-Z][A-Z0-9_]{3,})["']"""
    )
    seen, unknown = set(), set()
    for layer in ("ghidra_headless", "ghidra_mcp/infrastructure", "ghidra_mcp/application"):
        for path in (source / layer).rglob("*.py"):
            for match in raised.finditer(path.read_text(encoding="utf-8")):
                code = match.group(1) or match.group(2)
                seen.add(code)
                if classify_error_code(code) is None:
                    unknown.add(f"{code} ({path.relative_to(source)})")
    assert {"EXPORT_TARGET_EXISTS", "NAMESPACE_NOT_FOUND", "BSIM_UNSAVED_PROGRAM"} <= seen
    assert sorted(unknown) == []
