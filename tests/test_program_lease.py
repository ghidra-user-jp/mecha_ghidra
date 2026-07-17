from __future__ import annotations

import pytest

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure import ProgramLease


def test_program_lease_success_path():
    calls: list[str] = []

    lease = ProgramLease(
        before_close=lambda: calls.append("before_close"),
        do_operation=lambda: calls.append("operation") or {"ok": True},
        reopen=lambda: calls.append("reopen"),
    )

    result = lease.run()

    assert result == {"ok": True}
    assert calls == ["before_close", "operation", "reopen"]


def test_program_lease_save_failure_maps_to_domain_error():
    lease = ProgramLease(
        before_close=lambda: None,
        do_operation=lambda: None,
        reopen=lambda: None,
    )

    with pytest.raises(DomainError) as exc_info:
        lease.run(save=True, save_hook=lambda: (_ for _ in ()).throw(RuntimeError("save boom")))

    err = exc_info.value
    assert err.code == ErrorCode.SAVE_FAILED
    assert "save boom" in err.message


def test_program_lease_operation_failure_still_reopens():
    calls: list[str] = []

    def _operation():
        calls.append("operation")
        raise RuntimeError("op boom")

    lease = ProgramLease(
        before_close=lambda: calls.append("before_close"),
        do_operation=_operation,
        reopen=lambda: calls.append("reopen"),
    )

    with pytest.raises(RuntimeError, match="op boom"):
        lease.run()

    assert calls == ["before_close", "operation", "reopen"]


def test_program_lease_reopen_failure_maps_to_domain_error():
    lease = ProgramLease(
        before_close=lambda: None,
        do_operation=lambda: {"ok": True},
        reopen=lambda: (_ for _ in ()).throw(RuntimeError("reopen boom")),
    )

    with pytest.raises(DomainError) as exc_info:
        lease.run()

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert "reopen boom" in err.message
    assert err.retryable is False
    assert "inspect the remote operation state" in str(err.hint)


def test_program_lease_reopen_failure_marks_none_result_as_partial_success():
    lease = ProgramLease(
        before_close=lambda: None,
        do_operation=lambda: None,
        reopen=lambda: (_ for _ in ()).throw(RuntimeError("reopen boom")),
    )

    with pytest.raises(DomainError) as exc_info:
        lease.run()

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.details == {"operation_completed": True, "partial_success": True}
    assert err.retryable is False


def test_program_lease_reopen_failure_keeps_operation_error_in_details():
    def _operation():
        raise RuntimeError("operation boom")

    lease = ProgramLease(
        before_close=lambda: None,
        do_operation=_operation,
        reopen=lambda: (_ for _ in ()).throw(RuntimeError("reopen boom")),
    )

    with pytest.raises(DomainError) as exc_info:
        lease.run()

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.details == {"operation_error": "operation boom"}
    assert err.retryable is False


def test_program_lease_reopen_failure_keeps_success_result_in_details():
    operation_result = {"discarded_local_changes": True, "merged": False}
    lease = ProgramLease(
        before_close=lambda: None,
        do_operation=lambda: operation_result,
        reopen=lambda: (_ for _ in ()).throw(RuntimeError("reopen boom")),
    )

    with pytest.raises(DomainError) as exc_info:
        lease.run()

    err = exc_info.value
    assert err.code == ErrorCode.REOPEN_FAILED
    assert err.details == {
        "operation_completed": True,
        "partial_success": True,
        "operation_result": operation_result,
    }
