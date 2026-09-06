from __future__ import annotations

import pytest

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease


def _lease(*, operation, reopen, before_close=lambda: None):
    return ProgramLease(before_close=before_close, do_operation=operation, reopen=reopen)


def test_partial_success_details_survive_a_reopen_failure():
    def operation():
        raise DomainError(
            code=ErrorCode.SYNC_OPERATION_FAILED,
            message="undo returned but refresh failed",
            retryable=False,
            details={"operation": "undo_checkout", "operation_completed": True, "partial_success": True, "extra": 1},
        )

    def reopen():
        raise RuntimeError("reopen boom")

    with pytest.raises(DomainError) as exc_info:
        _lease(operation=operation, reopen=reopen).run()

    err = exc_info.value
    assert err.code is ErrorCode.REOPEN_FAILED
    assert err.retryable is False
    assert err.details["operation_error"] == "undo returned but refresh failed"
    assert err.details["operation"] == "undo_checkout"
    assert err.details["operation_completed"] is True
    assert err.details["partial_success"] is True
    assert "extra" not in err.details


def test_completed_operation_result_is_reported_when_reopen_fails():
    def reopen():
        raise RuntimeError("reopen boom")

    with pytest.raises(DomainError) as exc_info:
        _lease(operation=lambda: {"deleted": True}, reopen=reopen).run()

    err = exc_info.value
    assert err.code is ErrorCode.REOPEN_FAILED
    assert err.details == {"operation_completed": True, "partial_success": True, "operation_result": {"deleted": True}}


def test_save_hook_runs_only_when_requested_and_before_close():
    calls: list[str] = []
    lease = _lease(
        operation=lambda: calls.append("operation"),
        reopen=lambda: calls.append("reopen"),
        before_close=lambda: calls.append("before_close"),
    )
    lease.run(save=False, save_hook=lambda: calls.append("save"))
    assert calls == ["before_close", "operation", "reopen"]

    calls.clear()
    lease.run(save=True, save_hook=lambda: calls.append("save"))
    assert calls == ["save", "before_close", "operation", "reopen"]

    calls.clear()
    lease.run(save=True, save_hook=None)
    assert calls == ["before_close", "operation", "reopen"]
