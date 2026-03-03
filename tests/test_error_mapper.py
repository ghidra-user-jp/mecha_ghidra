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
    assert str(mapped) == "SYNC_OPERATION_FAILED: 操作に失敗しました"
    assert getattr(mapped, "domain_error")["code"] == ErrorCode.SYNC_OPERATION_FAILED.value
    assert getattr(mapped, "domain_error")["details"]["target"] == "fw"

