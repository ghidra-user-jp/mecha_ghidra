"""Map internal domain errors to public-facing exceptions/messages."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode

_PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.CHECKOUT_REQUIRED: "CHECKOUT_REQUIRED: 共有プロジェクトの更新系操作には checkout が必要です",
    ErrorCode.NOT_SHARED_PROJECT: "NOT_SHARED_PROJECT: 共有プロジェクトのバージョン管理対象ではありません",
    ErrorCode.NOT_CHECKED_OUT: "NOT_CHECKED_OUT: checkout済みではありません",
    ErrorCode.LOCAL_CHANGES_EXIST: "LOCAL_CHANGES_EXIST: ローカル変更があるため操作を中止しました",
    ErrorCode.LOCK_TIMEOUT: "LOCK_TIMEOUT: ロック取得に失敗しました",
    ErrorCode.SESSION_NOT_FOUND: "SESSION_NOT_FOUND: セッションが見つかりません",
    ErrorCode.TARGET_NOT_REGISTERED: "TARGET_NOT_REGISTERED: ターゲットが未登録です",
    ErrorCode.PROGRAM_NOT_FOUND: "PROGRAM_NOT_FOUND: プログラムが見つかりません",
    ErrorCode.VALIDATION_ERROR: "VALIDATION_ERROR: 入力検証に失敗しました",
    ErrorCode.REOPEN_FAILED: "REOPEN_FAILED: プログラム再オープンに失敗しました",
    ErrorCode.SAVE_FAILED: "SAVE_FAILED: 保存処理に失敗しました",
    ErrorCode.SYNC_OPERATION_FAILED: "SYNC_OPERATION_FAILED: 操作に失敗しました",
    ErrorCode.CORE_EXECUTOR_UNAVAILABLE: "CORE_EXECUTOR_UNAVAILABLE: core command dispatcherが利用できません",
}


def map_exception(exc: Exception, *, fallback_message: str | None = None, details: dict[str, Any] | None = None) -> Exception:
    if isinstance(exc, DomainError):
        payload = {"code": exc.code.value, "retryable": exc.retryable}
        if exc.hint is not None:
            payload["hint"] = exc.hint
        if exc.details:
            payload["details"] = exc.details
        if details:
            payload.update(details)
        public_message = fallback_message if fallback_message is not None else _PUBLIC_MESSAGES.get(exc.code, exc.code.value)
        mapped = RuntimeError(public_message)
        setattr(mapped, "domain_error", payload)
        mapped.__cause__ = exc
        return mapped
    return exc


__all__ = ["map_exception"]
