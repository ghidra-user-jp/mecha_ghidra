"""Target lifecycle service."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode


class TargetService:
    def __init__(self, runtime_state: RuntimeState) -> None:
        self._runtime = runtime_state

    def _raise_domain_error(self, exc: RuntimeError, *, operation: str, target: str | None = None) -> None:
        message = str(exc)
        code = ErrorCode.SYNC_OPERATION_FAILED
        retryable = False

        if "セッション '" in message and ("存在しません" in message or "初期化されていません" in message):
            code = ErrorCode.SESSION_NOT_FOUND
        elif "ターゲット '" in message and "初期化されていません" in message:
            code = ErrorCode.TARGET_NOT_REGISTERED
        elif message.startswith("REOPEN_FAILED"):
            code = ErrorCode.REOPEN_FAILED
            retryable = True
        elif message.startswith("SAVE_FAILED"):
            code = ErrorCode.SAVE_FAILED
        elif message.startswith("CHECKOUT_REQUIRED"):
            code = ErrorCode.CHECKOUT_REQUIRED
        elif "CORE_EXECUTOR_UNAVAILABLE" in message:
            code = ErrorCode.CORE_EXECUTOR_UNAVAILABLE

        raise DomainError(
            code=code,
            message=message,
            hint="操作対象の target/session 状態を確認してください",
            retryable=retryable,
            details={"operation": operation, "target": target},
        ) from exc

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.create_session(
                name,
                project_location,
                project_name=project_name,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="create_session", target=name)

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None):
        try:
            return self._runtime.register_target(name, project_location, project_name=project_name)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="register_target", target=name)

    def list_targets(self):
        return self._runtime.list_targets()

    def list_programs(self, name: str):
        try:
            return self._runtime.list_programs(name)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="list_programs", target=name)

    def load_program(self, name: str, domain_path: str):
        try:
            return self._runtime.load_program(name, domain_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="load_program", target=name)

    def import_program(self, name: str, binary_path: str):
        try:
            return self._runtime.import_program(name, binary_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="import_program", target=name)

    def close_session(self, name: str, *, remove_program: bool = False):
        try:
            return self._runtime.close_session(name, remove_program=remove_program)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="close_session", target=name)

    def close_all(self) -> None:
        return self._runtime.close_all()

    def has_sessions(self) -> bool:
        return self._runtime.has_sessions()

    def has_targets(self) -> bool:
        return self._runtime.has_targets()

    def call(self, command: str, params: dict[str, Any] | None = None, target: str = "default") -> Any:
        try:
            return self._runtime.call(command, params, target)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation=f"call:{command}", target=target)


__all__ = ["TargetService"]
