"""Shared-project sync service."""

from __future__ import annotations

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode


class SyncService:
    def __init__(self, runtime_state: RuntimeState) -> None:
        self._runtime = runtime_state

    def _raise_domain_error(
        self,
        exc: RuntimeError,
        *,
        operation: str,
        target: str,
        domain_path: str | None,
    ) -> None:
        message = str(exc)
        code = ErrorCode.SYNC_OPERATION_FAILED
        retryable = False

        if message.startswith("CHECKOUT_REQUIRED"):
            code = ErrorCode.CHECKOUT_REQUIRED
        elif message.startswith("NOT_SHARED_PROJECT"):
            code = ErrorCode.NOT_SHARED_PROJECT
        elif message.startswith("NOT_CHECKED_OUT"):
            code = ErrorCode.NOT_CHECKED_OUT
        elif message.startswith("LOCAL_CHANGES_EXIST"):
            code = ErrorCode.LOCAL_CHANGES_EXIST
        elif message.startswith("REOPEN_FAILED"):
            code = ErrorCode.REOPEN_FAILED
            retryable = True
        elif message.startswith("SAVE_FAILED"):
            code = ErrorCode.SAVE_FAILED

        raise DomainError(
            code=code,
            message=message,
            hint="shared project の状態と checkout 状態を確認してください",
            retryable=retryable,
            details={"operation": operation, "target": target, "domain_path": domain_path},
        ) from exc

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None):
        try:
            return self._runtime.get_project_sync_status(name, domain_path=domain_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="get_project_sync_status", target=name, domain_path=domain_path)

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.checkout_project_program(name, exclusive=exclusive, domain_path=domain_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="checkout_project_program", target=name, domain_path=domain_path)

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.add_project_program_to_version_control(
                name,
                comment,
                keep_checked_out=keep_checked_out,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(
                exc,
                operation="add_project_program_to_version_control",
                target=name,
                domain_path=domain_path,
            )

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.commit_project_program(
                name,
                message,
                keep_checked_out=keep_checked_out,
                auto_checkout=auto_checkout,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="commit_project_program", target=name, domain_path=domain_path)

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.pull_project_program(
                name,
                on_local_changes=on_local_changes,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="pull_project_program", target=name, domain_path=domain_path)

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.undo_checkout_project_program(
                name,
                discard_local_changes=discard_local_changes,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(
                exc,
                operation="undo_checkout_project_program",
                target=name,
                domain_path=domain_path,
            )

    def terminate_project_program_checkout(
        self,
        name: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.terminate_project_program_checkout(
                name,
                checkout_id=checkout_id,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(
                exc,
                operation="terminate_project_program_checkout",
                target=name,
                domain_path=domain_path,
            )

    def reload_project_program(self, name: str, *, domain_path: str | None = None):
        try:
            return self._runtime.reload_project_program(name, domain_path=domain_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="reload_project_program", target=name, domain_path=domain_path)

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None):
        try:
            return self._runtime.get_version_history(name, limit=limit, domain_path=domain_path)
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="get_version_history", target=name, domain_path=domain_path)

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        try:
            return self._runtime.get_version_diff(
                name,
                from_version=from_version,
                to_version=to_version,
                range_limit=range_limit,
                domain_path=domain_path,
            )
        except RuntimeError as exc:
            self._raise_domain_error(exc, operation="get_version_diff", target=name, domain_path=domain_path)


__all__ = ["SyncService"]
