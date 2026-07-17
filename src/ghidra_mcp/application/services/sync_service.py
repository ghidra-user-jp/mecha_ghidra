"""Shared-project sync service."""

from __future__ import annotations

from ghidra_mcp.application.services.ports import SyncRuntimePort
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_utils import is_project_lock_error, safe_cause_details
from ghidra_mcp.infrastructure.locks import LockManager


class SyncService:
    def __init__(self, runtime_state: SyncRuntimePort, *, lock_manager: LockManager | None = None) -> None:
        self._runtime = runtime_state
        self._lock_manager = lock_manager or LockManager()

    def _raise_domain_error(
        self,
        exc: Exception,
        *,
        operation: str,
        target: str,
        domain_path: str | None,
    ) -> DomainError:
        if isinstance(exc, DomainError):
            details = dict(exc.details or {})
            details.setdefault("operation", operation)
            details.setdefault("target", target)
            details.setdefault("domain_path", domain_path)
            return DomainError(
                code=exc.code,
                message=exc.message,
                hint=exc.hint,
                retryable=exc.retryable,
                details=details,
            )

        code = ErrorCode.PROJECT_LOCKED if is_project_lock_error(exc) else ErrorCode.SYNC_OPERATION_FAILED
        return DomainError(
            code=code,
            message=str(exc),
            hint="Check shared-project and checkout state",
            retryable=code == ErrorCode.PROJECT_LOCKED,
            details={
                "operation": operation,
                "target": target,
                "domain_path": domain_path,
                **safe_cause_details(exc),
            },
        )

    def _project_key(self, target: str) -> str | None:
        return self._runtime.project_lock_key(target)

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.get_project_sync_status(name, domain_path=domain_path)
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="get_project_sync_status",
                target=name,
                domain_path=domain_path,
            ) from exc

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.checkout_project_program(name, exclusive=exclusive, domain_path=domain_path)
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="checkout_project_program",
                target=name,
                domain_path=domain_path,
            ) from exc

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.add_project_program_to_version_control(
                    name,
                    comment,
                    keep_checked_out=keep_checked_out,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="add_project_program_to_version_control",
                target=name,
                domain_path=domain_path,
            ) from exc

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.commit_project_program(
                    name,
                    message,
                    keep_checked_out=keep_checked_out,
                    auto_checkout=auto_checkout,
                    on_conflict=on_conflict,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="commit_project_program",
                target=name,
                domain_path=domain_path,
            ) from exc

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.pull_project_program(
                    name,
                    on_local_changes=on_local_changes,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="pull_project_program",
                target=name,
                domain_path=domain_path,
            ) from exc

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.undo_checkout_project_program(
                    name,
                    discard_local_changes=discard_local_changes,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="undo_checkout_project_program",
                target=name,
                domain_path=domain_path,
            ) from exc

    def terminate_project_program_checkout(
        self,
        name: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.terminate_project_program_checkout(
                    name,
                    checkout_id=checkout_id,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="terminate_project_program_checkout",
                target=name,
                domain_path=domain_path,
            ) from exc

    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
        allow_non_atomic_versioned_delete: bool = False,
    ):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.delete_shared_project_file(
                    name,
                    domain_path=domain_path,
                    confirm=confirm,
                    expected_latest_version=expected_latest_version,
                    allow_private=allow_private,
                    allow_non_atomic_versioned_delete=allow_non_atomic_versioned_delete,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="delete_shared_project_file",
                target=name,
                domain_path=domain_path,
            ) from exc

    def reload_project_program(self, name: str, *, domain_path: str | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.reload_project_program(name, domain_path=domain_path)
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="reload_project_program",
                target=name,
                domain_path=domain_path,
            ) from exc

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None):
        try:
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.get_version_history(name, limit=limit, domain_path=domain_path)
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="get_version_history",
                target=name,
                domain_path=domain_path,
            ) from exc

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
            with self._lock_manager.acquire(target=name, project_key=self._project_key(name)):
                return self._runtime.get_version_diff(
                    name,
                    from_version=from_version,
                    to_version=to_version,
                    range_limit=range_limit,
                    domain_path=domain_path,
                )
        except Exception as exc:
            raise self._raise_domain_error(
                exc,
                operation="get_version_diff",
                target=name,
                domain_path=domain_path,
            ) from exc


__all__ = ["SyncService"]
