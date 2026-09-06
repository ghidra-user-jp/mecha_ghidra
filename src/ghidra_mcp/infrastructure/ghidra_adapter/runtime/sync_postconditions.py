"""Status validation, postcondition checks and partial-success reporting."""

from __future__ import annotations

import logging
from typing import Any, Dict

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import ProjectHandle
from ghidra_mcp.domain import DomainError, ErrorCode

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class SyncPostconditionMixin:
    """Mixin for :class:`RuntimeSyncOperations`; expects ``self._store``."""

    _store: RuntimeSessionStore

    @staticmethod
    def _ensure_checkout_status_consistent(status: Dict[str, Any], *, context: str) -> None:
        is_checked_out = bool(status.get("is_checked_out"))
        has_checkout_status = status.get("checkout_status") is not None
        if is_checked_out != has_checkout_status:
            raise HeadlessError(
                "SYNC_STATUS_UNAVAILABLE: inconsistent checkout state for "
                f"{context} (is_checked_out={is_checked_out}, "
                f"checkout_status_present={has_checkout_status})"
            )

    def _read_postcondition_sync_status_locked(
        self,
        name: str,
        *,
        domain_path: str,
        operation: str,
    ) -> Dict[str, Any]:
        try:
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            return self._get_refreshed_sync_status_locked(
                handle,
                resolved_domain_path,
                require_refresh=True,
            )
        except Exception as exc:
            raise self._partial_success_error(
                operation=operation,
                message=f"operation completed but postcondition status could not be read: {exc}",
            ) from exc

    def _verify_commit_postcondition(
        self,
        status: Dict[str, Any],
        *,
        previous_version: Any,
        previous_latest_version: Any,
    ) -> None:
        try:
            new_version = int(status.get("version"))
            prior_versions = [int(value) for value in (previous_version, previous_latest_version) if value is not None]
        except (TypeError, ValueError) as exc:
            raise self._partial_success_error(
                operation="commit_project_program",
                message=f"commit returned but version state is unavailable: {exc}",
            ) from exc
        if new_version < 1 or (prior_versions and new_version <= max(prior_versions)):
            prior_text = max(prior_versions) if prior_versions else None
            raise self._partial_success_error(
                operation="commit_project_program",
                message=(
                    "commit returned but the program version did not advance "
                    f"(before={prior_text}, after={new_version})"
                ),
            )

    @staticmethod
    def _status_contains_checkout_id(status: Dict[str, Any], checkout_id: int) -> bool:
        expected = int(checkout_id)
        checkout_status = status.get("checkout_status") or {}
        values = [checkout_status.get("checkout_id")]
        values.extend(item.get("checkout_id") for item in (status.get("checkouts") or []))
        for value in values:
            if value is None:
                continue
            try:
                if int(value) == expected:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    @staticmethod
    def _partial_success_error(*, operation: str, message: str) -> DomainError:
        return DomainError(
            code=ErrorCode.SYNC_OPERATION_FAILED,
            message=f"SYNC_OPERATION_FAILED: {message}",
            hint="Inspect the repository state before deciding whether it is safe to retry",
            retryable=False,
            details={
                "operation": operation,
                "operation_completed": True,
                "partial_success": True,
            },
        )

    def _ensure_latest_version_postcondition(
        self,
        status: Dict[str, Any],
        *,
        operation: str,
        operation_completed: bool,
    ) -> None:
        version = status.get("version")
        latest_version = status.get("latest_version")
        try:
            versions_match = (
                version is not None
                and latest_version is not None
                and int(version) >= 1
                and int(version) == int(latest_version)
            )
        except (TypeError, ValueError):
            versions_match = False
        if status.get("is_latest_version") is True and versions_match:
            return

        message = (
            "FOLLOW_LATEST_FAILED: refreshed program is not at repository latest "
            f"(version={version}, latest_version={latest_version}, "
            f"is_latest_version={status.get('is_latest_version')})"
        )
        if operation_completed:
            raise self._partial_success_error(operation=operation, message=message)
        raise DomainError(
            code=ErrorCode.SYNC_OPERATION_FAILED,
            message=f"SYNC_OPERATION_FAILED: {message}",
            hint="Retry after the repository refresh path is available",
            retryable=True,
            details={
                "operation": operation,
                "operation_completed": False,
                "partial_success": False,
            },
        )

    @staticmethod
    def _list_program_paths_locked(handle: ProjectHandle) -> set[str]:
        return {str(item.get("domain_path")) for item in handle.list_programs() if str(item.get("domain_path") or "")}

    @staticmethod
    def _resolve_new_keep_domain_path(
        handle: ProjectHandle,
        domain_path: str,
        existing_program_paths: set[str],
    ) -> str:
        keep_prefix = f"{domain_path}.keep"
        current_paths = {
            str(item.get("domain_path")) for item in handle.list_programs() if str(item.get("domain_path") or "")
        }
        new_keep_paths = sorted(
            (path for path in current_paths if path.startswith(keep_prefix) and path not in existing_program_paths),
            key=lambda path: SyncPostconditionMixin._keep_path_sort_key(path, keep_prefix),
        )
        if new_keep_paths:
            return new_keep_paths[-1]
        raise HeadlessError(f"KEEP_FILE_NOT_FOUND: no new keep file was created for {domain_path}")

    @staticmethod
    def _keep_path_sort_key(path: str, keep_prefix: str) -> tuple[int, int, str]:
        suffix = path[len(keep_prefix) :]
        if suffix == "":
            return (1, 0, path)
        if suffix.startswith(".") and suffix[1:].isdigit():
            return (1, int(suffix[1:]), path)
        return (0, 0, path)

    def _read_handle_status_after_side_effect(
        self,
        handle: ProjectHandle,
        *,
        domain_path: str,
        operation: str,
    ) -> Dict[str, Any]:
        try:
            self._refresh_project_sync_state_locked(handle, required=True)
            return handle.get_sync_status(domain_path)
        except Exception as exc:
            raise self._partial_success_error(
                operation=operation,
                message=f"operation completed but postcondition status could not be read: {exc}",
            ) from exc

    @staticmethod
    def _ensure_delete_allowed(status: Dict[str, Any], *, allow_private: bool) -> None:
        if status.get("is_hijacked"):
            raise HeadlessError(
                "HIJACKED_PROGRAM: refusing generic delete for a hijacked file; use "
                "pull_project_program(on_local_changes='discard') to reveal the repository version"
            )
        if not status.get("is_versioned"):
            if not allow_private:
                raise HeadlessError(
                    "PRIVATE_FILE_DELETE_NOT_ALLOWED: target file is not under shared-project "
                    "version control; pass allow_private=true only when deleting a private project file"
                )
            return

        checkouts = status.get("checkouts") or []
        if status.get("is_checked_out") or status.get("checkout_status") or checkouts:
            raise HeadlessError("SHARED_FILE_DELETE_BLOCKED: delete aborted because the file has an active checkout")
        if status.get("can_merge"):
            raise HeadlessError("SHARED_FILE_DELETE_BLOCKED: delete aborted because the file requires merge handling")

    @staticmethod
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
        if status.get("is_hijacked"):
            raise HeadlessError(
                "HIJACKED_PROGRAM: a private local file shadows the repository version; use "
                "pull_project_program(on_local_changes='discard') to recover it"
            )
        if not status.get("is_versioned"):
            if status.get("can_add_to_repository"):
                raise DomainError(
                    code=ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED,
                    message=(
                        "ADD_TO_VERSION_CONTROL_REQUIRED: target program is not under shared-project "
                        "version control; run add_project_program_to_version_control first"
                    ),
                    hint="Run add_project_program_to_version_control before shared-project sync operations",
                    retryable=False,
                    details={
                        "required_action": "add_project_program_to_version_control",
                        "can_add_to_repository": True,
                    },
                )
            raise HeadlessError("NOT_SHARED_PROJECT: target program is not under shared-project version control")
