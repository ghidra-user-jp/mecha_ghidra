"""Sync state of the program currently loaded in a target."""

from __future__ import annotations

import logging
from typing import Any, Dict

from ghidra_headless.errors import HeadlessError, error_code_of
from ghidra_headless.session import ProjectHandle

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class SyncActiveProgramMixin:
    """Mixin for :class:`RuntimeSyncOperations`; expects ``self._store``."""

    _store: RuntimeSessionStore

    def _current_sync_status_locked(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
        return handle.get_sync_status(resolved_domain_path)

    def _get_refreshed_sync_status_locked(
        self,
        handle: ProjectHandle,
        domain_path: str,
        *,
        require_refresh: bool = False,
    ) -> Dict[str, Any]:
        self._refresh_project_sync_state_locked(handle, required=require_refresh)
        return handle.get_sync_status(domain_path)

    def _overlay_active_program_sync_status_locked(
        self,
        active_target: str | None,
        domain_path: str,
        *,
        status: Dict[str, Any],
    ) -> Dict[str, Any]:
        if active_target is None:
            return status
        if not status.get("is_versioned"):
            return status
        if not status.get("is_checked_out"):
            return status
        if not self._active_program_is_changed_locked(active_target, domain_path):
            return status

        updated = dict(status)
        updated["modified_since_checkout"] = True
        if not updated.get("can_merge") and not updated.get("is_hijacked"):
            updated["can_checkin"] = True
        return updated

    def _active_program_is_changed_locked(self, name: str, domain_path: str) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        with self._store.registry_lock.read_lock():
            runtime_dirty = self._store.is_dirty_program(name, domain_path)
            session = self._store.sessions.get(name)
        if runtime_dirty:
            return True
        if session is None:
            return False
        program = session.get_program()
        try:
            return bool(program.isChanged())
        except Exception as exc:
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                name,
                exc,
            )
            return True

    def _active_program_version_locked(self, name: str | None, domain_path: str) -> int | None:
        if name is None or not self._is_active_domain_path_locked(name, domain_path):
            return None
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            return None
        try:
            domain_file = session.get_program().getDomainFile()
            get_version = getattr(domain_file, "getVersion", None)
            if get_version is None:
                return None
            value = int(get_version())
            return value if value > 0 else None
        except Exception as exc:
            logger.debug("failed to inspect loaded program version for '%s': %s", name, exc)
            return None

    def _refresh_active_versioned_program_state_locked(
        self,
        name: str,
        domain_path: str,
        *,
        status: Dict[str, Any] | None = None,
        save_before_close: bool,
        force: bool = False,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        effective_status = status or self._current_sync_status_locked(name, domain_path=domain_path)
        if not effective_status.get("is_versioned"):
            return False
        if not effective_status.get("is_checked_out"):
            return False
        if not force and not self._active_program_is_changed_locked(name, domain_path):
            return False
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=save_before_close,
        )
        return True

    def _reload_active_program_after_checkout_locked(
        self,
        name: str,
        domain_path: str,
        *,
        remove_target_lock_on_cleanup: bool = True,
    ) -> None:
        if not self._is_active_domain_path_locked(name, domain_path):
            return
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
            remove_target_lock_on_cleanup=remove_target_lock_on_cleanup,
        )

    def _reload_loaded_target_after_checkout_locked(self, *, handle: ProjectHandle, domain_path: str) -> None:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return
        if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
            return
        self._reload_active_program_after_checkout_locked(
            loaded_target,
            domain_path,
            remove_target_lock_on_cleanup=False,
        )

    def _reload_after_completed_checkout_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        operation: str,
    ) -> None:
        """Reload locally after a repository checkout that already succeeded."""
        try:
            self._reload_loaded_target_after_checkout_locked(
                handle=handle,
                domain_path=domain_path,
            )
        except Exception as exc:
            raise self._partial_success_error(
                operation=operation,
                message=(f"repository checkout completed, but the loaded program could not be reopened: {exc}"),
            ) from exc

    @staticmethod
    def _refresh_project_sync_state_locked(handle: ProjectHandle, *, required: bool = False) -> bool:
        try:
            handle.refresh_project_data(force=True)
        except Exception as exc:
            logger.debug("failed to refresh project sync state: %s", exc)
            if required:
                raise HeadlessError(f"SYNC_REFRESH_FAILED: failed to refresh project sync state: {exc}") from exc
            return False
        return True

    def _refresh_loaded_target_sync_state_locked(self, *, handle: ProjectHandle, domain_path: str) -> bool:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return False
        if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
            return False
        if self._active_program_is_changed_locked(loaded_target, domain_path):
            raise HeadlessError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
        self._run_with_reopened_program_locked(
            loaded_target,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
            remove_target_lock_on_cleanup=False,
        )
        return True

    def _save_active_program_if_needed_locked(
        self,
        name: str,
        domain_path: str,
        *,
        handle: ProjectHandle | None = None,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            return False
        if not self._active_program_is_changed_locked(name, domain_path):
            return False
        program = session.get_program()

        active_handle = handle or session.get_project_handle()
        try:
            active_handle.project.save(program)
        except Exception as exc:
            raise HeadlessError(f"SAVE_FAILED: failed to save program: {exc}") from exc
        with self._store.registry_lock.write_lock():
            self._store.clear_dirty_program(name, domain_path)
        return True

    def _rollback_auto_checkout_locked(
        self,
        name: str,
        *,
        domain_path: str,
    ) -> Dict[str, Any]:
        self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                active_domain_path,
                keep=False,
            ),
            save_before_close=False,
        )
        updated = self._read_postcondition_sync_status_locked(
            name,
            domain_path=domain_path,
            operation="commit_project_program.rollback_auto_checkout",
        )
        if updated.get("is_checked_out"):
            raise self._partial_success_error(
                operation="commit_project_program.rollback_auto_checkout",
                message="automatic checkout rollback returned but the program is still checked out",
            )
        return updated

    @staticmethod
    def _discard_conflict_checkout_operation(handle: ProjectHandle, domain_path: str) -> Dict[str, bool]:
        status = handle.get_sync_status(domain_path)
        discarded_local_changes = bool(status.get("modified_since_checkout"))
        if status.get("is_checked_out"):
            handle.undo_checkout_program(domain_path, keep=False)
        return {
            "discarded_local_changes": discarded_local_changes,
            "merged": False,
        }

    def _discard_hijacked_file_operation(self, handle: ProjectHandle, domain_path: str) -> None:
        status = handle.get_sync_status(domain_path)
        if not status.get("is_hijacked"):
            raise HeadlessError("HIJACK_STATE_CHANGED: local file is no longer hijacked; no file was deleted")
        try:
            handle.delete_domain_file(domain_path)
        except Exception as exc:
            if error_code_of(exc) == "DELETE_POSTCONDITION_FAILED":
                raise self._partial_success_error(
                    operation="pull_project_program.discard_hijack",
                    message=str(exc),
                ) from exc
            raise

    def _pull_operation(
        self,
        handle: ProjectHandle,
        domain_path: str,
        *,
        on_local_changes: str,
    ) -> Dict[str, bool]:
        status = handle.get_sync_status(domain_path)
        pending_merge_before_discard = bool(status.get("can_merge"))
        discarded_local_changes = False
        if status.get("modified_since_checkout"):
            if on_local_changes == "abort":
                raise HeadlessError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")
            handle.undo_checkout_program(domain_path, keep=False)
            discarded_local_changes = True
            status = self._read_handle_status_after_side_effect(
                handle,
                domain_path=domain_path,
                operation="pull_project_program.discard_local_changes",
            )
            if status.get("is_checked_out"):
                raise self._partial_success_error(
                    operation="pull_project_program.discard_local_changes",
                    message="undo checkout returned but the program is still checked out",
                )
            if status.get("can_merge"):
                raise self._partial_success_error(
                    operation="pull_project_program.discard_local_changes",
                    message="undo checkout returned but the program still reports a pending merge",
                )

        merged = False
        # undoCheckout(false) drops the stale checkout as well as its local
        # changes.  If the checkout already needed a merge, reopening now follows
        # the server's latest version even though canMerge becomes false afterward.
        followed_latest = discarded_local_changes and pending_merge_before_discard
        if status.get("can_merge"):
            if not status.get("is_checked_out"):
                raise HeadlessError(
                    "UNSAFE_MERGE_REQUIRED: remote changes require a Ghidra merge, "
                    "but automatic merge is disabled because PropertyList merges can crash. "
                    "Reopen the program from the latest version or re-checkout before retrying."
                )

            # Avoid DomainFile.merge() here. In Ghidra 12.0.4 the PropertyList merge path can
            # throw a NullPointerException when comment/property state diverges. Dropping a stale
            # checkout and reopening is safer when we only need to follow the latest server state.
            handle.undo_checkout_program(domain_path, keep=False)
            status = self._read_handle_status_after_side_effect(
                handle,
                domain_path=domain_path,
                operation="pull_project_program.follow_latest",
            )
            if status.get("is_checked_out") or status.get("can_merge"):
                raise self._partial_success_error(
                    operation="pull_project_program.follow_latest",
                    message=("checkout drop returned but the checkout or pending merge state is still active"),
                )
            followed_latest = True
        return {
            "discarded_local_changes": discarded_local_changes,
            "merged": merged,
            "followed_latest": followed_latest,
        }
