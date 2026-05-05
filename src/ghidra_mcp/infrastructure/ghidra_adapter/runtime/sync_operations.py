"""Shared project sync operations for runtime backend."""

from __future__ import annotations

import logging
import pathlib
from collections.abc import Callable
from typing import Any, Dict

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease
from ghidra_headless.session import ProjectHandle, path_utils

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class RuntimeSyncOperations:
    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path)
                status = self._overlay_active_program_sync_status_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                )
                return {"target": name, "program": resolved_domain_path, **status}

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                if active_target is not None and not status.get("is_versioned"):
                    self._refresh_loaded_target_sync_state_locked(
                        handle=handle,
                        domain_path=resolved_domain_path,
                    )
                    handle = self._store.get_target_handle_locked(name)
                    active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                    status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                if status.get("is_checked_out"):
                    if active_target is not None and not self._active_program_is_changed_locked(
                        active_target,
                        resolved_domain_path,
                    ):
                        self._reload_loaded_target_after_checkout_locked(
                            handle=handle,
                            domain_path=resolved_domain_path,
                        )
                    return {
                        "status": "ok",
                        "target": name,
                        "program": resolved_domain_path,
                        "checked_out": True,
                        "already_checked_out": True,
                        "exclusive": bool(status.get("is_checked_out_exclusive")),
                    }
                if active_target is not None and self._active_program_is_changed_locked(active_target, resolved_domain_path):
                    raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
                checked_out = handle.checkout_program(resolved_domain_path, exclusive=exclusive)
                if checked_out:
                    self._store.clear_dirty_program(name, resolved_domain_path)
                    self._reload_loaded_target_after_checkout_locked(handle=handle, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "checked_out": bool(checked_out),
                    "already_checked_out": False,
                    "exclusive": bool(exclusive),
                }

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        text = (comment or "").strip()
        if not text:
            raise ValueError("comment is required")
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                if status.get("is_versioned"):
                    return {
                        "status": "noop",
                        "reason": "already_versioned",
                        "target": name,
                        "program": resolved_domain_path,
                        "version": status.get("version"),
                    }
                if not status.get("can_add_to_repository"):
                    raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed")

                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=lambda active_handle, active_domain_path: active_handle.add_program_to_version_control(
                        active_domain_path,
                        text,
                        keep_checked_out=keep_checked_out,
                    ),
                    save_before_close=True,
                )
                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "is_versioned": bool(updated.get("is_versioned")),
                    "version": updated.get("version"),
                    "latest_version": updated.get("latest_version"),
                    "checked_out": bool(updated.get("is_checked_out")),
                    "effective_keep_checked_out": bool(updated.get("is_checked_out")),
                }

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        text = (message or "").strip()
        if not text:
            raise ValueError("message is required")
        conflict_action = (on_conflict or "abort").strip().lower()
        if conflict_action not in {"abort", "discard"}:
            raise ValueError("on_conflict must be either 'abort' or 'discard'")
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)

                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                if active_target is not None and not status.get("is_versioned"):
                    self._refresh_loaded_target_sync_state_locked(
                        handle=handle,
                        domain_path=resolved_domain_path,
                    )
                    handle = self._store.get_target_handle_locked(name)
                    active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                    status = handle.get_sync_status(resolved_domain_path)
                if not status.get("is_versioned") and status.get("can_add_to_repository"):
                    return {
                        "status": "noop",
                        "reason": "not_versioned",
                        "target": name,
                        "program": resolved_domain_path,
                        "required_action": "add_project_program_to_version_control",
                        "can_add_to_repository": True,
                        "message": (
                            "Program is not under version control; "
                            "run add_project_program_to_version_control before commit_project_program."
                        ),
                    }
                self._ensure_versioned_project(status)
                status = self._overlay_active_program_sync_status_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                )
                if not status.get("is_checked_out"):
                    if auto_checkout and status.get("can_checkout"):
                        if active_target is not None and self._active_program_is_changed_locked(
                            active_target,
                            resolved_domain_path,
                        ):
                            raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
                        checked_out = handle.checkout_program(resolved_domain_path, exclusive=False)
                        if checked_out:
                            self._reload_loaded_target_after_checkout_locked(
                                handle=handle,
                                domain_path=resolved_domain_path,
                            )
                            handle = self._store.get_target_handle_locked(name)
                        status = handle.get_sync_status(resolved_domain_path)
                        status = self._overlay_active_program_sync_status_locked(
                            active_target,
                            resolved_domain_path,
                            status=status,
                        )
                        if not status.get("is_checked_out"):
                            if not checked_out:
                                raise RuntimeError("AUTO_CHECKOUT_FAILED: checkout failed")
                            raise RuntimeError("AUTO_CHECKOUT_FAILED: post-checkout state verification failed")
                    else:
                        raise RuntimeError("NOT_CHECKED_OUT: program is not checked out")

                conflict_result = self._handle_commit_conflict_locked(
                    name,
                    resolved_domain_path,
                    active_target=active_target,
                    status=status,
                    conflict_action=conflict_action,
                )
                if conflict_result is not None:
                    return conflict_result

                saved_active_program = False
                if active_target is not None:
                    saved_active_program = self._save_active_program_if_needed_locked(
                        active_target,
                        resolved_domain_path,
                        handle=handle,
                    )
                    if self._refresh_active_versioned_program_state_locked(
                        active_target,
                        resolved_domain_path,
                        status=status,
                        save_before_close=False,
                        force=saved_active_program,
                    ):
                        handle = self._store.get_target_handle_locked(name)
                status = handle.get_sync_status(resolved_domain_path)
                status = self._overlay_active_program_sync_status_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                )
                conflict_result = self._handle_commit_conflict_locked(
                    name,
                    resolved_domain_path,
                    active_target=active_target,
                    status=status,
                    conflict_action=conflict_action,
                )
                if conflict_result is not None:
                    return conflict_result
                if not status.get("can_checkin"):
                    if not status.get("modified_since_checkout"):
                        return {
                            "status": "noop",
                            "reason": "not_modified",
                            "target": name,
                            "program": resolved_domain_path,
                            "checked_out": bool(status.get("is_checked_out")),
                            "version": status.get("version"),
                        }
                    raise RuntimeError("CHECKIN_NOT_ALLOWED: checkin is not allowed")

                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=lambda active_handle, active_domain_path: active_handle.commit_program(
                        active_domain_path,
                        text,
                        keep_checked_out=keep_checked_out,
                    ),
                    save_before_close=True,
                )
                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "new_version": updated.get("version"),
                    "checked_out": bool(updated.get("is_checked_out")),
                    "effective_keep_checked_out": bool(updated.get("is_checked_out")),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        normalized = (on_local_changes or "abort").strip().lower()
        if normalized not in {"abort", "discard"}:
            raise ValueError("on_local_changes must be either 'abort' or 'discard'")
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                self._ensure_versioned_project(status)
                status = self._overlay_active_program_sync_status_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                )

                if status.get("modified_since_checkout") and normalized == "abort":
                    raise RuntimeError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")

                needs_operation = bool(status.get("modified_since_checkout")) or bool(status.get("can_merge"))
                discarded_unsaved_active_changes = (
                    normalized == "discard"
                    and active_target is not None
                    and self._active_program_is_changed_locked(active_target, resolved_domain_path)
                )
                action = {
                    "discarded_local_changes": False,
                    "merged": False,
                    "followed_latest": False,
                }
                if needs_operation:
                    action = self._run_sync_operation_for_domain_locked(
                        name,
                        resolved_domain_path,
                        operation=lambda active_handle, active_domain_path: self._pull_operation(
                            active_handle,
                            active_domain_path,
                            on_local_changes=normalized,
                        ),
                        save_before_close=False,
                    )
                    if discarded_unsaved_active_changes:
                        action["discarded_local_changes"] = True

                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "updated": bool(
                        action["merged"] or action["discarded_local_changes"] or action["followed_latest"]
                    ),
                    "merged": bool(action["merged"]),
                    "discarded_local_changes": bool(action["discarded_local_changes"]),
                    "followed_latest": bool(action["followed_latest"]),
                    "version": updated.get("version"),
                    "latest_version": updated.get("latest_version"),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                self._ensure_versioned_project(status)
                status = self._overlay_active_program_sync_status_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                )
                if not status.get("is_checked_out"):
                    return {
                        "status": "noop",
                        "reason": "not_checked_out",
                        "target": name,
                        "program": resolved_domain_path,
                    }

                keep = not bool(discard_local_changes)
                was_active = active_target is not None
                keep_path_resolver: Callable[[ProjectHandle, str], str] | None = None
                if keep and was_active and (
                    bool(status.get("modified_since_checkout"))
                    or self._active_program_is_changed_locked(active_target, resolved_domain_path)
                ):
                    # Ghidra only creates a .keep file when there are local changes to preserve.
                    existing_program_paths = self._list_program_paths_locked(handle)

                    def resolve_keep_path(active_handle, active_domain_path):  # noqa: ANN001
                        return self._resolve_new_keep_domain_path(
                            active_handle,
                            active_domain_path,
                            existing_program_paths,
                        )

                    keep_path_resolver = resolve_keep_path

                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                        active_domain_path,
                        keep=keep,
                    ),
                    save_before_close=keep,
                    reopen_domain_path_resolver=keep_path_resolver,
                )
                self._store.clear_dirty_program(name, resolved_domain_path)
                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                result = {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "checked_out": bool(updated.get("is_checked_out")),
                    "version": updated.get("version"),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }
                if keep and was_active:
                    session = self._store.sessions.get(active_target)
                    if session is not None:
                        active_domain_path = self._store.session_domain_path(session)
                        if active_domain_path != resolved_domain_path:
                            result["kept_program"] = active_domain_path
                return result

    def terminate_project_program_checkout(
        self,
        name: str,
        checkout_id: int,
        *,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
                self._ensure_versioned_project(status)
                active_checkout_status = status.get("checkout_status") or {}
                active_checkout_id = active_checkout_status.get("checkout_id")
                is_local_checkout = active_checkout_id is not None and int(active_checkout_id) == int(checkout_id)
                if is_local_checkout:
                    raise RuntimeError(
                        "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: terminating the active checkout would hijack the local file; "
                        "use undo_checkout_project_program instead"
                    )
                handle.terminate_checkout_program(resolved_domain_path, checkout_id)
                updated = handle.get_sync_status(resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "checkout_id": int(checkout_id),
                    "active_checkouts": updated.get("checkouts"),
                }

    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
    ) -> Dict[str, Any]:
        if not (domain_path or "").strip():
            raise ValueError("domain_path is required")
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle = self._store.get_target_handle_locked(name)
                resolved_domain_path = self._normalize_domain_path_locked(handle, domain_path)
                confirmation = (confirm or "").strip()
                if confirmation != resolved_domain_path:
                    raise ValueError(
                        "confirm must exactly match the normalized domain_path "
                        f"({resolved_domain_path})"
                    )

                active_target = self._find_loaded_target_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                )
                if active_target is not None:
                    details = {
                        "operation": "delete_shared_project_file",
                        "target": name,
                        "domain_path": resolved_domain_path,
                    }
                    if active_target != name:
                        details["owner_target"] = active_target
                    raise DomainError(
                        code=ErrorCode.TARGET_ALREADY_LOADED,
                        message=f"TARGET_ALREADY_LOADED: program already loaded: {resolved_domain_path}",
                        hint="Close the loaded target before deleting the shared project file",
                        retryable=False,
                        details=details,
                    )

                status = self._get_refreshed_sync_status_locked(
                    handle,
                    resolved_domain_path,
                    require_refresh=True,
                )
                was_versioned = bool(status.get("is_versioned"))
                latest_version = status.get("latest_version")
                version = status.get("version")
                if expected_latest_version is not None:
                    expected = int(expected_latest_version)
                    if expected < 1:
                        raise ValueError("expected_latest_version must be >= 1")
                    if latest_version is None or int(latest_version) != expected:
                        raise RuntimeError(
                            "LATEST_VERSION_MISMATCH: delete aborted because latest_version "
                            f"is {latest_version}, expected {expected}"
                        )

                self._ensure_delete_allowed(status, allow_private=allow_private)
                delete_result = handle.delete_domain_file(resolved_domain_path)
                self._store.clear_dirty_program(name, resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "domain_path": resolved_domain_path,
                    "deleted": True,
                    "content_type": delete_result.get("content_type"),
                    "was_versioned": was_versioned,
                    "version": version,
                    "latest_version": latest_version,
                }

    def reload_project_program(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                if self._is_active_domain_path_locked(name, resolved_domain_path):
                    save_before_close = self._active_program_is_changed_locked(name, resolved_domain_path)
                    self._run_with_reopened_program_locked(
                        name,
                        operation=lambda _active_handle, _active_domain_path: None,
                        save_before_close=save_before_close,
                    )
                else:
                    owner_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                    if owner_target is not None:
                        details = {
                            "operation": "reload_project_program",
                            "target": name,
                            "domain_path": resolved_domain_path,
                        }
                        if owner_target != name:
                            details["owner_target"] = owner_target
                        raise DomainError(
                            code=ErrorCode.TARGET_ALREADY_LOADED,
                            message=f"TARGET_ALREADY_LOADED: program already loaded: {resolved_domain_path}",
                            hint="Use the existing target directly instead of reloading the same program",
                            retryable=False,
                            details=details,
                        )
                    temporary_session = handle.open_program(resolved_domain_path)
                    temporary_session.close()
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "reloaded": True,
                }

    def get_version_history(
        self,
        name: str,
        *,
        domain_path: str | None = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                self._ensure_versioned_project(self._get_refreshed_sync_status_locked(handle, resolved_domain_path))
                history = handle.get_version_history(resolved_domain_path, limit=limit)
                return {
                    "target": name,
                    "program": resolved_domain_path,
                    **history,
                }

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        domain_path: str | None = None,
        range_limit: int = 200,
    ) -> Dict[str, Any]:
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                self._ensure_versioned_project(self._get_refreshed_sync_status_locked(handle, resolved_domain_path))
                diff = handle.get_version_diff(
                    resolved_domain_path,
                    from_version=from_version,
                    to_version=to_version,
                    range_limit=range_limit,
                )
                return {
                    "target": name,
                    "program": resolved_domain_path,
                    **diff,
                }

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
        if self._store.is_dirty_program(name, domain_path):
            return True
        session = self._store.sessions.get(name)
        if session is None:
            return False
        program = session.get_program()
        try:
            return bool(program.isChanged())
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                name,
                exc,
            )
            return True

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

    def _reload_active_program_after_checkout_locked(self, name: str, domain_path: str) -> None:
        if not self._is_active_domain_path_locked(name, domain_path):
            return
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
        )

    def _reload_loaded_target_after_checkout_locked(self, *, handle: ProjectHandle, domain_path: str) -> None:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return
        lock = self._store.ensure_lock(loaded_target)
        with lock:
            if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
                return
            self._reload_active_program_after_checkout_locked(loaded_target, domain_path)

    @staticmethod
    def _refresh_project_sync_state_locked(handle: ProjectHandle, *, required: bool = False) -> bool:
        refresh_project_data = getattr(handle, "refresh_project_data", None)
        if refresh_project_data is None:
            return False
        try:
            refresh_project_data(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to refresh project sync state: %s", exc)
            if required:
                raise RuntimeError(f"SYNC_REFRESH_FAILED: failed to refresh project sync state: {exc}") from exc
            return False
        return True

    def _refresh_loaded_target_sync_state_locked(self, *, handle: ProjectHandle, domain_path: str) -> bool:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return False
        lock = self._store.ensure_lock(loaded_target)
        with lock:
            if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
                return False
            if self._active_program_is_changed_locked(loaded_target, domain_path):
                raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
            self._run_with_reopened_program_locked(
                loaded_target,
                operation=lambda _active_handle, _active_domain_path: None,
                save_before_close=False,
            )
            return True

    def _handle_commit_conflict_locked(
        self,
        name: str,
        domain_path: str,
        *,
        active_target: str | None,
        status: Dict[str, Any],
        conflict_action: str,
    ) -> Dict[str, Any] | None:
        if not status.get("can_merge"):
            return None
        if conflict_action == "abort":
            raise RuntimeError(
                "UNSAFE_MERGE_REQUIRED: remote changes require a merge before check-in; "
                "pass on_conflict='discard' to drop this checkout and follow the latest server state"
            )
        discarded_unsaved_active_changes = (
            active_target is not None
            and self._active_program_is_changed_locked(active_target, domain_path)
        )
        action = self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=lambda active_handle, active_domain_path: self._discard_conflict_checkout_operation(
                active_handle,
                active_domain_path,
            ),
            save_before_close=False,
        )
        if discarded_unsaved_active_changes:
            action["discarded_local_changes"] = True
        updated = self._current_sync_status_locked(name, domain_path=domain_path)
        return {
            "status": "noop",
            "reason": "conflict_discarded",
            "target": name,
            "program": domain_path,
            "discarded_local_changes": bool(action["discarded_local_changes"]),
            "merged": bool(action["merged"]),
            "version": updated.get("version"),
            "latest_version": updated.get("latest_version"),
            "is_latest_version": bool(updated.get("is_latest_version")),
            "checked_out": bool(updated.get("is_checked_out")),
        }

    def _resolve_sync_target_locked(
        self,
        name: str,
        domain_path: str | None,
    ) -> tuple[ProjectHandle, str]:
        resolved_domain_path = (domain_path or "").strip()
        if resolved_domain_path:
            handle = self._store.get_target_handle_locked(name)
            return handle, self._normalize_domain_path_locked(handle, resolved_domain_path)

        session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        return handle, self._store.session_domain_path(session)

    @staticmethod
    def _normalize_domain_path_locked(handle: ProjectHandle, domain_path: str | None) -> str:
        domain_dir, domain_name = path_utils._parse_domain_path(handle.project, domain_path)
        normalized_path = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        return normalized_path

    def _is_active_domain_path_locked(self, name: str, domain_path: str) -> bool:
        session = self._store.sessions.get(name)
        if session is None:
            return False
        return self._store.session_domain_path(session) == domain_path

    def _find_loaded_target_locked(self, *, handle: ProjectHandle, domain_path: str) -> str | None:
        requested_key = handle.get_key()
        for target_name, session in self._store.sessions.items():
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception:
                continue
            if session_handle.get_key() != requested_key:
                continue
            if session_domain_path == domain_path:
                return target_name
        return None

    def _save_active_program_if_needed_locked(
        self,
        name: str,
        domain_path: str,
        *,
        handle: ProjectHandle | None = None,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
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
            raise RuntimeError(f"SAVE_FAILED: failed to save program: {exc}") from exc
        self._store.clear_dirty_program(name, domain_path)
        return True

    @staticmethod
    def _list_program_paths_locked(handle: ProjectHandle) -> set[str]:
        return {
            str(item.get("domain_path"))
            for item in handle.list_programs()
            if str(item.get("domain_path") or "")
        }

    @staticmethod
    def _resolve_new_keep_domain_path(
        handle: ProjectHandle,
        domain_path: str,
        existing_program_paths: set[str],
    ) -> str:
        keep_prefix = f"{domain_path}.keep"
        current_paths = {
            str(item.get("domain_path"))
            for item in handle.list_programs()
            if str(item.get("domain_path") or "")
        }
        new_keep_paths = sorted(
            (path for path in current_paths if path.startswith(keep_prefix) and path not in existing_program_paths),
            key=lambda path: RuntimeSyncOperations._keep_path_sort_key(path, keep_prefix),
        )
        if new_keep_paths:
            return new_keep_paths[-1]
        raise RuntimeError(f"KEEP_FILE_NOT_FOUND: no new keep file was created for {domain_path}")

    @staticmethod
    def _keep_path_sort_key(path: str, keep_prefix: str) -> tuple[int, int, str]:
        suffix = path[len(keep_prefix) :]
        if suffix == "":
            return (1, 0, path)
        if suffix.startswith(".") and suffix[1:].isdigit():
            return (1, int(suffix[1:]), path)
        return (0, 0, path)

    def _run_sync_operation_for_domain_locked(
        self,
        name: str,
        domain_path: str,
        operation,
        *,
        save_before_close: bool,
        reopen_domain_path_resolver=None,
    ):
        handle = self._store.get_target_handle_locked(name)
        active_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if active_target is None:
            return operation(handle, domain_path)
        lock = self._store.ensure_lock(active_target)
        with lock:
            return self._run_with_reopened_program_locked(
                active_target,
                operation=operation,
                save_before_close=save_before_close,
                reopen_domain_path_resolver=reopen_domain_path_resolver,
            )

    def _run_with_reopened_program_locked(
        self,
        name: str,
        operation,
        *,
        save_before_close: bool,
        reopen_domain_path_resolver=None,
    ):
        session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
        domain_path = self._store.session_domain_path(session)
        program = session.get_program()
        active_handle: ProjectHandle | None = None
        reopened_session_bound = False

        def _save_hook() -> None:
            handle.project.save(program)

        def _before_close() -> None:
            session.close(save=False)
            if handle.is_closed():
                self._store.project_handles.pop(handle.get_key(), None)

        def _do_operation():
            nonlocal active_handle
            active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            return operation(active_handle, domain_path)

        def _reopen() -> None:
            nonlocal reopened_session_bound
            nonlocal active_handle
            if active_handle is None:
                active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            reopen_domain_path = domain_path
            if reopen_domain_path_resolver is not None:
                reopen_domain_path = reopen_domain_path_resolver(active_handle, domain_path)
            reopened = active_handle.open_program(reopen_domain_path)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=name)
                self._store.sessions[name] = reopened
                reopened_session_bound = True
            except Exception:
                try:
                    reopened.close()
                except Exception as close_exc:
                    logger.warning("failed to close reopened session during rollback for target '%s': %s", name, close_exc)
                raise
            finally:
                if active_handle is not None and active_handle.is_closed():
                    self._store.project_handles.pop(active_handle.get_key(), None)

        lease = ProgramLease(
            before_close=_before_close,
            do_operation=_do_operation,
            reopen=_reopen,
        )
        try:
            result = lease.run(save=save_before_close, save_hook=_save_hook)
            self._store.clear_dirty_program(name, domain_path)
            return result
        except DomainError as exc:
            if exc.code == ErrorCode.SAVE_FAILED:
                raise RuntimeError(f"SAVE_FAILED: {exc.message}") from exc

            if exc.code == ErrorCode.REOPEN_FAILED:
                self._cleanup_reopenable_target_state_locked(name, handle=handle)
                operation_error = (exc.details or {}).get("operation_error")
                if operation_error:
                    raise RuntimeError(
                        f"SYNC_OPERATION_FAILED: {operation_error}; REOPEN_FAILED: {exc.message}"
                    ) from exc
                raise RuntimeError(f"REOPEN_FAILED: {exc.message}") from exc

            raise RuntimeError(str(exc)) from exc
        except Exception:
            if not reopened_session_bound and self._session_is_closed(session):
                self._cleanup_reopenable_target_state_locked(name, handle=handle)
            raise

    def _cleanup_reopenable_target_state_locked(self, name: str, *, handle: ProjectHandle | None = None) -> None:
        self._store.sessions.pop(name, None)
        self._store.locks.pop(name, None)
        self._store.target_projects.pop(name, None)
        self._store.clear_analyzed_loads_for_target(name)
        self._store.clear_dirty_programs_for_target(name)
        if handle is not None and handle.is_closed():
            self._store.project_handles.pop(handle.get_key(), None)
        try:
            self._store.core_accessor().remove_context(name)
        except Exception as remove_exc:
            logger.warning("failed to remove context while cleaning target '%s': %s", name, remove_exc)

    @staticmethod
    def _session_is_closed(session) -> bool:
        try:
            session.get_project_handle()
            return False
        except Exception:
            return True

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

    @staticmethod
    def _pull_operation(handle: ProjectHandle, domain_path: str, *, on_local_changes: str) -> Dict[str, bool]:
        status = handle.get_sync_status(domain_path)
        discarded_local_changes = False
        if status.get("modified_since_checkout"):
            if on_local_changes == "abort":
                raise RuntimeError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")
            handle.undo_checkout_program(domain_path, keep=False)
            discarded_local_changes = True
            status = handle.get_sync_status(domain_path)

        merged = False
        followed_latest = False
        if status.get("can_merge"):
            if not status.get("is_checked_out"):
                raise RuntimeError(
                    "UNSAFE_MERGE_REQUIRED: remote changes require a Ghidra merge, "
                    "but automatic merge is disabled because PropertyList merges can crash. "
                    "Reopen the program from the latest version or re-checkout before retrying."
                )

            # Avoid DomainFile.merge() here. In Ghidra 12.0.4 the PropertyList merge path can
            # throw a NullPointerException when comment/property state diverges. Dropping a stale
            # checkout and reopening is safer when we only need to follow the latest server state.
            handle.undo_checkout_program(domain_path, keep=False)
            status = handle.get_sync_status(domain_path)
            if status.get("can_merge"):
                raise RuntimeError(
                    "FOLLOW_LATEST_FAILED: checkout was dropped, but the program still reports a pending merge"
                )
            followed_latest = True
        return {
            "discarded_local_changes": discarded_local_changes,
            "merged": merged,
            "followed_latest": followed_latest,
        }

    @staticmethod
    def _ensure_delete_allowed(status: Dict[str, Any], *, allow_private: bool) -> None:
        if not status.get("is_versioned"):
            if not allow_private:
                raise RuntimeError(
                    "PRIVATE_FILE_DELETE_NOT_ALLOWED: target file is not under shared-project "
                    "version control; pass allow_private=true only when deleting a private project file"
                )
            return

        checkouts = status.get("checkouts") or []
        if status.get("is_checked_out") or status.get("checkout_status") or checkouts:
            raise RuntimeError(
                "SHARED_FILE_DELETE_BLOCKED: delete aborted because the file has an active checkout"
            )
        if status.get("can_merge"):
            raise RuntimeError(
                "SHARED_FILE_DELETE_BLOCKED: delete aborted because the file requires merge handling"
            )

    @staticmethod
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
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
            raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")


__all__ = ["RuntimeSyncOperations"]
