"""Shared project sync operations for runtime backend."""

from __future__ import annotations

import logging
import pathlib
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
                status = handle.get_sync_status(resolved_domain_path)
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
                status = handle.get_sync_status(resolved_domain_path)
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
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        text = (message or "").strip()
        if not text:
            raise ValueError("message is required")
        with self._store.registry_lock.write_lock():
            lock = self._store.ensure_lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)

                status = handle.get_sync_status(resolved_domain_path)
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
                if status.get("can_merge"):
                    action = self._run_sync_operation_for_domain_locked(
                        name,
                        resolved_domain_path,
                        operation=lambda active_handle, active_domain_path: self._discard_conflict_checkout_operation(
                            active_handle,
                            active_domain_path,
                        ),
                        save_before_close=False,
                    )
                    updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                    return {
                        "status": "noop",
                        "reason": "conflict_discarded",
                        "target": name,
                        "program": resolved_domain_path,
                        "discarded_local_changes": bool(action["discarded_local_changes"]),
                        "merged": bool(action["merged"]),
                        "version": updated.get("version"),
                        "latest_version": updated.get("latest_version"),
                        "is_latest_version": bool(updated.get("is_latest_version")),
                        "checked_out": bool(updated.get("is_checked_out")),
                    }
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
                status = handle.get_sync_status(resolved_domain_path)
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
                status = handle.get_sync_status(resolved_domain_path)
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
                keep_path_resolver = None
                if keep and was_active and (
                    bool(status.get("modified_since_checkout"))
                    or self._active_program_is_changed_locked(active_target, resolved_domain_path)
                ):
                    # Ghidra only creates a .keep file when there are local changes to preserve.
                    existing_program_paths = self._list_program_paths_locked(handle)
                    keep_path_resolver = lambda active_handle, active_domain_path: self._resolve_new_keep_domain_path(
                        active_handle,
                        active_domain_path,
                        existing_program_paths,
                    )
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
                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                active_checkout_status = status.get("checkout_status") or {}
                active_checkout_id = active_checkout_status.get("checkout_id")
                loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                is_loaded_checkout_in_use = (
                    loaded_target is not None
                    and active_checkout_id is not None
                    and int(active_checkout_id) == int(checkout_id)
                )
                if is_loaded_checkout_in_use:
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
        except Exception:
            return False

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
            path for path in current_paths if path.startswith(keep_prefix) and path not in existing_program_paths
        )
        if new_keep_paths:
            return new_keep_paths[-1]
        raise RuntimeError(f"KEEP_FILE_NOT_FOUND: no new keep file was created for {domain_path}")

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
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
        if not status.get("is_versioned"):
            raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")


__all__ = ["RuntimeSyncOperations"]
