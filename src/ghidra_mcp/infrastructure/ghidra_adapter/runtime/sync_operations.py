"""Shared project sync operations for runtime backend."""

from __future__ import annotations

import logging
from typing import Any, Dict

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease
from ghidra_headless.session import ProjectHandle

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
                status = handle.get_sync_status(resolved_domain_path)
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
                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                if status.get("is_checked_out"):
                    return {
                        "status": "ok",
                        "target": name,
                        "program": resolved_domain_path,
                        "checked_out": True,
                        "already_checked_out": True,
                        "exclusive": bool(status.get("is_checked_out_exclusive")),
                    }
                checked_out = handle.checkout_program(resolved_domain_path, exclusive=exclusive)
                if checked_out:
                    self._reload_active_program_after_checkout_locked(name, resolved_domain_path)
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

                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                if not status.get("is_checked_out"):
                    if auto_checkout and status.get("can_checkout"):
                        checked_out = handle.checkout_program(resolved_domain_path, exclusive=False)
                        if checked_out:
                            self._reload_active_program_after_checkout_locked(name, resolved_domain_path)
                            handle = self._store.get_target_handle_locked(name)
                        status = handle.get_sync_status(resolved_domain_path)
                        if not status.get("is_checked_out"):
                            if not checked_out:
                                raise RuntimeError("AUTO_CHECKOUT_FAILED: checkout failed")
                            raise RuntimeError("AUTO_CHECKOUT_FAILED: post-checkout state verification failed")
                    else:
                        raise RuntimeError("NOT_CHECKED_OUT: program is not checked out")

                self._save_active_program_if_needed_locked(
                    name,
                    resolved_domain_path,
                    handle=handle,
                )
                status = handle.get_sync_status(resolved_domain_path)
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
                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)

                if status.get("modified_since_checkout") and normalized == "abort":
                    raise RuntimeError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")

                needs_operation = bool(status.get("modified_since_checkout")) or bool(status.get("can_merge"))
                action = {
                    "discarded_local_changes": False,
                    "merged": False,
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

                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "updated": bool(action["merged"] or action["discarded_local_changes"]),
                    "merged": bool(action["merged"]),
                    "discarded_local_changes": bool(action["discarded_local_changes"]),
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
                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                if not status.get("is_checked_out"):
                    return {
                        "status": "noop",
                        "reason": "not_checked_out",
                        "target": name,
                        "program": resolved_domain_path,
                    }

                keep = not bool(discard_local_changes)
                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                        active_domain_path,
                        keep=keep,
                    ),
                    save_before_close=False,
                )
                updated = self._current_sync_status_locked(name, domain_path=resolved_domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "checked_out": bool(updated.get("is_checked_out")),
                    "version": updated.get("version"),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }

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
                    self._run_with_reopened_program_locked(
                        name,
                        operation=lambda _active_handle, _active_domain_path: None,
                        save_before_close=True,
                    )
                else:
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

    def _reload_active_program_after_checkout_locked(self, name: str, domain_path: str) -> None:
        if not self._is_active_domain_path_locked(name, domain_path):
            return
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
        )

    def _resolve_sync_target_locked(
        self,
        name: str,
        domain_path: str | None,
    ) -> tuple[ProjectHandle, str]:
        resolved_domain_path = (domain_path or "").strip()
        if resolved_domain_path:
            handle = self._store.get_target_handle_locked(name)
            return handle, resolved_domain_path

        session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        return handle, self._store.session_domain_path(session)

    def _is_active_domain_path_locked(self, name: str, domain_path: str) -> bool:
        session = self._store.sessions.get(name)
        if session is None:
            return False
        return self._store.session_domain_path(session) == domain_path

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
        program = session.get_program()

        active_handle = handle or session.get_project_handle()
        try:
            active_handle.project.save(program)
        except Exception as exc:
            raise RuntimeError(f"SAVE_FAILED: failed to save program: {exc}") from exc
        return True

    def _run_sync_operation_for_domain_locked(
        self,
        name: str,
        domain_path: str,
        operation,
        *,
        save_before_close: bool,
    ):
        if self._is_active_domain_path_locked(name, domain_path):
            return self._run_with_reopened_program_locked(
                name,
                operation=operation,
                save_before_close=save_before_close,
            )
        handle = self._store.get_target_handle_locked(name)
        return operation(handle, domain_path)

    def _run_with_reopened_program_locked(
        self,
        name: str,
        operation,
        *,
        save_before_close: bool,
    ):
        session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
        domain_path = self._store.session_domain_path(session)
        program = session.get_program()
        active_handle: ProjectHandle | None = None

        def _save_hook() -> None:
            handle.project.save(program)

        def _before_close() -> None:
            session.close()
            if handle.is_closed():
                self._store.project_handles.pop(handle.get_key(), None)

        def _do_operation():
            nonlocal active_handle
            active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            return operation(active_handle, domain_path)

        def _reopen() -> None:
            nonlocal active_handle
            if active_handle is None:
                active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            reopened = active_handle.open_program(domain_path)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=name)
                self._store.sessions[name] = reopened
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
            return lease.run(save=save_before_close, save_hook=_save_hook)
        except DomainError as exc:
            if exc.code == ErrorCode.SAVE_FAILED:
                raise RuntimeError(f"SAVE_FAILED: {exc.message}") from exc

            if exc.code == ErrorCode.REOPEN_FAILED:
                self._store.sessions.pop(name, None)
                self._store.locks.pop(name, None)
                try:
                    self._store.core_accessor().remove_context(name)
                except Exception as remove_exc:
                    logger.warning("failed to remove context after reopen failure for target '%s': %s", name, remove_exc)
                operation_error = (exc.details or {}).get("operation_error")
                if operation_error:
                    raise RuntimeError(
                        f"SYNC_OPERATION_FAILED: {operation_error}; REOPEN_FAILED: {exc.message}"
                    ) from exc
                raise RuntimeError(f"REOPEN_FAILED: {exc.message}") from exc

            raise RuntimeError(str(exc)) from exc

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
        if status.get("can_merge"):
            handle.merge_program(domain_path, ok_to_upgrade=True)
            merged = True
        return {
            "discarded_local_changes": discarded_local_changes,
            "merged": merged,
        }

    @staticmethod
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
        if not status.get("is_versioned"):
            raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")


__all__ = ["RuntimeSyncOperations"]
