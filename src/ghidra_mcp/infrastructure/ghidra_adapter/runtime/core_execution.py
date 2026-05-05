"""Core command execution delegate for runtime backend."""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Dict

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class RuntimeCoreExecution:
    def __init__(
        self,
        *,
        store: RuntimeSessionStore,
        checkout_required_commands: set[str],
        normalize_result,
    ) -> None:
        self._store = store
        self._checkout_required_commands = set(checkout_required_commands)
        self._normalize_result = normalize_result

    def call(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        with self._store.registry_lock.write_lock():
            session = self._store.ensure_session(target)
            lock = self._store.ensure_lock(target)
            project_key = self._store.target_projects.get(target)
            if project_key is None:
                get_key = getattr(session.get_project_handle(), "get_key", None)
                if get_key is not None:
                    project_key = get_key()
                    self._store.target_projects[target] = project_key
            project_lock = self._store.ensure_project_lock(project_key) if project_key is not None else None

        with lock:
            lock_context = project_lock if project_lock is not None else contextlib.nullcontext()
            with lock_context:
                self._ensure_checkout_for_mutating_command_locked(command, target)
                result = self._store.core_accessor().execute(command, params or {}, key=target)
                if command in self._checkout_required_commands:
                    session = self._store.sessions.get(target)
                    if session is not None:
                        self._store.mark_dirty_program(target, self._store.session_domain_path(session))
                return self._normalize_result(result)

    def _ensure_checkout_for_mutating_command_locked(self, command: str, target: str) -> None:
        if command not in self._checkout_required_commands:
            return
        session = self._store.sessions.get(target)
        if session is None:
            return
        handle = session.get_project_handle()
        domain_path = self._store.session_domain_path(session)
        self._refresh_project_sync_state_locked(handle, required=True)
        status = handle.get_sync_status(domain_path)
        if not status.get("is_versioned"):
            if self._refresh_active_program_sync_state_locked(target, domain_path, status=status):
                session = self._store.sessions.get(target)
                if session is None:
                    return
                handle = session.get_project_handle()
                status = handle.get_sync_status(domain_path)
            if status.get("is_versioned"):
                if status.get("is_checked_out"):
                    return
                raise RuntimeError(
                    "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects. "
                    "Run checkout_project_program first"
                )
            return
        if status.get("is_checked_out"):
            return
        raise RuntimeError(
            "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects. "
            "Run checkout_project_program first"
        )

    def _refresh_active_program_sync_state_locked(
        self,
        target: str,
        domain_path: str,
        *,
        status: Dict[str, Any],
    ) -> bool:
        if status.get("is_versioned"):
            return False
        if not status.get("can_add_to_repository"):
            return False
        session = self._store.sessions.get(target)
        if session is None:
            return False
        if self._store.is_dirty_program(target, domain_path):
            return False
        if self._active_program_is_changed_locked(target, domain_path):
            raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")

        handle = session.get_project_handle()
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
        active_handle = None
        reopened_session_bound = False
        try:
            session.close(save=False)
            if self._handle_is_closed(handle):
                self._store.project_handles.pop(handle.get_key(), None)
            if not self._handle_is_closed(handle):
                active_handle = handle
            else:
                active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            reopened = active_handle.open_program(domain_path)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=target)
                self._store.sessions[target] = reopened
                reopened_session_bound = True
            except Exception as init_error:  # noqa: BLE001
                try:
                    reopened.close(save=False)
                except Exception as close_exc:  # noqa: BLE001
                    self._store.sessions[target] = reopened
                    reopened_session_bound = True
                    raise RuntimeError(
                        "PROGRAM_CLOSE_FAILED: failed to close reopened session during "
                        f"checkout guard rollback for target '{target}': {close_exc}; "
                        f"original error: {init_error}"
                    ) from init_error
                raise
            finally:
                if active_handle is not None and self._handle_is_closed(active_handle):
                    self._store.project_handles.pop(active_handle.get_key(), None)
            self._store.clear_dirty_program(target, domain_path)
            return True
        except Exception:
            if not reopened_session_bound and self._session_is_closed(session):
                self._cleanup_reopenable_target_state_locked(target, handle=handle)
            raise

    def _active_program_is_changed_locked(self, target: str, domain_path: str) -> bool:
        if self._store.is_dirty_program(target, domain_path):
            return True
        session = self._store.sessions.get(target)
        if session is None:
            return False
        try:
            return bool(session.get_program().isChanged())
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                target,
                exc,
            )
            return True

    def _cleanup_reopenable_target_state_locked(self, target: str, *, handle=None) -> None:  # noqa: ANN001
        self._store.sessions.pop(target, None)
        self._store.locks.pop(target, None)
        self._store.target_projects.pop(target, None)
        self._store.clear_analyzed_loads_for_target(target)
        self._store.clear_dirty_programs_for_target(target)
        if handle is not None and self._handle_is_closed(handle):
            self._store.project_handles.pop(handle.get_key(), None)
        try:
            self._store.core_accessor().remove_context(target)
        except Exception as remove_exc:  # noqa: BLE001
            logger.warning("failed to remove context while cleaning target '%s': %s", target, remove_exc)

    @staticmethod
    def _handle_is_closed(handle) -> bool:  # noqa: ANN001
        try:
            return bool(handle.is_closed())
        except Exception:
            return False

    @staticmethod
    def _session_is_closed(session) -> bool:  # noqa: ANN001
        try:
            session.get_project_handle()
            return False
        except Exception:
            return True

    @staticmethod
    def _refresh_project_sync_state_locked(handle, *, required: bool = False) -> bool:  # noqa: ANN001
        refresh_project_data = getattr(handle, "refresh_project_data", None)
        if refresh_project_data is None:
            return False
        try:
            refresh_project_data(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to refresh project sync state before checkout guard: %s", exc)
            if required:
                raise RuntimeError(f"SYNC_OPERATION_FAILED: failed to refresh project sync state: {exc}") from exc
            return False
        return True


__all__ = ["RuntimeCoreExecution"]
