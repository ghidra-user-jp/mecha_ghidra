"""Close/operate/reopen lifecycle around a loaded program."""

from __future__ import annotations

import logging

from ghidra_headless.errors import HeadlessError
from ghidra_headless.session import ProjectHandle
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class SyncReopenMixin:
    """Mixin for :class:`RuntimeSyncOperations`; expects ``self._store``."""

    _store: RuntimeSessionStore

    def _run_sync_operation_for_domain_locked(
        self,
        name: str,
        domain_path: str,
        operation,
        *,
        save_before_close: bool,
        reopen_domain_path_resolver=None,
    ):
        handle = self._store.get_target_handle(name)
        active_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if active_target is None:
            return operation(handle, domain_path)
        return self._run_with_reopened_program_locked(
            active_target,
            operation=operation,
            save_before_close=save_before_close,
            reopen_domain_path_resolver=reopen_domain_path_resolver,
            preserve_none_operation_completion=True,
            remove_target_lock_on_cleanup=active_target == name,
        )

    def _run_with_reopened_program_locked(
        self,
        name: str,
        operation,
        *,
        save_before_close: bool,
        reopen_domain_path_resolver=None,
        preserve_none_operation_completion: bool = False,
        remove_target_lock_on_cleanup: bool = True,
        reopen_version: int | None = None,
    ):
        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        project_key = handle.get_key()
        domain_path = self._store.session_domain_path(session)
        program = session.get_program()
        active_handle: ProjectHandle | None = None
        reopened_session_bound = False

        def _save_hook() -> None:
            handle.project.save(program)

        def _before_close() -> None:
            session.close(save=False)
            if handle.is_closed():
                with self._store.registry_lock.write_lock():
                    handle_key = handle.get_key()
                    if self._store.project_handles.get(handle_key) is handle:
                        self._store.project_handles.pop(handle_key, None)

        def _do_operation():
            nonlocal active_handle
            active_handle = self._store.get_or_create_project_handle(project_key)
            return operation(active_handle, domain_path)

        def _reopen() -> None:
            nonlocal reopened_session_bound
            nonlocal active_handle
            if active_handle is None:
                active_handle = self._store.get_or_create_project_handle(project_key)
            reopen_domain_path = domain_path
            if reopen_domain_path_resolver is not None:
                reopen_domain_path = reopen_domain_path_resolver(active_handle, domain_path)
            if reopen_version is None:
                reopened = active_handle.open_program(reopen_domain_path)
            else:
                reopened = active_handle.open_program(reopen_domain_path, version=reopen_version)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=name)
                with self._store.registry_lock.write_lock():
                    self._store.sessions[name] = reopened
                reopened_session_bound = True
            except Exception as init_error:
                try:
                    reopened.close()
                except Exception as close_exc:
                    with self._store.registry_lock.write_lock():
                        self._store.sessions[name] = reopened
                    reopened_session_bound = True
                    raise HeadlessError(
                        "PROGRAM_CLOSE_FAILED: failed to close reopened session during "
                        f"sync rollback for target '{name}': {close_exc}; "
                        f"original error: {init_error}"
                    ) from init_error
                raise
            finally:
                if active_handle is not None and active_handle.is_closed():
                    with self._store.registry_lock.write_lock():
                        active_key = active_handle.get_key()
                        if self._store.project_handles.get(active_key) is active_handle:
                            self._store.project_handles.pop(active_key, None)

        lease = ProgramLease(
            before_close=_before_close,
            do_operation=_do_operation,
            reopen=_reopen,
        )
        try:
            result = lease.run(save=save_before_close, save_hook=_save_hook)
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(name, domain_path)
            return result
        except DomainError as exc:
            if exc.code == ErrorCode.SAVE_FAILED:
                raise HeadlessError(f"SAVE_FAILED: {exc.message}") from exc

            if exc.code == ErrorCode.REOPEN_FAILED:
                if not reopened_session_bound:
                    self._cleanup_reopenable_target_state_locked(
                        name,
                        handle=handle,
                        remove_target_lock=remove_target_lock_on_cleanup,
                    )
                details = exc.details or {}
                operation_error = details.get("operation_error")
                if operation_error and details.get("partial_success"):
                    # The operation itself already reported a completed remote
                    # side effect.  Preserve the structured non-retryable error
                    # even though reopening failed as well.
                    raise
                if operation_error:
                    raise HeadlessError(
                        f"SYNC_OPERATION_FAILED: {operation_error}; REOPEN_FAILED: {exc.message}"
                    ) from exc
                if "operation_result" in details or (
                    preserve_none_operation_completion and details.get("operation_completed")
                ):
                    raise
                raise HeadlessError(f"REOPEN_FAILED: {exc.message}") from exc

            # Preserve structured non-retryable/partial-success errors raised by an
            # operation or its postcondition verification.
            raise
        except Exception:
            if not reopened_session_bound and self._session_is_closed(session):
                self._cleanup_reopenable_target_state_locked(
                    name,
                    handle=handle,
                    remove_target_lock=remove_target_lock_on_cleanup,
                )
            raise

    def _cleanup_reopenable_target_state_locked(
        self,
        name: str,
        *,
        handle: ProjectHandle | None = None,
        remove_target_lock: bool = True,
    ) -> None:
        with self._store.registry_lock.write_lock():
            self._store.sessions.pop(name, None)
            if remove_target_lock:
                self._store.locks.pop(name, None)
            self._store.target_projects.pop(name, None)
            if handle is not None and handle.is_closed():
                handle_key = handle.get_key()
                if self._store.project_handles.get(handle_key) is handle:
                    self._store.project_handles.pop(handle_key, None)
            self._store.clear_analyzed_loads_for_target(name)
            self._store.clear_dirty_programs_for_target(name)
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
    def _session_lookup_error_is_closed(exc: Exception) -> bool:
        return "Session is already closed" in str(exc)
