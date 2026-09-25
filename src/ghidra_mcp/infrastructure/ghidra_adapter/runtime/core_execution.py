"""Core command execution delegate for runtime backend."""

from __future__ import annotations

import logging
from typing import Any, Dict

from ghidra_headless.errors import HeadlessError
from ghidra_mcp.application.locks import SCRIPT_BARRIER, USE_SCRIPT_QUEUE_TIMEOUT, acquire_ordered_locks
from ghidra_mcp.application.services.ports import OperationControl
from ghidra_mcp.domain import DomainError

from .errors import to_domain_error
from .session_store import RuntimeSessionStore, bind_session_project, format_project_key

logger = logging.getLogger(__name__)

# Job commands that run their own checks before changing the program and mark
# that moment themselves (begin_command), so a refusal there leaves nothing.
_BEGINS_ITSELF = frozenset({"run_script"})
# A failed write's output_state, from how the core says its transactions ended
# (ghidra_headless.session.transactions); anything else is uncertain.
_OUTPUT_STATES = {"unchanged": "absent", "rolled_back": "absent", "committed": "created"}


class _Progress:
    """Whether a write got past the checks and ran."""

    ran = False


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
        *,
        exclusive: bool = False,
        control: OperationControl | None = None,
    ) -> Any:
        if control is not None or command not in self._checkout_required_commands:
            return self._call(command, params, target, exclusive=exclusive, control=control)
        # A write run as a tool call says what its failure left behind, as a
        # job's record does: nothing before it ran, else what its transactions did.
        progress = _Progress()
        try:
            return self._call(command, params, target, exclusive=exclusive, progress=progress)
        except Exception as exc:
            raise self._with_output_state(exc, command, target, ran=progress.ran) from exc

    def _with_output_state(self, exc: Exception, command: str, target: str, *, ran: bool) -> DomainError:
        state = _OUTPUT_STATES.get(self._transaction_outcome(), "uncertain") if ran else "absent"
        error = to_domain_error(exc, operation=command, target=target)
        return DomainError(
            code=error.code,
            message=error.message,
            hint=error.hint,
            # A transient cause is only worth retrying when nothing was written.
            retryable=error.retryable and state == "absent",
            details={**(error.details or {}), "output_state": state},
        )

    def _transaction_outcome(self) -> str | None:
        """How the last command on this thread ended its transactions, if the core can say."""
        try:
            return self._store.core_accessor().transaction_outcome()
        except Exception:
            return None

    def _call(
        self,
        command: str,
        params: Dict[str, Any] | None,
        target: str,
        *,
        exclusive: bool = False,
        control: OperationControl | None = None,
        progress: _Progress | None = None,
    ) -> Any:
        # ``exclusive`` takes the runtime-wide barrier as a writer: script
        # execution mutates process-global state (sys.modules, OSGi bundles,
        # the Jython runtime) that per-target locks do not cover.  The writer
        # waits on the script queue budget, not the general lock timeout: a
        # requested script run should outwait a running analysis, not fail.
        process_barrier = (
            SCRIPT_BARRIER.write_lock(timeout=USE_SCRIPT_QUEUE_TIMEOUT) if exclusive else SCRIPT_BARRIER.read_lock()
        )
        runtime_barrier = (
            self._store.operation_lock.write_lock() if exclusive else self._store.operation_lock.read_lock()
        )
        with process_barrier, runtime_barrier:
            with self._store.registry_lock.write_lock():
                if control is not None and target not in self._store.sessions:
                    raise self._session_changed(target)
                session = self._store.ensure_session(target)
                lock = self._store.ensure_lock(target)
                project_key = self._store.target_projects.get(target)
                if project_key is None:
                    project_key = session.get_project_handle().get_key()
                    self._store.target_projects[target] = project_key
                project_lock = self._store.ensure_project_lock(project_key) if project_key is not None else None

            locks = [("target", lock)]
            if project_lock is not None:
                locks.append(("project", project_lock))
            with acquire_ordered_locks(locks, message_prefix="runtime "):
                if control is not None:
                    control.check_active()
                with self._store.registry_lock.write_lock():
                    current_session = self._store.sessions.get(target)
                    if current_session is None:
                        if control is not None:
                            raise self._session_changed(target)
                        raise self._store.missing_session_error(target)
                    if current_session is not session:
                        raise HeadlessError(
                            f"SESSION_CHANGED: target '{target}' session changed before core command execution"
                        )
                    current_project_key = self._store.target_projects.get(target)
                    if (
                        project_key is not None
                        and current_project_key is not None
                        and current_project_key != project_key
                    ):
                        raise HeadlessError(
                            f"SESSION_CHANGED: target '{target}' project changed before core command execution"
                        )
                    if control is not None and (
                        current_project_key is None
                        or format_project_key(current_project_key) != control.expected_project_key
                        or (
                            control.expected_generation is not None
                            and self._store.session_generation(current_session) != control.expected_generation
                        )
                    ):
                        # Reloaded, reopened or switched while the job waited:
                        # never run a job on a program the client did not ask for.
                        raise self._session_changed(target)
                self._ensure_target_not_quarantined_locked(command, target)
                self._ensure_checkout_for_mutating_command_locked(command, target)
                if progress is not None:
                    progress.ran = True
                try:
                    result = self._execute_locked(command, params or {}, target, control)
                finally:
                    if command == "run_script":
                        self._refresh_domain_path_locked(target)
                if control is None:
                    return self._finish_command_locked(command, target, result)
                try:
                    return self._finish_command_locked(command, target, result)
                except Exception as exc:
                    # The command's transaction has committed: the job did change the program.
                    error = to_domain_error(exc, operation=command, target=target)
                    error.details = {**(error.details or {}), "output_created": True}
                    raise error from exc

    def analyze_program(self, name: str, *, force: bool = False, control: OperationControl) -> Any:
        """Run the analyze_program command for a background job."""
        return self.call("analyze_program", {"force": True} if force else {}, name, control=control)

    @staticmethod
    def _session_changed(target: str) -> HeadlessError:
        return HeadlessError(
            f"SESSION_CHANGED: target '{target}' was reloaded, closed or switched to another program "
            "after the job was accepted; the job did not run"
        )

    def _execute_locked(
        self, command: str, params: Dict[str, Any], target: str, control: OperationControl | None
    ) -> Any:
        if control is None:
            return self._store.core_accessor().execute(command, params, key=target)
        # The checkout guard may have reopened the session: use the current one.
        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(target)
        # Cancellation reaches the command through this monitor; the command
        # then aborts its transaction, which rolls the half-done work back.
        monitor = session.get_project_handle().create_cancellable_monitor()
        control.bind_cancel(monitor.cancel)
        try:
            if command in _BEGINS_ITSELF:
                return self._store.core_accessor().execute(
                    command, params, key=target, task_monitor=monitor, on_begin=control.begin
                )
            control.begin()
            return self._store.core_accessor().execute(command, params, key=target, task_monitor=monitor)
        finally:
            control.bind_cancel(None)

    def _refresh_domain_path_locked(self, target: str) -> None:
        # A script may rename or move the program's file, and a rollback does
        # not undo that; list_targets reports the path captured here.
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(target)
        if session is not None:
            session.refresh_domain_path()

    def _finish_command_locked(self, command: str, target: str, result: Any) -> Any:
        if command in self._checkout_required_commands:
            with self._store.registry_lock.read_lock():
                session = self._store.sessions.get(target)
            if session is not None:
                domain_path = self._store.session_domain_path(session)
                try:
                    changed = bool(session.get_program().isChanged())
                except Exception as exc:
                    logger.warning("failed to read dirty state after %s on target '%s': %s", command, target, exc)
                    changed = True
                with self._store.registry_lock.write_lock():
                    if self._store.sessions.get(target) is session:
                        # Previews, no-ops and undo can leave a saved program
                        # unchanged; do not force saves or block sync for them.
                        self._store.update_unsaved_program(target, domain_path, changed=changed)
        return self._normalize_result(result)

    def _ensure_target_not_quarantined_locked(self, command: str, target: str) -> None:
        """Refuse mutating commands on a target a script run left unverifiable."""
        if command not in self._checkout_required_commands:
            return
        payload = self._store.quarantine_state(target)
        if payload is None:
            return
        raise HeadlessError(
            f"TARGET_EXECUTION_INVALID: target '{target}' is quarantined ({payload.get('reason')}); "
            "close_session(discard_changes=true) then reload the program",
            details=dict(payload),
        )

    def _ensure_checkout_for_mutating_command_locked(self, command: str, target: str) -> None:
        if command not in self._checkout_required_commands:
            return
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(target)
        if session is None:
            return
        read_only_version = getattr(session, "read_only_version", None)
        if read_only_version is not None:
            raise HeadlessError(
                f"READ_ONLY_PROGRAM: target '{target}' holds version {int(read_only_version)} opened read-only; "
                "load the current version with load_project_program before mutating"
            )
        handle = session.get_project_handle()
        domain_path = self._store.session_domain_path(session)
        self._refresh_project_sync_state_locked(handle, required=True)
        status = handle.get_sync_status(domain_path)
        if status.get("is_hijacked"):
            raise HeadlessError(
                "HIJACKED_PROGRAM: mutating operations are blocked because a private local file "
                "shadows the repository version; recover it with "
                "pull_project_program(on_local_changes='discard')"
            )
        if not status.get("is_versioned"):
            if self._refresh_active_program_sync_state_locked(target, domain_path, status=status):
                with self._store.registry_lock.read_lock():
                    session = self._store.sessions.get(target)
                if session is None:
                    return
                handle = session.get_project_handle()
                status = handle.get_sync_status(domain_path)
            if status.get("is_hijacked"):
                raise HeadlessError(
                    "HIJACKED_PROGRAM: mutating operations are blocked because a private local file "
                    "shadows the repository version; recover it with "
                    "pull_project_program(on_local_changes='discard')"
                )
            if status.get("is_versioned"):
                if status.get("is_checked_out"):
                    return
                raise HeadlessError(
                    "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects. "
                    "Run checkout_project_program first"
                )
            return
        if status.get("is_checked_out"):
            return
        raise HeadlessError(
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
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(target)
            runtime_dirty = self._store.is_dirty_program(target, domain_path)
        if session is None:
            return False
        handle = session.get_project_handle()
        is_repository = getattr(handle, "is_repository_project", None)
        if callable(is_repository) and not is_repository():
            # canAddToRepository() also returns true for a private local project.
            # There is no remote version to discover there; reopening would
            # unnecessarily invalidate every revision observed before an edit.
            return False
        if runtime_dirty:
            return False
        if self._active_program_is_changed_locked(target, domain_path):
            raise HeadlessError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")

        handle = session.get_project_handle()
        project_key = handle.get_key()
        active_handle = None
        reopened_session_bound = False
        try:
            session.close(save=False)
            if self._handle_is_closed(handle):
                with self._store.registry_lock.write_lock():
                    if self._store.project_handles.get(handle.get_key()) is handle:
                        self._store.project_handles.pop(handle.get_key(), None)
            if not self._handle_is_closed(handle):
                active_handle = handle
            else:
                active_handle = self._store.get_or_create_project_handle(project_key)
            reopened = active_handle.open_program(domain_path)
            # The same unchanged program, reopened only to see the repository's
            # state: a job accepted before this reopen still asked for it.
            self._store.carry_generation(session, reopened)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=target)
                bind_session_project(self._store.core_accessor, target, reopened)
                with self._store.registry_lock.write_lock():
                    self._store.sessions[target] = reopened
                reopened_session_bound = True
            except Exception as init_error:
                try:
                    reopened.close(save=False)
                except Exception as close_exc:
                    with self._store.registry_lock.write_lock():
                        self._store.sessions[target] = reopened
                    reopened_session_bound = True
                    raise HeadlessError(
                        "PROGRAM_CLOSE_FAILED: failed to close reopened session during "
                        f"checkout guard rollback for target '{target}': {close_exc}; "
                        f"original error: {init_error}"
                    ) from init_error
                raise
            finally:
                if active_handle is not None and self._handle_is_closed(active_handle):
                    with self._store.registry_lock.write_lock():
                        if self._store.project_handles.get(active_handle.get_key()) is active_handle:
                            self._store.project_handles.pop(active_handle.get_key(), None)
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(target, domain_path)
            return True
        except Exception:
            if not reopened_session_bound and self._session_is_closed(session):
                self._cleanup_reopenable_target_state_locked(target, handle=handle)
            raise

    def _active_program_is_changed_locked(self, target: str, domain_path: str) -> bool:
        with self._store.registry_lock.read_lock():
            runtime_dirty = self._store.is_dirty_program(target, domain_path)
            session = self._store.sessions.get(target)
        if runtime_dirty:
            return True
        if session is None:
            return False
        try:
            return bool(session.get_program().isChanged())
        except Exception as exc:
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                target,
                exc,
            )
            return True

    def _cleanup_reopenable_target_state_locked(self, target: str, *, handle=None) -> None:
        with self._store.registry_lock.write_lock():
            self._store.sessions.pop(target, None)
            self._store.locks.pop(target, None)
            self._store.target_projects.pop(target, None)
            if handle is not None and self._handle_is_closed(handle):
                if self._store.project_handles.get(handle.get_key()) is handle:
                    self._store.project_handles.pop(handle.get_key(), None)
            self._store.clear_dirty_programs_for_target(target)
        try:
            self._store.core_accessor().remove_context(target)
        except Exception as remove_exc:
            logger.warning("failed to remove context while cleaning target '%s': %s", target, remove_exc)

    @staticmethod
    def _handle_is_closed(handle) -> bool:
        try:
            return bool(handle.is_closed())
        except Exception:
            return False

    @staticmethod
    def _session_is_closed(session) -> bool:
        try:
            session.get_project_handle()
            return False
        except Exception:
            return True

    @staticmethod
    def _refresh_project_sync_state_locked(handle, *, required: bool = False) -> bool:
        try:
            handle.refresh_project_data(force=True)
        except Exception as exc:
            logger.debug("failed to refresh project sync state before checkout guard: %s", exc)
            if required:
                raise HeadlessError(f"SYNC_OPERATION_FAILED: failed to refresh project sync state: {exc}") from exc
            return False
        return True


__all__ = ["RuntimeCoreExecution"]
