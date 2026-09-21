"""Shared runtime state access helpers."""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import Any, Callable

from ghidra_headless.errors import HeadlessError, error_code_of
from ghidra_headless.session import ProgramSession, ProjectHandle
from ghidra_mcp.application.services.runtime_state import RuntimeState

logger = logging.getLogger(__name__)

# Close failures with these codes keep their own code; anything else is reported
# as a generic SESSION_CLOSE_FAILED.
_SURFACED_CLOSE_CODES = frozenset(
    {"SAVE_FAILED", "PROGRAM_CLOSE_FAILED", "SESSION_CLOSE_FAILED", "REMOVE_PROGRAM_FAILED"}
)


def _java_project_of(session: ProgramSession):
    """Best-effort ``ghidra.framework.model.Project`` for a session (None if unavailable)."""
    try:
        return session.get_project_handle().get_java_project()
    except Exception as exc:
        logger.debug("java project unavailable for session: %s", exc)
        return None


def bind_session_project(core_accessor, key: str, session: ProgramSession) -> None:
    """Give the context for ``key`` its Java project when the accessor supports it (scripts need it)."""
    bind = getattr(core_accessor(), "bind_project", None)
    if bind is None:
        return
    project = _java_project_of(session)
    if project is None:
        return
    try:
        bind(key, project)
    except Exception as exc:
        logger.debug("bind_project failed for target '%s': %s", key, exc)


class RuntimeSessionStore:
    def __init__(
        self,
        *,
        state: RuntimeState,
        core_accessor: Callable[[], Any],
    ) -> None:
        self.core_accessor = core_accessor
        self.sessions = state.sessions
        self.locks = state.locks
        self.project_locks = state.project_locks
        self.target_projects = state.target_projects
        self.project_handles = state.project_handles
        self.analyzed_loads = state.analyzed_loads
        self.dirty_programs = state.dirty_programs
        self.pending_sync_programs = state.pending_sync_programs
        self.invalid_targets = state.invalid_targets
        self.orphaned_sessions = state.orphaned_sessions
        self.orphan_handles = state.orphan_handles
        self.operation_lock = state.operation_lock
        self.registry_lock = state.registry_lock

    # ---- quarantine (execution_state=invalid) ---------------------------------

    def quarantine_state(self, name: str) -> dict[str, Any] | None:
        """Return the quarantine payload for ``name`` from either layer, or None."""
        payload = self.invalid_targets.get(name)
        if payload is not None:
            return payload
        accessor = self.core_accessor()
        execution_state = getattr(accessor, "execution_state", None)
        if execution_state is None:
            return None
        try:
            payload = execution_state(name)
        except Exception as exc:
            logger.debug("execution_state lookup failed for target '%s': %s", name, exc)
            return None
        return None if payload is None else dict(payload)

    def quarantine_target(self, name: str, payload: dict[str, Any]) -> None:
        with self.registry_lock.write_lock():
            self.invalid_targets[name] = dict(payload)

    def clear_quarantine(self, name: str) -> None:
        with self.registry_lock.write_lock():
            self.invalid_targets.pop(name, None)

    def ensure_not_quarantined(self, name: str, *, operation: str) -> None:
        """Refuse an operation that would persist or reopen a quarantined target's state."""
        payload = self.quarantine_state(name)
        if payload is None:
            return
        raise HeadlessError(
            f"TARGET_EXECUTION_INVALID: target '{name}' is quarantined ({payload.get('reason')}); "
            f"{operation} is refused. Use close_session with discard_changes=true, then reload the program",
            details=dict(payload),
        )

    # ---- orphaned program consumers ------------------------------------------

    def record_orphan(self, name: str, session: Any, *, stage: str, error: BaseException) -> None:
        """Keep ownership of a session whose close failed; it is retried by ``release_orphans``."""
        with self.registry_lock.write_lock():
            self.orphaned_sessions.setdefault(name, []).append(
                {"session": session, "stage": stage, "error": str(error), "code": error_code_of(error)}
            )
        logger.error("target '%s': program consumer could not be released at %s: %s", name, stage, error)

    def orphans_for(self, name: str) -> list[dict[str, Any]]:
        with self.registry_lock.read_lock():
            return [{k: v for k, v in item.items() if k != "session"} for item in self.orphaned_sessions.get(name, [])]

    def release_orphans(self, name: str) -> list[dict[str, Any]]:
        """Retry every orphaned close for ``name``; return the ones still unreleased."""
        with self.registry_lock.read_lock():
            items = list(self.orphaned_sessions.get(name, []))
        remaining: list[dict[str, Any]] = []
        for item in items:
            session = item["session"]
            try:
                session.get_project_handle()
            except Exception:
                continue  # already closed
            try:
                session.close(save=False)
            except Exception as exc:
                remaining.append({**item, "error": str(exc), "code": error_code_of(exc)})
        with self.registry_lock.write_lock():
            if remaining:
                self.orphaned_sessions[name] = remaining
            else:
                self.orphaned_sessions.pop(name, None)
        result = [{k: v for k, v in item.items() if k != "session"} for item in remaining]
        # Programs a ProjectHandle could not release during a failed open belong to the same recovery.
        for handle in self._handles_for_target(name):
            release = getattr(handle, "release_orphaned_programs", None)
            if release is None:
                continue
            try:
                leftover = int(release())
            except Exception as exc:
                leftover = -1
                result.append({"stage": "handle_release", "error": str(exc), "code": error_code_of(exc)})
            if leftover > 0:
                result.append(
                    {
                        "stage": "handle_orphaned_program",
                        "error": f"{leftover} program(s) still unreleased",
                        "code": None,
                    }
                )
        if not result:
            with self.registry_lock.write_lock():
                self.orphan_handles.pop(name, None)
        return result

    def _handles_for_target(self, name: str) -> list[ProjectHandle]:
        with self.registry_lock.read_lock():
            key = self.target_projects.get(name)
            session = self.sessions.get(name)
        handles: list[ProjectHandle] = []
        if session is not None:
            with contextlib.suppress(Exception):
                handles.append(session.get_project_handle())
        if key is not None:
            with self.registry_lock.read_lock():
                handle = self.project_handles.get(key)
            if handle is not None and all(handle is not known for known in handles):
                handles.append(handle)
        with self.registry_lock.read_lock():
            remembered = list(self.orphan_handles.get(name, []))
        for handle in remembered:
            if all(handle is not known for known in handles):
                handles.append(handle)
        return handles

    def note_open_failure(self, name: str, exc: BaseException, *, handle: Any = None) -> bool:
        """Quarantine ``name`` when an open failed while leaving a program consumer unreleased.

        The owning handle is remembered explicitly so recovery can reach it even
        after the target's project binding was rolled back.  Returns True when
        the target was quarantined.
        """
        details = getattr(exc, "details", None) or {}
        if "orphaned_program" not in details:
            return False
        with self.registry_lock.write_lock():
            if handle is not None:
                known = self.orphan_handles.setdefault(name, [])
                if all(handle is not existing for existing in known):
                    known.append(handle)
        self.quarantine_target(
            name,
            {"reason": "orphaned_program", "domain_path": details["orphaned_program"], "error": str(exc)},
        )
        return True

    def ensure_session(self, name: str) -> ProgramSession:
        try:
            return self.sessions[name]
        except KeyError:
            if name in self.target_projects:
                raise RuntimeError(
                    f"Session '{name}' is not initialized (program not loaded). "
                    "Open a program with load_project_program"
                )
            raise RuntimeError(f"Session '{name}' is not initialized")

    def ensure_lock(self, name: str):
        try:
            return self.locks[name]
        except KeyError:
            raise RuntimeError(f"Session '{name}' is not initialized")

    def ensure_project_lock(self, key: tuple[str, str]) -> threading.RLock:
        lock = self.project_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            self.project_locks[key] = lock
        return lock

    def get_or_create_project_handle(
        self,
        key: tuple[str, str],
    ) -> ProjectHandle:
        """Open a project without holding the global registry lock."""

        with self.registry_lock.read_lock():
            observed = self.project_handles.get(key)
        if observed is not None and not observed.is_closed():
            return observed

        candidate = ProjectHandle(key[0], key[1])
        while True:
            with self.registry_lock.write_lock():
                current = self.project_handles.get(key)
                if current is None or current is observed:
                    self.project_handles[key] = candidate
                    return candidate
            if not current.is_closed():
                break
            observed = current
        try:
            candidate.close()
        except Exception as exc:
            logger.warning(
                "failed to close duplicate project handle for %s::%s: %s",
                key[0],
                key[1],
                exc,
            )
        return current

    def get_target_handle(self, name: str) -> ProjectHandle:
        """Resolve a target handle while keeping project-open I/O lock-free."""

        with self.registry_lock.write_lock():
            session = self.sessions.get(name)
            if session is not None:
                handle = session.get_project_handle()
                self.target_projects[name] = handle.get_key()
                return handle
            key = self.get_target_project_key_locked(name)
        return self.get_or_create_project_handle(key)

    def get_target_project_key_locked(self, name: str) -> tuple[str, str]:
        session = self.sessions.get(name)
        if session is not None:
            key = session.get_project_handle().get_key()
            self.target_projects[name] = key
            return key
        try:
            return self.target_projects[name]
        except KeyError:
            raise RuntimeError(f"Target '{name}' is not initialized")

    def cleanup_session(
        self,
        name: str,
        session: ProgramSession | None,
        handle: ProjectHandle | None,
        *,
        remove_registry_entry: bool,
        remove_context: bool = True,
        remove_program: bool = False,
        save: bool = True,
    ) -> None:
        session_domain_path = None
        owns_target_state = not remove_registry_entry
        if session is not None:
            try:
                session_domain_path = self.session_domain_path(session)
            except Exception:
                session_domain_path = None
        if remove_registry_entry:
            with self.registry_lock.write_lock():
                owns_target_state = session is None or self.sessions.get(name) is session
                if owns_target_state:
                    self.sessions.pop(name, None)
                    self.locks.pop(name, None)

        close_error = None
        try:
            if session is not None:
                session.close(save=save, remove_program=remove_program)
        except Exception as exc:
            close_error = exc

        # A detached/stale session may finish closing after another session has
        # already been installed for the same target.  Its cleanup must not
        # remove the replacement session's context.
        with self.registry_lock.read_lock():
            current_session = self.sessions.get(name)
        can_clear_dirty = owns_target_state and (current_session is None or current_session is session)
        can_remove_context = owns_target_state and (not remove_registry_entry or can_clear_dirty)
        if remove_context and can_remove_context:
            self.core_accessor().remove_context(name)

        session_closed = False
        if session is not None:
            try:
                session_closed = session.get_project_handle() is None
            except Exception:
                session_closed = True

        handle_closed = handle is not None and handle.is_closed()
        with self.registry_lock.write_lock():
            if handle is not None and handle_closed:
                handle_key = handle.get_key()
                if self.project_handles.get(handle_key) is handle:
                    self.project_handles.pop(handle_key, None)
            current_session = self.sessions.get(name)
            can_clear_dirty = owns_target_state and (current_session is None or current_session is session)
            if can_clear_dirty and session_domain_path is not None and (close_error is None or session_closed):
                self.clear_dirty_program(name, session_domain_path)

        if close_error is not None:
            if error_code_of(close_error) in _SURFACED_CLOSE_CODES:
                raise HeadlessError(str(close_error)) from close_error
            raise HeadlessError(f"SESSION_CLOSE_FAILED: {close_error}")

    def has_sessions(self) -> bool:
        with self.registry_lock.read_lock():
            return bool(self.sessions)

    def has_targets(self) -> bool:
        with self.registry_lock.read_lock():
            return bool(self.target_projects)

    def project_lock_key(self, name: str) -> str | None:
        with self.registry_lock.read_lock():
            key = self.target_projects.get(name)
            if key is None:
                session = self.sessions.get(name)
                if session is not None:
                    key = session.get_project_handle().get_key()
            if key is None:
                return None
            return f"{key[0]}::{key[1]}"

    def is_analyzed_load(self, name: str, domain_path: str) -> bool:
        return (name, domain_path) in self.analyzed_loads

    def mark_analyzed_load(self, name: str, domain_path: str) -> None:
        self.analyzed_loads.add((name, domain_path))

    def clear_analyzed_loads_for_target(self, name: str) -> None:
        if not self.analyzed_loads:
            return
        remove_keys = [key for key in self.analyzed_loads if key[0] == name]
        for key in remove_keys:
            self.analyzed_loads.discard(key)

    def clear_analyzed_loads(self) -> None:
        self.analyzed_loads.clear()

    def is_dirty_program(self, name: str, domain_path: str) -> bool:
        return (name, domain_path) in self.dirty_programs

    def mark_dirty_program(self, name: str, domain_path: str) -> None:
        self.dirty_programs.add((name, domain_path))

    def mark_pending_sync_program(self, name: str, domain_path: str) -> None:
        self.mark_dirty_program(name, domain_path)
        self.pending_sync_programs.add((name, domain_path))

    def update_unsaved_program(self, name: str, domain_path: str, *, changed: bool) -> None:
        if changed:
            self.mark_dirty_program(name, domain_path)
        elif (name, domain_path) not in self.pending_sync_programs:
            self.clear_dirty_program(name, domain_path)

    def clear_dirty_program(self, name: str, domain_path: str) -> None:
        self.dirty_programs.discard((name, domain_path))
        self.pending_sync_programs.discard((name, domain_path))

    def clear_dirty_programs_for_target(self, name: str) -> None:
        if not self.dirty_programs:
            return
        remove_keys = [key for key in self.dirty_programs if key[0] == name]
        for key in remove_keys:
            self.clear_dirty_program(*key)

    def clear_dirty_programs(self) -> None:
        self.dirty_programs.clear()
        self.pending_sync_programs.clear()

    @staticmethod
    def session_domain_path(session: ProgramSession) -> str:
        program = session.get_program()
        domain_file = program.getDomainFile()
        if domain_file is None:
            raise RuntimeError("Current program has no DomainFile")
        path = domain_file.getPathname()
        if not path:
            raise RuntimeError("failed to resolve domain path for current program")
        return path
