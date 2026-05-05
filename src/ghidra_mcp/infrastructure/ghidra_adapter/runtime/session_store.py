"""Shared runtime state access helpers."""

from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_headless.session import ProgramSession, ProjectHandle


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
        self.registry_lock = state.registry_lock

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

    def get_or_create_project_handle(self, project_location: str, project_name: Optional[str]) -> ProjectHandle:
        key = ProjectHandle.make_key(project_location, project_name)
        handle = self.project_handles.get(key)
        if handle is None or handle.is_closed():
            handle = ProjectHandle(project_location, project_name)
            self.project_handles[key] = handle
        return handle

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

    def get_target_handle_locked(self, name: str) -> ProjectHandle:
        session = self.sessions.get(name)
        if session is not None:
            handle = session.get_project_handle()
            self.target_projects[name] = handle.get_key()
            return handle
        key = self.get_target_project_key_locked(name)
        return self.get_or_create_project_handle(key[0], key[1])

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
        if session is not None:
            try:
                session_domain_path = self.session_domain_path(session)
            except Exception:
                session_domain_path = None
        if remove_registry_entry:
            self.sessions.pop(name, None)
            self.locks.pop(name, None)

        close_error = None
        try:
            if session is not None:
                session.close(save=save, remove_program=remove_program)
        except Exception as exc:  # noqa: BLE001
            close_error = exc

        if remove_context:
            self.core_accessor().remove_context(name)

        session_closed = False
        if session is not None:
            try:
                session_closed = session.get_project_handle() is None
            except Exception:
                session_closed = True

        if handle is not None and handle.is_closed():
            self.project_handles.pop(handle.get_key(), None)
        if session_domain_path is not None and (close_error is None or session_closed):
            self.clear_dirty_program(name, session_domain_path)

        if close_error is not None:
            message = str(close_error)
            if (
                message.startswith("SAVE_FAILED:")
                or message.startswith("PROGRAM_CLOSE_FAILED:")
                or message.startswith("SESSION_CLOSE_FAILED:")
                or message.startswith("REMOVE_PROGRAM_FAILED:")
            ):
                raise RuntimeError(message) from close_error
            raise RuntimeError(f"SESSION_CLOSE_FAILED: {close_error}")

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

    def clear_dirty_program(self, name: str, domain_path: str) -> None:
        self.dirty_programs.discard((name, domain_path))

    def clear_dirty_programs_for_target(self, name: str) -> None:
        if not self.dirty_programs:
            return
        remove_keys = [key for key in self.dirty_programs if key[0] == name]
        for key in remove_keys:
            self.dirty_programs.discard(key)

    def clear_dirty_programs(self) -> None:
        self.dirty_programs.clear()

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


__all__ = ["RuntimeSessionStore"]
