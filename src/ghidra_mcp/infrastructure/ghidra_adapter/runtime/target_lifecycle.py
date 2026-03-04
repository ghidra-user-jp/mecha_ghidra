"""Target/session lifecycle operations for runtime backend."""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional

from ghidra_headless.session import ProgramSession, ProjectHandle, java_bindings

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class RuntimeTargetLifecycle:
    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ) -> ProgramSession:
        handle: ProjectHandle | None = None
        session: ProgramSession | None = None
        with self._store.registry_lock.write_lock():
            if name in self._store.sessions:
                raise ValueError(f"セッション '{name}' は既に存在します")

            handle = self._store.get_or_create_project_handle(project_location, project_name)
            had_target = name in self._store.target_projects
            had_lock = name in self._store.locks
            self._store.target_projects[name] = handle.get_key()
            session = handle.open_program(domain_path)

            try:
                self._initialize_opened_session_locked(
                    name=name,
                    session=session,
                )
                self._store.locks.setdefault(name, threading.RLock())
                self._store.sessions[name] = session
                return session
            except Exception:  # noqa: BLE001
                self._store.sessions.pop(name, None)
                try:
                    if session is not None:
                        session.close()
                except Exception as close_exc:
                    logger.warning("failed to rollback session close during create_session for target '%s': %s", name, close_exc)
                if not had_target:
                    self._store.target_projects.pop(name, None)
                if not had_lock:
                    self._store.locks.pop(name, None)
                try:
                    self._store.core_accessor().remove_context(name)
                except Exception as remove_exc:
                    logger.warning("failed to rollback context removal during create_session for target '%s': %s", name, remove_exc)
                if handle is not None and handle.is_closed():
                    self._store.project_handles.pop(handle.get_key(), None)
                raise

    def register_target(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
    ) -> Dict[str, Optional[str]]:
        with self._store.registry_lock.write_lock():
            key = ProjectHandle.make_key(project_location, project_name)
            if name in self._store.sessions:
                active_key = self._store.sessions[name].get_project_handle().get_key()
                if active_key != key:
                    raise ValueError(
                        f"ターゲット '{name}' は既に別プロジェクトでセッションが開いています: {active_key}"
                    )
            self._store.target_projects[name] = key
            self._store.locks.setdefault(name, threading.RLock())
            return {
                "target": name,
                "project_location": key[0],
                "project_name": key[1],
                "domain_path": None,
            }

    def list_targets(self) -> List[Dict[str, Optional[str]]]:
        with self._store.registry_lock.read_lock():
            names = sorted(set(self._store.target_projects.keys()) | set(self._store.sessions.keys()))
            results: List[Dict[str, Optional[str]]] = []
            for name in names:
                session = self._store.sessions.get(name)
                if session is not None:
                    info = session.to_dict()
                else:
                    project_key = self._store.target_projects.get(name)
                    if project_key is None:
                        continue
                    info = {
                        "project_location": project_key[0],
                        "project_name": project_key[1],
                        "domain_path": None,
                    }
                results.append({"target": name, **info})
            return results

    def list_programs(self, name: str):
        with self._store.registry_lock.write_lock():
            session = self._store.sessions.get(name)
            if session is not None:
                handle = session.get_project_handle()
                self._store.target_projects[name] = handle.get_key()
                return handle.list_programs()

            key = self._store.get_target_project_key_locked(name)
            metadata_programs = ProjectHandle.list_programs_from_metadata(key[0], key[1])
            if metadata_programs is not None:
                return metadata_programs

            handle = self._store.get_or_create_project_handle(key[0], key[1])
            return handle.list_programs()

    def load_program(
        self,
        name: str,
        domain_path: str,
    ) -> str:
        with self._store.registry_lock.write_lock():
            if not domain_path:
                raise ValueError("domain_path を指定してください")
            handle = self._store.get_target_handle_locked(name)
            new_session = handle.open_program(domain_path)
            had_session = name in self._store.sessions
            try:
                loaded_domain_path = self._initialize_opened_session_locked(
                    name=name,
                    session=new_session,
                )
            except Exception:
                self._store.cleanup_session(
                    name,
                    new_session,
                    handle,
                    remove_registry_entry=False,
                    remove_context=not had_session,
                )
                raise

            old_session = self._store.sessions.get(name)
            self._store.sessions[name] = new_session
            self._store.locks.setdefault(name, threading.RLock())
            self._store.target_projects[name] = handle.get_key()
            try:
                if old_session is not None:
                    old_session.close()
            finally:
                if handle.is_closed():
                    self._store.project_handles.pop(handle.get_key(), None)
            return loaded_domain_path

    def import_program(self, name: str, binary_path: str) -> str:
        with self._store.registry_lock.write_lock():
            if not binary_path:
                raise ValueError("binary_path を指定してください")
            handle = self._store.get_target_handle_locked(name)
            domain_file = handle.import_program(binary_path)
            self._store.target_projects[name] = handle.get_key()
            return domain_file.getPathname()

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        with self._store.registry_lock.write_lock():
            self._close_session_locked(name, remove_program=remove_program)

    def close_all(self) -> None:
        with self._store.registry_lock.write_lock():
            names = list(self._store.sessions.keys())
            for name in names:
                try:
                    self._close_session_locked(name, remove_program=False)
                except Exception as close_exc:  # noqa: BLE001
                    logger.warning("failed to close session during close_all for target '%s': %s", name, close_exc)
            self._store.sessions.clear()
            self._store.locks.clear()
            self._store.target_projects.clear()
            self._store.clear_analyzed_loads()
            for handle in list(self._store.project_handles.values()):
                try:
                    handle.close()
                except Exception as handle_exc:
                    logger.warning("failed to close project handle during close_all: %s", handle_exc)
            self._store.project_handles.clear()
            self._store.core_accessor().clear_contexts()

    def _close_session_locked(self, name: str, *, remove_program: bool) -> None:
        session = self._store.sessions.get(name)
        if session is None:
            raise RuntimeError(f"セッション '{name}' は存在しません")
        handle = session.get_project_handle()
        self._store.cleanup_session(
            name,
            session,
            handle,
            remove_registry_entry=False,
            remove_context=False,
            remove_program=remove_program,
        )
        self._store.sessions.pop(name, None)
        self._store.locks.pop(name, None)
        self._store.target_projects.pop(name, None)
        self._store.clear_analyzed_loads_for_target(name)
        self._store.core_accessor().remove_context(name)

    def _initialize_opened_session_locked(
        self,
        *,
        name: str,
        session: ProgramSession,
    ) -> str:
        program = session.get_program()
        self._store.core_accessor().initialize(program, key=name)
        loaded_domain_path = session.to_dict().get("domain_path") or self._store.session_domain_path(session)
        self._analyze_program_on_first_load_locked(name=name, domain_path=loaded_domain_path, session=session)
        return loaded_domain_path

    def _analyze_program_on_first_load_locked(
        self,
        *,
        name: str,
        domain_path: str,
        session: ProgramSession,
    ) -> None:
        if self._store.is_analyzed_load(name, domain_path):
            return

        utilities = java_bindings._ghidra_program_utilities()
        program = session.get_program()
        should_analyze = bool(utilities.shouldAskToAnalyze(program))
        if should_analyze:
            script_util = java_bindings._ghidra_script_util()
            script_util.acquireBundleHostReference()
            try:
                session.flat_api.analyzeAll(program)
                utilities.markProgramAnalyzed(program)
            finally:
                script_util.releaseBundleHostReference()
        self._store.mark_analyzed_load(name, domain_path)


__all__ = ["RuntimeTargetLifecycle"]
