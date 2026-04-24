"""Target/session lifecycle operations for runtime backend."""

from __future__ import annotations

import logging
import pathlib
import threading
from typing import Dict, List, Optional

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_headless.session import ProgramSession, ProjectHandle, java_bindings, path_utils

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
                raise ValueError(f"Session '{name}' already exists")

            handle = self._store.get_or_create_project_handle(project_location, project_name)
            had_target = name in self._store.target_projects
            previous_target_key = self._store.target_projects.get(name)
            had_lock = name in self._store.locks
            self._store.target_projects[name] = handle.get_key()

            try:
                session = handle.open_program(domain_path)
                self._initialize_opened_session_locked(
                    name=name,
                    session=session,
                )
                self._store.locks.setdefault(name, threading.RLock())
                self._store.sessions[name] = session
                return session
            except Exception:  # noqa: BLE001
                self._store.sessions.pop(name, None)
                rollback_error = None
                if handle is not None:
                    rollback_error = self._cleanup_failed_create_session_locked(
                        name=name,
                        session=session,
                        handle=handle,
                    )
                if rollback_error is not None:
                    logger.warning(
                        "failed to rollback session close during create_session for target '%s': %s",
                        name,
                        rollback_error,
                    )
                if had_target and previous_target_key is not None:
                    self._store.target_projects[name] = previous_target_key
                else:
                    self._store.target_projects.pop(name, None)
                if not had_lock:
                    self._store.locks.pop(name, None)
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
                        f"Target '{name}' already has an open session in another project: {active_key}"
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
            if not ProjectHandle.is_repository_project_from_metadata(key[0], key[1]):
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
                raise ValueError("domain_path is required")
            handle = self._store.get_target_handle_locked(name)
            normalized_domain_path = self._normalize_domain_path_locked(handle, domain_path)
            owner_target = self._find_loaded_target_locked(handle=handle, domain_path=normalized_domain_path)
            if owner_target is not None:
                details = {
                    "operation": "load_program",
                    "target": name,
                    "domain_path": normalized_domain_path,
                }
                if owner_target != name:
                    details["owner_target"] = owner_target
                raise DomainError(
                    code=ErrorCode.TARGET_ALREADY_LOADED,
                    message=f"TARGET_ALREADY_LOADED: program already loaded: {normalized_domain_path}",
                    hint="Use the existing target directly instead of reloading the same program",
                    retryable=False,
                    details=details,
                )

            old_session = self._store.sessions.get(name)
            old_domain_path = None
            if old_session is not None:
                try:
                    old_domain_path = self._store.session_domain_path(old_session)
                except Exception:
                    old_domain_path = None
            new_session = handle.open_program(normalized_domain_path)
            try:
                loaded_domain_path = self._initialize_opened_session_locked(
                    name=name,
                    session=new_session,
                )
            except Exception:
                self._rollback_failed_load_initialization_locked(
                    name=name,
                    handle=handle,
                    new_session=new_session,
                    old_session=old_session,
                )
                raise

            self._store.locks.setdefault(name, threading.RLock())
            self._store.target_projects[name] = handle.get_key()
            try:
                if old_session is not None:
                    old_session.close()
            except Exception:
                self._rollback_failed_session_replacement_locked(
                    name=name,
                    handle=handle,
                    new_session=new_session,
                    old_session=old_session,
                    old_domain_path=old_domain_path,
                )
                raise

            self._store.sessions[name] = new_session
            if old_domain_path is not None:
                self._store.clear_dirty_program(name, old_domain_path)
            if handle.is_closed():
                self._store.project_handles.pop(handle.get_key(), None)
            return loaded_domain_path

    def import_program(self, name: str, binary_path: str, **kwargs) -> str:
        with self._store.registry_lock.write_lock():
            if not binary_path:
                raise ValueError("binary_path is required")
            handle = self._store.get_target_handle_locked(name)
            binary = pathlib.Path(binary_path)
            existing_domain_path = self._existing_imported_program_path_locked(handle, binary)
            if existing_domain_path is not None:
                raise DomainError(
                    code=ErrorCode.PROGRAM_ALREADY_IMPORTED,
                    message=f"PROGRAM_ALREADY_IMPORTED: program already exists: {existing_domain_path}",
                    hint="Use load_project_program with the existing domain path instead of importing again",
                    retryable=False,
                    details={
                        "operation": "import_program",
                        "target": name,
                        "binary_path": binary_path,
                        "existing_domain_path": existing_domain_path,
                    },
                )
            domain_file = handle.import_program(binary_path, **kwargs)
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
            self._store.clear_dirty_programs()
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
            raise RuntimeError(f"Session '{name}' does not exist")
        handle = session.get_project_handle()
        if remove_program:
            self._ensure_program_removal_allowed_locked(name, session, handle)
        close_error = None
        try:
            self._store.cleanup_session(
                name,
                session,
                handle,
                remove_registry_entry=False,
                remove_context=False,
                remove_program=remove_program,
            )
        except Exception as exc:
            close_error = exc

        if close_error is None or self._session_is_closed(session):
            self._store.sessions.pop(name, None)
            self._store.locks.pop(name, None)
            self._store.target_projects.pop(name, None)
            self._store.clear_analyzed_loads_for_target(name)
            self._store.clear_dirty_programs_for_target(name)
            self._store.core_accessor().remove_context(name)

        if close_error is not None:
            raise close_error

    def _ensure_program_removal_allowed_locked(self, name: str, session, handle) -> None:
        domain_path = self._store.session_domain_path(session)
        try:
            status = handle.get_sync_status(domain_path)
        except Exception as exc:
            raise DomainError(
                code=ErrorCode.UNSAFE_PROGRAM_REMOVE,
                message=(
                    "UNSAFE_PROGRAM_REMOVE: failed to verify whether the program is under "
                    "shared-project version control"
                ),
                hint="Close the session without remove_program, then inspect get_project_sync_status",
                retryable=False,
                details={
                    "operation": "close_session",
                    "target": name,
                    "domain_path": domain_path,
                },
            ) from exc

        if status.get("is_versioned"):
            raise DomainError(
                code=ErrorCode.UNSAFE_PROGRAM_REMOVE,
                message=(
                    "UNSAFE_PROGRAM_REMOVE: refusing to remove a versioned shared-project program; "
                    "undo checkout or close the session without removing the program"
                ),
                hint="Use close_session for versioned programs; do not use close_session_and_remove_program",
                retryable=False,
                details={
                    "operation": "close_session",
                    "target": name,
                    "domain_path": domain_path,
                    "version": status.get("version"),
                    "latest_version": status.get("latest_version"),
                },
            )

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

    def _rollback_failed_load_initialization_locked(
        self,
        *,
        name: str,
        handle: ProjectHandle,
        new_session: ProgramSession,
        old_session: ProgramSession | None,
    ) -> None:
        cleanup_error = self._cleanup_failed_session_locked(
            name=name,
            session=new_session,
            handle=handle,
            remove_context=old_session is None,
            allow_handle_close=old_session is None,
        )
        restore_error = None
        if old_session is not None and not self._session_is_closed(old_session):
            try:
                self._restore_session_context_locked(name, old_session)
            except Exception as exc:  # noqa: BLE001
                restore_error = exc
        if cleanup_error is not None:
            raise cleanup_error
        if restore_error is not None:
            raise restore_error

    def _rollback_failed_session_replacement_locked(
        self,
        *,
        name: str,
        handle: ProjectHandle,
        new_session: ProgramSession,
        old_session: ProgramSession,
        old_domain_path: str | None,
    ) -> None:
        old_session_closed = self._session_is_closed(old_session)
        cleanup_error = self._cleanup_failed_session_locked(
            name=name,
            session=new_session,
            handle=handle,
            remove_context=old_session_closed,
            allow_handle_close=old_session_closed,
        )
        if old_session_closed:
            self._store.sessions.pop(name, None)
            if old_domain_path is not None:
                self._store.clear_dirty_program(name, old_domain_path)
            if cleanup_error is not None:
                raise cleanup_error
            return

        restore_error = None
        try:
            self._restore_session_context_locked(name, old_session)
        except Exception as exc:  # noqa: BLE001
            restore_error = exc
        if cleanup_error is not None:
            raise cleanup_error
        if restore_error is not None:
            raise restore_error

    def _cleanup_failed_session_locked(
        self,
        *,
        name: str,
        session: ProgramSession,
        handle: ProjectHandle,
        remove_context: bool,
        allow_handle_close: bool,
    ) -> Exception | None:
        cleanup_error = None
        try:
            self._store.cleanup_session(
                name,
                session,
                handle,
                remove_registry_entry=False,
                remove_context=remove_context,
                save=False,
            )
        except Exception as exc:  # noqa: BLE001
            cleanup_error = exc

        if allow_handle_close and not handle.is_closed() and not self._handle_has_live_sessions_locked(handle):
            try:
                handle.close()
            except Exception as handle_exc:  # noqa: BLE001
                logger.warning("failed to close leaked project handle during rollback for target '%s': %s", name, handle_exc)
        if handle.is_closed():
            self._store.project_handles.pop(handle.get_key(), None)
        return cleanup_error

    def _cleanup_failed_create_session_locked(
        self,
        *,
        name: str,
        session: ProgramSession | None,
        handle: ProjectHandle,
    ) -> Exception | None:
        if session is not None:
            return self._cleanup_failed_session_locked(
                name=name,
                session=session,
                handle=handle,
                remove_context=True,
                allow_handle_close=True,
            )

        if not handle.is_closed() and not self._handle_has_live_sessions_locked(handle):
            try:
                handle.close()
            except Exception as handle_exc:  # noqa: BLE001
                logger.warning("failed to close leaked project handle during rollback for target '%s': %s", name, handle_exc)
        if handle.is_closed():
            self._store.project_handles.pop(handle.get_key(), None)
        return None

    def _handle_has_live_sessions_locked(self, handle: ProjectHandle) -> bool:
        handle_key = handle.get_key()
        for session in self._store.sessions.values():
            if self._session_is_closed(session):
                continue
            try:
                session_handle = session.get_project_handle()
            except Exception:
                continue
            if session_handle.get_key() == handle_key:
                return True
        return False

    def _restore_session_context_locked(self, name: str, session: ProgramSession) -> None:
        self._store.core_accessor().initialize(session.get_program(), key=name)

    @staticmethod
    def _normalize_domain_path_locked(handle: ProjectHandle, domain_path: str | None) -> str:
        domain_dir, domain_name = path_utils._parse_domain_path(handle.project, domain_path)
        normalized_path = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        return normalized_path

    def _find_loaded_target_locked(self, *, handle: ProjectHandle, domain_path: str) -> str | None:
        requested_key = handle.get_key()
        for target_name, session in self._store.sessions.items():
            session_handle = session.get_project_handle()
            if session_handle.get_key() != requested_key:
                continue
            if self._store.session_domain_path(session) == domain_path:
                return target_name
        return None

    @staticmethod
    def _existing_imported_program_path_locked(handle: ProjectHandle, binary_path: pathlib.Path) -> str | None:
        domain_file = handle.project.getProjectData().getFile("/" + binary_path.name)
        if domain_file is None:
            return None
        return domain_file.getPathname()

    @staticmethod
    def _session_is_closed(session: ProgramSession) -> bool:
        try:
            return session.get_project_handle() is None
        except Exception:
            return True


__all__ = ["RuntimeTargetLifecycle"]
