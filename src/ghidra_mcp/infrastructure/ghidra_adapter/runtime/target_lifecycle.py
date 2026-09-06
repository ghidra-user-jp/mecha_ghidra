"""Target/session lifecycle operations for runtime backend."""

from __future__ import annotations

import contextlib
import logging
import pathlib
import re
import threading
from collections.abc import Iterator
from typing import Dict, List, Optional

from ghidra_headless.errors import HeadlessError, error_code_of
from ghidra_headless.session import ProgramSession, ProjectHandle, java_bindings, path_utils
from ghidra_headless.session.transactions import run_in_transaction
from ghidra_mcp.application.locks import acquire_ordered_locks
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_utils import is_project_lock_error

from .session_store import RuntimeSessionStore
from .sync_reopen import SyncReopenMixin

logger = logging.getLogger(__name__)

_IMPORT_DOMAIN_PATH_PATTERNS = (
    re.compile(r"IMPORT_CLOSE_FAILED: imported program (?P<path>/.*?) but "),
    re.compile(r"IMPORT_POST_PROCESS_FAILED: imported program (?P<path>/.*?) but "),
    re.compile(r"IMPORT_POST_PROCESS_FAILED: rolled back imported program (?P<path>/.*?) after "),
    re.compile(r"PROGRAM_CLOSE_FAILED: failed to close imported program (?P<path>/.*?): "),
    re.compile(r"PROGRAM_CLOSE_FAILED: failed to close raw import results for imported program (?P<path>/.*?): "),
)


class RuntimeTargetLifecycle(SyncReopenMixin):
    """Target/session lifecycle; reuses the sync close/reopen lease for in-place reloads."""

    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    def create_repository_cache_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        repository_url: str,
    ) -> Dict[str, object]:
        with self._store.operation_lock.read_lock():
            return ProjectHandle.create_repository_cache_project(
                project_location,
                project_name,
                repository_url=repository_url,
            )

    @contextlib.contextmanager
    def _target_operation(self, name: str, *, create: bool = False) -> Iterator[None]:
        with self._store.operation_lock.read_lock():
            with self._store.registry_lock.write_lock():
                lock = (
                    self._store.locks.setdefault(name, threading.RLock()) if create else self._store.ensure_lock(name)
                )
                project_key = self._store.target_projects.get(name)
                if project_key is None and name in self._store.sessions:
                    project_key = self._store.sessions[name].get_project_handle().get_key()
                    self._store.target_projects[name] = project_key
                project_lock = self._store.ensure_project_lock(project_key) if project_key is not None else None
            locks = [("target", lock)]
            if project_lock is not None:
                locks.append(("project", project_lock))
            with acquire_ordered_locks(locks, message_prefix="runtime "):
                yield

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ) -> ProgramSession:
        with self._store.operation_lock.read_lock():
            return self._create_session_locked(
                name,
                project_location,
                project_name=project_name,
                domain_path=domain_path,
            )

    def create_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        overwrite: bool = False,
    ) -> Dict[str, object]:
        with self._store.operation_lock.write_lock():
            project_key = ProjectHandle.resolve_project_creation_target(
                project_location,
                project_name,
            )
            if overwrite:
                with self._store.registry_lock.read_lock():
                    registered_targets = sorted(
                        name for name, target_key in self._store.target_projects.items() if target_key == project_key
                    )
                    handle = self._store.project_handles.get(project_key)
                has_open_handle = handle is not None and not handle.is_closed()
                if registered_targets or has_open_handle:
                    reasons = []
                    if registered_targets:
                        reasons.append(f"registered target(s): {', '.join(registered_targets)}")
                    if has_open_handle:
                        reasons.append("an open project handle")
                    raise HeadlessError(
                        "PROJECT_IN_USE: cannot overwrite project "
                        f"'{project_key[0]}::{project_key[1]}' while it has " + " and ".join(reasons)
                    )
            return ProjectHandle.create_project(
                project_key[0],
                project_key[1],
                overwrite=overwrite,
            )

    def _create_session_locked(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None,
        domain_path: str | None,
    ) -> ProgramSession:
        project_key = ProjectHandle.make_key(project_location, project_name)
        handle: ProjectHandle | None = None
        session: ProgramSession | None = None
        with self._store.registry_lock.write_lock():
            if name in self._store.sessions:
                raise ValueError(f"Session '{name}' already exists")
            had_target = name in self._store.target_projects
            previous_target_key = self._store.target_projects.get(name)
            had_lock = name in self._store.locks
            lock = self._store.locks.setdefault(name, threading.RLock())
            project_lock = self._store.ensure_project_lock(project_key)
            self._store.target_projects[name] = project_key

        with acquire_ordered_locks(
            [("target", lock), ("project", project_lock)],
            message_prefix="runtime ",
        ):
            with self._store.registry_lock.write_lock():
                if name in self._store.sessions:
                    if had_target and previous_target_key is not None:
                        self._store.target_projects[name] = previous_target_key
                    else:
                        self._store.target_projects.pop(name, None)
                    if not had_lock:
                        self._store.locks.pop(name, None)
                    raise ValueError(f"Session '{name}' already exists")
            try:
                handle = self._store.get_or_create_project_handle(project_key)
                session = handle.open_program(domain_path)
                self._initialize_opened_session_locked(
                    name=name,
                    session=session,
                )
                with self._store.registry_lock.write_lock():
                    self._store.sessions[name] = session
                return session
            except Exception as operation_error:
                with self._store.registry_lock.write_lock():
                    if session is not None and self._store.sessions.get(name) is session:
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
                with self._store.registry_lock.write_lock():
                    if had_target and previous_target_key is not None:
                        self._store.target_projects[name] = previous_target_key
                    else:
                        self._store.target_projects.pop(name, None)
                    if not had_lock:
                        self._store.locks.pop(name, None)
                if rollback_error is not None:
                    raise rollback_error from operation_error
                raise

    def register_target(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
    ) -> Dict[str, Optional[str]]:
        key = ProjectHandle.make_key(project_location, project_name)
        with self._store.operation_lock.read_lock():
            with self._store.registry_lock.write_lock():
                lock = self._store.locks.setdefault(name, threading.RLock())
                project_lock = self._store.ensure_project_lock(key)
            with acquire_ordered_locks(
                [("target", lock), ("project", project_lock)],
                message_prefix="runtime ",
            ):
                with self._store.registry_lock.write_lock():
                    if name in self._store.sessions:
                        active_key = self._store.sessions[name].get_project_handle().get_key()
                        if active_key != key:
                            raise ValueError(
                                f"Target '{name}' already has an open session in another project: {active_key}"
                            )
                    self._store.target_projects[name] = key
                    self._store.locks.setdefault(name, lock)
                return {
                    "target": name,
                    "project_location": key[0],
                    "project_name": key[1],
                    "domain_path": None,
                }

    def list_targets(self) -> List[Dict[str, Optional[str]]]:
        with self._store.operation_lock.read_lock():
            with self._store.registry_lock.read_lock():
                names = sorted(set(self._store.target_projects.keys()) | set(self._store.sessions.keys()))
            results: List[Dict[str, Optional[str]]] = []
            for name in names:
                # A target lock can be removed and recreated while this read is
                # waiting.  Retry until the lock we acquired is still the
                # registry's lock for this target.
                while True:
                    with self._store.registry_lock.read_lock():
                        lock = self._store.locks.get(name)
                        target_exists = name in self._store.sessions or name in self._store.target_projects
                    if lock is None and target_exists:
                        with self._store.registry_lock.write_lock():
                            if name in self._store.sessions or name in self._store.target_projects:
                                lock = self._store.locks.setdefault(name, threading.RLock())
                    if lock is None:
                        break
                    with acquire_ordered_locks(
                        [("target", lock)],
                        message_prefix="runtime ",
                    ):
                        with self._store.registry_lock.read_lock():
                            if self._store.locks.get(name) is not lock:
                                continue
                            session = self._store.sessions.get(name)
                            project_key = self._store.target_projects.get(name)
                        if session is not None:
                            # ProgramSession.to_dict() reaches into Ghidra.  The
                            # target lock keeps the session alive without
                            # holding registry_lock across that external call.
                            info = session.to_dict()
                        elif project_key is not None:
                            info = {
                                "project_location": project_key[0],
                                "project_name": project_key[1],
                                "domain_path": None,
                            }
                        else:
                            info = None
                        break

                if lock is None:
                    # The target was removed after the names snapshot, or the
                    # registry is incomplete.  Do not inspect a session whose
                    # lifecycle cannot be protected by a target lock.
                    continue
                if info is None:
                    continue
                results.append({"target": name, **info})
            return results

    def list_programs(self, name: str):
        with self._store.operation_lock.read_lock():
            with self._store.registry_lock.write_lock():
                lock = self._store.ensure_lock(name)
                key = self._store.get_target_project_key_locked(name)
                project_lock = self._store.ensure_project_lock(key)
            with acquire_ordered_locks(
                [("target", lock), ("project", project_lock)],
                message_prefix="runtime ",
            ):
                with self._store.registry_lock.write_lock():
                    session = self._store.sessions.get(name)
                    if session is not None:
                        handle = session.get_project_handle()
                        self._store.target_projects[name] = handle.get_key()
                    else:
                        handle = None
                        key = self._store.get_target_project_key_locked(name)
                if handle is not None:
                    return handle.list_programs()

                is_repository_project = ProjectHandle.is_repository_project_from_metadata(key[0], key[1])
                if not is_repository_project:
                    metadata_programs = self._list_programs_from_metadata_locked(key)
                    if metadata_programs is not None:
                        return metadata_programs

                try:
                    handle = self._store.get_or_create_project_handle(key)
                    return handle.list_programs()
                except Exception as exc:
                    if is_repository_project and is_project_lock_error(exc):
                        metadata_programs = self._list_programs_from_metadata_locked(key)
                        if metadata_programs is not None:
                            logger.info(
                                "project is locked while listing programs for target '%s'; "
                                "returning project metadata snapshot",
                                name,
                            )
                            return self._mark_metadata_programs_as_lock_snapshot(metadata_programs)
                    raise

    def load_program(
        self,
        name: str,
        domain_path: str,
        *,
        version: int | None = None,
    ) -> Dict[str, object]:
        """Open ``domain_path`` in target ``name``.

        Loading the program the target already holds reopens it in place (the
        former ``reload_project_program``); a ``version`` opens that past
        repository version read-only instead of the current file.
        """
        if not domain_path:
            raise ValueError("domain_path is required")
        requested_version = None if version is None else int(version)
        if requested_version is not None and requested_version < 1:
            raise ValueError("version must be >= 1")
        with self._target_operation(name):
            handle = self._store.get_target_handle(name)
            normalized_domain_path = self._normalize_domain_path_locked(handle, domain_path)
            with self._store.registry_lock.read_lock():
                session_snapshot = list(self._store.sessions.items())
                current_session = self._store.sessions.get(name)
            if current_session is not None and self._session_matches_load_locked(
                current_session,
                domain_path=normalized_domain_path,
                version=requested_version,
            ):
                return self._reload_current_session_locked(
                    name,
                    domain_path=normalized_domain_path,
                    version=requested_version,
                )
            owner_target = self._find_loaded_target_locked(
                handle=handle,
                domain_path=normalized_domain_path,
                sessions=session_snapshot,
            )
            if owner_target is not None and owner_target != name and requested_version is None:
                raise DomainError(
                    code=ErrorCode.TARGET_ALREADY_LOADED,
                    message=f"TARGET_ALREADY_LOADED: program already loaded: {normalized_domain_path}",
                    hint="Use the existing target directly instead of reloading the same program",
                    retryable=False,
                    details={
                        "operation": "load_program",
                        "target": name,
                        "domain_path": normalized_domain_path,
                        "owner_target": owner_target,
                    },
                )

            with self._store.registry_lock.read_lock():
                old_session = self._store.sessions.get(name)
            old_domain_path = None
            if old_session is not None:
                try:
                    old_domain_path = self._store.session_domain_path(old_session)
                except Exception:
                    old_domain_path = None
            if requested_version is None:
                new_session = handle.open_program(normalized_domain_path)
            else:
                new_session = handle.open_program(normalized_domain_path, version=requested_version)
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

            with self._store.registry_lock.write_lock():
                self._store.locks.setdefault(name, threading.RLock())
                self._store.target_projects[name] = handle.get_key()
            try:
                if old_session is not None:
                    old_session.close()
            except Exception:
                assert old_session is not None
                self._rollback_failed_session_replacement_locked(
                    name=name,
                    handle=handle,
                    new_session=new_session,
                    old_session=old_session,
                    old_domain_path=old_domain_path,
                )
                raise

            handle_closed = handle.is_closed()
            with self._store.registry_lock.write_lock():
                self._store.sessions[name] = new_session
                if old_domain_path is not None:
                    self._store.clear_dirty_program(name, old_domain_path)
                if handle_closed:
                    if self._store.project_handles.get(handle.get_key()) is handle:
                        self._store.project_handles.pop(handle.get_key(), None)
            return {
                "program": loaded_domain_path,
                "reloaded": False,
                "version": requested_version,
                "read_only": requested_version is not None,
            }

    def _session_matches_load_locked(self, session: ProgramSession, *, domain_path: str, version: int | None) -> bool:
        try:
            current_path = self._store.session_domain_path(session)
        except Exception:
            return False
        if current_path != domain_path:
            return False
        current_version = getattr(session, "read_only_version", None)
        return (None if current_version is None else int(current_version)) == version

    def _reload_current_session_locked(self, name: str, *, domain_path: str, version: int | None) -> Dict[str, object]:
        """Close and reopen the program the target already holds (unsaved edits are saved first)."""
        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(name)
        save_before_close = version is None and self._active_program_is_changed_locked(name, session, domain_path)
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=save_before_close,
            reopen_version=version,
        )
        return {
            "program": domain_path,
            "reloaded": True,
            "version": version,
            "read_only": version is not None,
        }

    def import_program(self, name: str, binary_path: str, **kwargs) -> str:
        if not binary_path:
            raise ValueError("binary_path is required")
        with self._target_operation(name):
            handle = self._store.get_target_handle(name)
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
            try:
                domain_file = handle.import_program(binary_path, **kwargs)
            except Exception as exc:
                mapped = self._partial_import_error(
                    exc,
                    target=name,
                    binary_path=binary_path,
                )
                if mapped is not None:
                    raise mapped from exc
                raise
            with self._store.registry_lock.write_lock():
                self._store.target_projects[name] = handle.get_key()
            return domain_file.getPathname()

    def save_project_program(self, name: str, *, domain_path: str | None = None) -> Dict[str, object]:
        with self._target_operation(name):
            with self._store.registry_lock.read_lock():
                session = self._store.ensure_session(name)
            handle = session.get_project_handle()
            active_domain_path = self._store.session_domain_path(session)
            requested_domain_path = (domain_path or "").strip()
            resolved_domain_path = active_domain_path
            if requested_domain_path:
                resolved_domain_path = self._normalize_domain_path_locked(handle, requested_domain_path)
                if resolved_domain_path != active_domain_path:
                    raise ValueError(
                        "domain_path must match the currently loaded program: "
                        f"requested={resolved_domain_path}, active={active_domain_path}"
                    )

            runtime_dirty = self._store.is_dirty_program(name, resolved_domain_path)
            saved = handle.save_program(session.get_program(), force=runtime_dirty)
            with self._store.registry_lock.write_lock():
                if not runtime_dirty or self._save_cleared_runtime_dirty_locked(
                    handle,
                    resolved_domain_path,
                    saved=bool(saved),
                ):
                    self._store.clear_dirty_program(name, resolved_domain_path)
            return {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "saved": bool(saved),
            }

    @staticmethod
    def _save_cleared_runtime_dirty_locked(handle, domain_path: str, *, saved: bool) -> bool:
        if not saved:
            return False
        try:
            status = handle.get_sync_status(domain_path)
        except Exception as exc:
            logger.debug("failed to refresh sync status after runtime-dirty save: %s", exc)
            return False
        if not status.get("is_versioned"):
            return True
        if not status.get("is_checked_out"):
            return True
        return bool(status.get("modified_since_checkout"))

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        with self._target_operation(name):
            self._close_session_locked(name, remove_program=remove_program)

    def close_all(self) -> None:
        with self._store.operation_lock.write_lock():
            self._close_all_locked()

    def _close_all_locked(self) -> None:
        with self._store.registry_lock.read_lock():
            names = list(self._store.sessions.keys())
        close_errors: list[tuple[str, Exception]] = []
        handle_errors: list[tuple[tuple[str, str], Exception]] = []
        for name in names:
            try:
                self._close_session_locked(name, remove_program=False)
            except Exception as close_exc:
                logger.warning("failed to close session during close_all for target '%s': %s", name, close_exc)
                close_errors.append((name, close_exc))
            with self._store.registry_lock.write_lock():
                if name not in self._store.sessions:
                    self._store.locks.pop(name, None)
                    self._store.target_projects.pop(name, None)
                    self._store.clear_analyzed_loads_for_target(name)
                    self._store.clear_dirty_programs_for_target(name)

        with self._store.registry_lock.read_lock():
            handles = list(self._store.project_handles.values())
        for handle in handles:
            if close_errors and self._handle_has_live_sessions_locked(handle):
                continue
            try:
                # force: a session close that failed above may have leaked a
                # refcount; shutdown must still reclaim the project.
                handle.close(force=True)
            except Exception as handle_exc:
                logger.warning("failed to close project handle during close_all: %s", handle_exc)
                handle_errors.append((handle.get_key(), handle_exc))
            if handle.is_closed():
                with self._store.registry_lock.write_lock():
                    if self._store.project_handles.get(handle.get_key()) is handle:
                        self._store.project_handles.pop(handle.get_key(), None)

        if close_errors or handle_errors:
            parts = [f"{name}: {error}" for name, error in close_errors]
            parts.extend(f"{key[0]}::{key[1]}: {error}" for key, error in handle_errors)
            summary = "; ".join(parts)
            raise HeadlessError(f"CLOSE_ALL_FAILED: failed to close runtime resource(s): {summary}")

        with self._store.registry_lock.write_lock():
            self._store.sessions.clear()
            self._store.locks.clear()
            self._store.project_locks.clear()
            self._store.target_projects.clear()
            self._store.clear_analyzed_loads()
            self._store.clear_dirty_programs()
            self._store.project_handles.clear()
        self._store.core_accessor().clear_contexts()

    def _close_session_locked(self, name: str, *, remove_program: bool) -> None:
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
            target_exists = name in self._store.target_projects
        if session is None:
            if not remove_program and target_exists:
                return
            raise RuntimeError(f"Session '{name}' does not exist")
        handle = session.get_project_handle()
        domain_path = self._store.session_domain_path(session)
        if remove_program:
            self._ensure_program_removal_allowed_locked(name, session, handle)
            with self._store.registry_lock.read_lock():
                session = self._store.sessions.get(name)
            if session is None:
                raise RuntimeError(f"Session '{name}' was closed during remove safety verification")
            handle = session.get_project_handle()
            domain_path = self._store.session_domain_path(session)
        project_key = handle.get_key()
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

        remove_failed = (
            remove_program and close_error is not None and str(close_error).startswith("REMOVE_PROGRAM_FAILED:")
        )
        if remove_failed:
            # ProgramSession marks itself closed when removal fails after the
            # program was released.  Do not leave that unusable object in the
            # registry if reopening also fails.
            if self._session_is_closed(session):
                with self._store.registry_lock.write_lock():
                    if self._store.sessions.get(name) is session:
                        self._store.sessions.pop(name, None)
            restore_error = self._restore_session_after_remove_failure_locked(
                name,
                project_key=project_key,
                domain_path=domain_path,
            )
            if restore_error is not None:
                with self._store.registry_lock.write_lock():
                    restored_session = self._store.sessions.get(name)
                    self._store.target_projects[name] = project_key
                    self._store.locks.setdefault(name, threading.RLock())
                if restored_session is None:
                    try:
                        self._store.core_accessor().remove_context(name)
                    except Exception as remove_exc:
                        logger.warning("failed to remove context while preserving target '%s': %s", name, remove_exc)
                raise RuntimeError(
                    f"{close_error}; REOPEN_FAILED: failed to restore session: {restore_error}"
                ) from close_error
            raise close_error

        if close_error is None or self._session_is_closed(session):
            owns_target_state = False
            with self._store.registry_lock.write_lock():
                current_session = self._store.sessions.get(name)
                if current_session is session:
                    self._store.sessions.pop(name, None)
                    owns_target_state = True
                elif current_session is None:
                    owns_target_state = True
                if owns_target_state:
                    if remove_program:
                        self._store.locks.pop(name, None)
                        self._store.target_projects.pop(name, None)
                        self._store.clear_analyzed_loads_for_target(name)
                        self._store.clear_dirty_programs_for_target(name)
                    else:
                        self._store.target_projects[name] = project_key
                        self._store.locks.setdefault(name, threading.RLock())
            if owns_target_state:
                self._store.core_accessor().remove_context(name)

        if close_error is not None:
            raise close_error

    def _restore_session_after_remove_failure_locked(
        self,
        name: str,
        *,
        project_key: tuple[str, str],
        domain_path: str,
    ) -> Exception | None:
        with self._store.registry_lock.write_lock():
            self._store.target_projects[name] = project_key
            self._store.locks.setdefault(name, threading.RLock())
        try:
            handle = self._store.get_or_create_project_handle(project_key)
            restored = handle.open_program(domain_path)
            try:
                self._initialize_opened_session_locked(name=name, session=restored)
            except Exception as init_error:
                try:
                    restored.close(save=False)
                except Exception as close_exc:
                    with self._store.registry_lock.write_lock():
                        self._store.sessions[name] = restored
                    raise HeadlessError(
                        "PROGRAM_CLOSE_FAILED: failed to close restored session during "
                        f"remove-failure recovery for target '{name}': {close_exc}; "
                        f"original error: {init_error}"
                    ) from init_error
                raise
            with self._store.registry_lock.write_lock():
                self._store.sessions[name] = restored
            return None
        except Exception as exc:
            return exc

    def _ensure_program_removal_allowed_locked(self, name: str, session, handle) -> None:
        domain_path = self._store.session_domain_path(session)
        status: dict = {}
        try:
            handle.refresh_project_data(force=True)
            status = handle.get_sync_status(domain_path)
            if not status.get("is_versioned"):
                status = self._refresh_active_program_sync_status_for_remove_locked(
                    name,
                    session,
                    handle,
                    domain_path,
                    status=status,
                )
        except DomainError as exc:
            details = dict(exc.details or {})
            details.setdefault("operation", "close_session")
            details.setdefault("target", name)
            details.setdefault("domain_path", domain_path)
            raise DomainError(
                code=exc.code,
                message=exc.message,
                hint=exc.hint,
                retryable=exc.retryable,
                details=details,
            ) from exc
        except Exception as exc:
            if self._remove_guard_error_should_surface(exc):
                raise
            details = {
                "operation": "close_session",
                "target": name,
                "domain_path": domain_path,
            }
            details.update(self._sync_status_version_details(status))
            raise DomainError(
                code=ErrorCode.UNSAFE_PROGRAM_REMOVE,
                message=(
                    "UNSAFE_PROGRAM_REMOVE: failed to verify whether the program is under "
                    "shared-project version control"
                ),
                hint="Close the session without remove_program, then inspect get_project_sync_status",
                retryable=False,
                details=details,
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

    def _refresh_active_program_sync_status_for_remove_locked(
        self,
        name: str,
        session,
        handle,
        domain_path: str,
        *,
        status: dict,
    ) -> dict:
        if status.get("is_versioned"):
            return status
        if not status.get("can_add_to_repository"):
            return status
        save_before_reopen = self._active_program_is_changed_locked(name, session, domain_path)
        reopened_session = self._reopen_session_for_sync_status_refresh_locked(
            name,
            session,
            handle,
            domain_path,
            save=save_before_reopen,
        )
        refreshed_handle = reopened_session.get_project_handle()
        return refreshed_handle.get_sync_status(domain_path)

    def _reopen_session_for_sync_status_refresh_locked(
        self,
        name: str,
        session,
        handle,
        domain_path: str,
        *,
        save: bool,
    ):
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
        active_handle = None
        reopened_session_bound = False
        try:
            session.close(save=save)
            if handle.is_closed():
                with self._store.registry_lock.write_lock():
                    if self._store.project_handles.get(handle.get_key()) is handle:
                        self._store.project_handles.pop(handle.get_key(), None)
            if not handle.is_closed():
                active_handle = handle
            else:
                active_handle = self._store.get_or_create_project_handle(
                    ProjectHandle.make_key(project_location, project_name)
                )
            reopened = active_handle.open_program(domain_path)
            try:
                self._initialize_opened_session_locked(name=name, session=reopened)
                with self._store.registry_lock.write_lock():
                    self._store.sessions[name] = reopened
                reopened_session_bound = True
            except Exception as init_error:
                try:
                    reopened.close(save=False)
                except Exception as close_exc:
                    with self._store.registry_lock.write_lock():
                        self._store.sessions[name] = reopened
                    reopened_session_bound = True
                    raise HeadlessError(
                        "PROGRAM_CLOSE_FAILED: failed to close reopened session during "
                        f"remove guard rollback for target '{name}': {close_exc}; "
                        f"original error: {init_error}"
                    ) from init_error
                raise
            finally:
                if active_handle is not None and active_handle.is_closed():
                    with self._store.registry_lock.write_lock():
                        if self._store.project_handles.get(active_handle.get_key()) is active_handle:
                            self._store.project_handles.pop(active_handle.get_key(), None)
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(name, domain_path)
            return reopened
        except Exception:
            if not reopened_session_bound and self._session_is_closed(session):
                with self._store.registry_lock.write_lock():
                    if self._store.sessions.get(name) is session:
                        self._store.sessions.pop(name, None)
                    self._store.clear_analyzed_loads_for_target(name)
                    self._store.clear_dirty_programs_for_target(name)
                try:
                    self._store.core_accessor().remove_context(name)
                except Exception as remove_exc:
                    logger.warning("failed to remove context while cleaning target '%s': %s", name, remove_exc)
            raise

    def _active_program_is_changed_locked(self, name: str, session, domain_path: str) -> bool:
        if self._store.is_dirty_program(name, domain_path):
            return True
        try:
            return bool(session.get_program().isChanged())
        except Exception as exc:
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                name,
                exc,
            )
            return True

    @staticmethod
    def _remove_guard_error_should_surface(exc: Exception) -> bool:
        return error_code_of(exc) in {
            "SAVE_FAILED",
            "PROGRAM_CLOSE_FAILED",
            "SESSION_CLOSE_FAILED",
            "REOPEN_FAILED",
            "PROJECT_CLOSE_FAILED",
        }

    @staticmethod
    def _sync_status_version_details(status: dict) -> dict[str, object]:
        details: dict[str, object] = {}
        for key in ("is_versioned", "version", "latest_version"):
            if key in status:
                details[key] = status.get(key)
        return details

    @staticmethod
    def _list_programs_from_metadata_locked(key: tuple[str, str]):
        return ProjectHandle.list_programs_from_metadata(key[0], key[1])

    @staticmethod
    def _mark_metadata_programs_as_lock_snapshot(programs):
        marked = []
        for item in programs:
            updated = dict(item)
            updated.setdefault("is_versioned", None)
            updated.setdefault("version", None)
            updated.setdefault("latest_version", None)
            updated.setdefault("is_latest_version", None)
            updated.setdefault("can_add_to_repository", None)
            updated["sync_status_error"] = "PROJECT_LOCKED: returned metadata snapshot because the project is locked"
            marked.append(updated)
        return marked

    def _initialize_opened_session_locked(
        self,
        *,
        name: str,
        session: ProgramSession,
    ) -> str:
        program = session.get_program()
        self._store.core_accessor().initialize(program, key=name)
        loaded_domain_path = session.to_dict().get("domain_path") or self._store.session_domain_path(session)
        if getattr(session, "read_only_version", None) is None:
            # A past version is immutable, so it can neither be analyzed nor saved.
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
            if not self._auto_analysis_allowed_locked(name=name, domain_path=domain_path, session=session):
                return
            script_util = java_bindings._ghidra_script_util()
            script_util.acquireBundleHostReference()
            try:

                def _analyze():
                    session.flat_api.analyzeAll(program)
                    utilities.markProgramAnalyzed(program)

                run_in_transaction(program, "Auto analysis", _analyze)
                self._save_analyzed_program_locked(session, program)
            finally:
                script_util.releaseBundleHostReference()
        self._store.mark_analyzed_load(name, domain_path)

    @staticmethod
    def _auto_analysis_allowed_locked(
        *,
        name: str,
        domain_path: str,
        session: ProgramSession,
    ) -> bool:
        handle = session.get_project_handle()
        try:
            status = handle.get_sync_status(domain_path)
        except Exception as exc:
            logger.warning(
                "skipping initial auto-analysis for target '%s' because sync status is unavailable: %s",
                name,
                exc,
            )
            return False
        if status.get("is_versioned") and not status.get("is_checked_out"):
            logger.info(
                "skipping initial auto-analysis for target '%s' because the shared-project program is not checked out",
                name,
            )
            return False
        if not status.get("is_versioned") and status.get("can_add_to_repository"):
            logger.info(
                "skipping initial auto-analysis for target '%s' because the shared-project program "
                "has not been added to version control",
                name,
            )
            return False
        return True

    @staticmethod
    def _save_analyzed_program_locked(session: ProgramSession, program) -> None:
        handle = session.get_project_handle()
        try:
            handle.save_program(program, force=True)
        except Exception as exc:
            raise HeadlessError(f"SAVE_FAILED: failed to save analysis results after initial load: {exc}") from exc

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
            except Exception as exc:
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
            with self._store.registry_lock.write_lock():
                if self._store.sessions.get(name) is old_session:
                    self._store.sessions.pop(name, None)
                if old_domain_path is not None:
                    self._store.clear_dirty_program(name, old_domain_path)
            if cleanup_error is not None:
                raise cleanup_error
            return

        restore_error = None
        try:
            self._restore_session_context_locked(name, old_session)
        except Exception as exc:
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
        except Exception as exc:
            cleanup_error = exc

        if allow_handle_close and not handle.is_closed() and not self._handle_has_live_sessions_locked(handle):
            try:
                # force: the failed session's program release may itself have
                # failed, leaving a nonzero refcount with no live session that
                # could ever release it — a plain close would reject and wedge
                # the target until the server restarts.
                handle.close(force=True)
            except Exception as handle_exc:
                handle_close_error = HeadlessError(
                    "PROJECT_CLOSE_FAILED: failed to close leaked project handle during rollback "
                    f"for target '{name}': {handle_exc}"
                )
                if cleanup_error is not None:
                    cleanup_error = RuntimeError(f"{cleanup_error}; {handle_close_error}")
                else:
                    cleanup_error = handle_close_error
        if handle.is_closed():
            with self._store.registry_lock.write_lock():
                if self._store.project_handles.get(handle.get_key()) is handle:
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

        cleanup_error = None
        if not handle.is_closed() and not self._handle_has_live_sessions_locked(handle):
            try:
                # force: see _cleanup_failed_session_locked — a leaked refcount
                # from a failed open/release must not wedge the target.
                handle.close(force=True)
            except Exception as handle_exc:
                cleanup_error = HeadlessError(
                    "PROJECT_CLOSE_FAILED: failed to close leaked project handle during rollback "
                    f"for target '{name}': {handle_exc}"
                )
        if handle.is_closed():
            with self._store.registry_lock.write_lock():
                if self._store.project_handles.get(handle.get_key()) is handle:
                    self._store.project_handles.pop(handle.get_key(), None)
        return cleanup_error

    def _handle_has_live_sessions_locked(self, handle: ProjectHandle) -> bool:
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.values())
        for session in sessions:
            if self._session_is_closed(session):
                continue
            try:
                session_handle = session.get_project_handle()
            except Exception:
                continue
            if session_handle is handle:
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

    def _find_loaded_target_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        sessions: list[tuple[str, ProgramSession]],
    ) -> str | None:
        requested_key = handle.get_key()
        for target_name, session in sessions:
            if getattr(session, "read_only_version", None) is not None:
                # Read-only version sessions never conflict with a live load.
                continue
            try:
                session_handle = session.get_project_handle()
            except Exception:
                continue
            if session_handle.get_key() != requested_key:
                continue
            loaded_domain_path = self._store.session_domain_path(session)
            if loaded_domain_path == domain_path:
                return target_name
        return None

    @staticmethod
    def _existing_imported_program_path_locked(handle: ProjectHandle, binary_path: pathlib.Path) -> str | None:
        domain_file = handle.project.getProjectData().getFile("/" + binary_path.name)
        if domain_file is None:
            return None
        return domain_file.getPathname()

    @staticmethod
    def _partial_import_error(
        exc: Exception,
        *,
        target: str,
        binary_path: str,
    ) -> DomainError | None:
        message = str(exc)
        if not message.startswith(
            (
                "IMPORT_CLOSE_FAILED:",
                "IMPORT_POST_PROCESS_FAILED:",
                "PROGRAM_CLOSE_FAILED: failed to close imported program",
                "PROGRAM_CLOSE_FAILED: failed to close raw import results",
            )
        ):
            return None

        imported_domain_path = None
        for pattern in _IMPORT_DOMAIN_PATH_PATTERNS:
            match = pattern.search(message)
            if match is not None:
                imported_domain_path = match.group("path")
                break

        rollback_deleted = message.startswith("IMPORT_POST_PROCESS_FAILED: rolled back imported program")
        partial_import = imported_domain_path is not None and not rollback_deleted
        details: dict[str, object] = {
            "operation": "import_program",
            "target": target,
            "binary_path": binary_path,
            "partial_import": partial_import,
        }
        if imported_domain_path is not None:
            details["imported_domain_path"] = imported_domain_path
        if rollback_deleted:
            details["rollback_deleted"] = True
        elif not partial_import:
            details["cleanup_error"] = True

        return DomainError(
            code=ErrorCode.OPERATION_FAILED,
            message=message,
            hint=(
                "Use load_project_program with imported_domain_path if partial_import is true; "
                "otherwise retry the import after checking the project state"
            ),
            retryable=False,
            details=details,
        )

    @staticmethod
    def _session_is_closed(session: ProgramSession) -> bool:
        try:
            return session.get_project_handle() is None
        except Exception:
            return True


__all__ = ["RuntimeTargetLifecycle"]
