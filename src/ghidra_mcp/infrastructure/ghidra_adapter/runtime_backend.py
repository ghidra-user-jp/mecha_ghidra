"""Ghidra runtime backend implementing target/sync/core operations."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease
from ghidra_headless.session import ProgramSession, ProjectHandle


class RuntimeBackend:
    def __init__(
        self,
        *,
        state: RuntimeState,
    ) -> None:
        self._state = state
        self._core_accessor = state.core_accessor
        self._checkout_required_commands = set(state.checkout_required_commands)
        self._normalize_result = state.normalize_result
        self._sessions = state.sessions
        self._locks = state.locks
        self._target_projects = state.target_projects
        self._project_handles = state.project_handles
        self._registry_lock = state.registry_lock

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
        with self._registry_lock.write_lock():
            if name in self._sessions:
                raise ValueError(f"セッション '{name}' は既に存在します")

            handle = self._get_or_create_project_handle(project_location, project_name)
            had_target = name in self._target_projects
            had_lock = name in self._locks
            self._target_projects[name] = handle.get_key()
            session = handle.open_program(domain_path)
            self._locks.setdefault(name, threading.RLock())
            self._sessions[name] = session

            try:
                program = session.get_program()
                self._core_accessor().initialize(program, key=name)
                return session
            except Exception:  # noqa: BLE001
                self._sessions.pop(name, None)
                try:
                    session.close()
                except Exception:
                    pass
                if not had_target:
                    self._target_projects.pop(name, None)
                if not had_lock:
                    self._locks.pop(name, None)
                try:
                    self._core_accessor().remove_context(name)
                except Exception:
                    pass
                if handle is not None and handle.is_closed():
                    self._project_handles.pop(handle.get_key(), None)
                raise

    def register_target(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
    ) -> Dict[str, Optional[str]]:
        with self._registry_lock.write_lock():
            key = ProjectHandle.make_key(project_location, project_name)
            if name in self._sessions:
                active_key = self._sessions[name].get_project_handle().get_key()
                if active_key != key:
                    raise ValueError(
                        f"ターゲット '{name}' は既に別プロジェクトでセッションが開いています: {active_key}"
                    )
            self._target_projects[name] = key
            self._locks.setdefault(name, threading.RLock())
            return {
                "target": name,
                "project_location": key[0],
                "project_name": key[1],
                "domain_path": None,
            }

    def _ensure(self, name: str) -> ProgramSession:
        try:
            return self._sessions[name]
        except KeyError:
            if name in self._target_projects:
                raise RuntimeError(
                    f"セッション '{name}' は初期化されていません（プログラム未ロード）。"
                    " load_project_program で program を開いてください"
                )
            raise RuntimeError(f"セッション '{name}' は初期化されていません")

    def _lock(self, name: str) -> threading.RLock:
        try:
            return self._locks[name]
        except KeyError:
            raise RuntimeError(f"セッション '{name}' は初期化されていません")

    def list_targets(self) -> List[Dict[str, Optional[str]]]:
        with self._registry_lock.read_lock():
            names = sorted(set(self._target_projects.keys()) | set(self._sessions.keys()))
            results: List[Dict[str, Optional[str]]] = []
            for name in names:
                session = self._sessions.get(name)
                if session is not None:
                    info = session.to_dict()
                else:
                    project_key = self._target_projects.get(name)
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
        with self._registry_lock.write_lock():
            session = self._sessions.get(name)
            if session is not None:
                handle = session.get_project_handle()
                self._target_projects[name] = handle.get_key()
                return handle.list_programs()

            key = self._get_target_project_key_locked(name)
            metadata_programs = ProjectHandle.list_programs_from_metadata(key[0], key[1])
            if metadata_programs is not None:
                return metadata_programs

            handle = self._get_or_create_project_handle(key[0], key[1])
            return handle.list_programs()

    def load_program(
        self,
        name: str,
        domain_path: str,
    ) -> str:
        with self._registry_lock.write_lock():
            if not domain_path:
                raise ValueError("domain_path を指定してください")
            handle = self._get_target_handle_locked(name)
            new_session = handle.open_program(domain_path)
            loaded_domain_path = new_session.to_dict().get("domain_path") or ""
            had_session = name in self._sessions
            try:
                new_program = new_session.get_program()
                self._core_accessor().initialize(new_program, key=name)
            except Exception:
                self._cleanup_session(
                    name,
                    new_session,
                    handle,
                    remove_registry_entry=False,
                    remove_context=not had_session,
                )
                raise

            old_session = self._sessions.get(name)
            self._sessions[name] = new_session
            self._locks.setdefault(name, threading.RLock())
            self._target_projects[name] = handle.get_key()
            try:
                if old_session is not None:
                    old_session.close()
            finally:
                if handle.is_closed():
                    self._project_handles.pop(handle.get_key(), None)
            return loaded_domain_path

    def import_program(self, name: str, binary_path: str) -> str:
        with self._registry_lock.write_lock():
            if not binary_path:
                raise ValueError("binary_path を指定してください")
            handle = self._get_target_handle_locked(name)
            domain_file = handle.import_program(binary_path)
            self._target_projects[name] = handle.get_key()
            return domain_file.getPathname()

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
                    # checkout前に開いていたactive programはread-only状態のまま残るため、
                    # ここで開き直してshared projectの最新checkout状態を反映させる。
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
            raise ValueError("comment を指定してください")
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
                    raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControlできない状態です")

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
            raise ValueError("message を指定してください")
        with self._registry_lock.write_lock():
            lock = self._lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)

                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)
                if not status.get("is_checked_out"):
                    if auto_checkout and status.get("can_checkout"):
                        checked_out = handle.checkout_program(resolved_domain_path, exclusive=False)
                        if checked_out:
                            self._reload_active_program_after_checkout_locked(name, resolved_domain_path)
                            handle = self._get_target_handle_locked(name)
                        status = handle.get_sync_status(resolved_domain_path)
                        if not status.get("is_checked_out"):
                            if not checked_out:
                                raise RuntimeError("AUTO_CHECKOUT_FAILED: checkoutに失敗しました")
                            raise RuntimeError("AUTO_CHECKOUT_FAILED: checkout後の状態確認に失敗しました")
                    else:
                        raise RuntimeError("NOT_CHECKED_OUT: checkout済みではありません")

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
                    raise RuntimeError("CHECKIN_NOT_ALLOWED: checkinできない状態です")

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
            raise ValueError("on_local_changes は 'abort' または 'discard' を指定してください")
        with self._registry_lock.write_lock():
            lock = self._lock(name)
            with lock:
                handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
                status = handle.get_sync_status(resolved_domain_path)
                self._ensure_versioned_project(status)

                if status.get("modified_since_checkout") and normalized == "abort":
                    raise RuntimeError("LOCAL_CHANGES_EXIST: ローカル変更があるためpullを中止しました")

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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
        with self._registry_lock.write_lock():
            lock = self._lock(name)
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
            handle = self._get_target_handle_locked(name)
            return handle, resolved_domain_path

        session = self._ensure(name)
        handle = session.get_project_handle()
        return handle, self._session_domain_path(session)

    def _is_active_domain_path_locked(self, name: str, domain_path: str) -> bool:
        session = self._sessions.get(name)
        if session is None:
            return False
        return self._session_domain_path(session) == domain_path

    def _save_active_program_if_needed_locked(
        self,
        name: str,
        domain_path: str,
        *,
        handle: ProjectHandle | None = None,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        session = self._sessions.get(name)
        if session is None:
            return False
        program = session.get_program()

        active_handle = handle or session.get_project_handle()
        try:
            active_handle.project.save(program)
        except Exception as exc:
            raise RuntimeError(f"SAVE_FAILED: プログラム保存に失敗しました: {exc}") from exc
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
        handle = self._get_target_handle_locked(name)
        return operation(handle, domain_path)

    def _run_with_reopened_program_locked(
        self,
        name: str,
        operation,
        *,
        save_before_close: bool,
    ):
        session = self._ensure(name)
        handle = session.get_project_handle()
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
        domain_path = self._session_domain_path(session)
        program = session.get_program()
        active_handle: ProjectHandle | None = None

        def _save_hook() -> None:
            handle.project.save(program)

        def _before_close() -> None:
            session.close()
            if handle.is_closed():
                self._project_handles.pop(handle.get_key(), None)

        def _do_operation():
            nonlocal active_handle
            active_handle = self._get_or_create_project_handle(project_location, project_name)
            return operation(active_handle, domain_path)

        def _reopen() -> None:
            nonlocal active_handle
            if active_handle is None:
                active_handle = self._get_or_create_project_handle(project_location, project_name)
            reopened = active_handle.open_program(domain_path)
            try:
                self._core_accessor().initialize(reopened.get_program(), key=name)
                self._sessions[name] = reopened
            except Exception:
                try:
                    reopened.close()
                except Exception:
                    pass
                raise
            finally:
                if active_handle is not None and active_handle.is_closed():
                    self._project_handles.pop(active_handle.get_key(), None)

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
                self._sessions.pop(name, None)
                self._locks.pop(name, None)
                try:
                    self._core_accessor().remove_context(name)
                except Exception:
                    pass
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
                raise RuntimeError("LOCAL_CHANGES_EXIST: ローカル変更があるためpullを中止しました")
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

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        with self._registry_lock.write_lock():
            self._close_session_locked(name, remove_program=remove_program)

    def _close_session_locked(self, name: str, *, remove_program: bool) -> None:
        session = self._sessions.get(name)
        if session is None:
            raise RuntimeError(f"セッション '{name}' は存在しません")
        handle = session.get_project_handle()
        self._cleanup_session(
            name,
            session,
            handle,
            remove_registry_entry=False,
            remove_context=False,
            remove_program=remove_program,
        )
        self._sessions.pop(name, None)
        self._locks.pop(name, None)
        self._target_projects.pop(name, None)
        self._core_accessor().remove_context(name)

    def close_all(self) -> None:
        with self._registry_lock.write_lock():
            names = list(self._sessions.keys())
            for name in names:
                try:
                    self._close_session_locked(name, remove_program=False)
                except Exception:  # noqa: BLE001
                    pass
            self._sessions.clear()
            self._locks.clear()
            self._target_projects.clear()
            for handle in list(self._project_handles.values()):
                try:
                    handle.close()
                except Exception:
                    pass
            self._project_handles.clear()
            self._core_accessor().clear_contexts()

    def _cleanup_session(
        self,
        name: str,
        session: ProgramSession | None,
        handle: ProjectHandle | None,
        *,
        remove_registry_entry: bool,
        remove_context: bool = True,
        remove_program: bool = False,
    ) -> None:
        if remove_registry_entry:
            self._sessions.pop(name, None)
            self._locks.pop(name, None)

        close_error = None
        try:
            if session is not None:
                session.close(remove_program=remove_program)
        except Exception as exc:  # noqa: BLE001
            close_error = exc

        if remove_context:
            self._core_accessor().remove_context(name)

        if handle is not None and handle.is_closed():
            self._project_handles.pop(handle.get_key(), None)

        if close_error is not None:
            raise RuntimeError(f"SESSION_CLOSE_FAILED: {close_error}")

    def has_sessions(self) -> bool:
        with self._registry_lock.read_lock():
            return bool(self._sessions)

    def has_targets(self) -> bool:
        with self._registry_lock.read_lock():
            return bool(self._target_projects)

    def project_lock_key(self, name: str) -> str | None:
        with self._registry_lock.read_lock():
            key = self._target_projects.get(name)
            if key is None:
                session = self._sessions.get(name)
                if session is not None:
                    key = session.get_project_handle().get_key()
            if key is None:
                return None
            return f"{key[0]}::{key[1]}"

    def _get_or_create_project_handle(self, project_location: str, project_name: Optional[str]) -> ProjectHandle:
        key = ProjectHandle.make_key(project_location, project_name)
        handle = self._project_handles.get(key)
        if handle is None or handle.is_closed():
            handle = ProjectHandle(project_location, project_name)
            self._project_handles[key] = handle
        return handle

    def _get_target_project_key_locked(self, name: str) -> tuple[str, str]:
        session = self._sessions.get(name)
        if session is not None:
            key = session.get_project_handle().get_key()
            self._target_projects[name] = key
            return key
        try:
            return self._target_projects[name]
        except KeyError:
            raise RuntimeError(f"ターゲット '{name}' は初期化されていません")

    def _get_target_handle_locked(self, name: str) -> ProjectHandle:
        session = self._sessions.get(name)
        if session is not None:
            handle = session.get_project_handle()
            self._target_projects[name] = handle.get_key()
            return handle
        key = self._get_target_project_key_locked(name)
        return self._get_or_create_project_handle(key[0], key[1])

    @staticmethod
    def _session_domain_path(session: ProgramSession) -> str:
        program = session.get_program()
        domain_file = program.getDomainFile()
        if domain_file is None:
            raise RuntimeError("現在のプログラムにDomainFileがありません")
        path = domain_file.getPathname()
        if not path:
            raise RuntimeError("現在のプログラムのdomain pathを取得できません")
        return path

    @staticmethod
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
        if not status.get("is_versioned"):
            raise RuntimeError("NOT_SHARED_PROJECT: 共有プロジェクトのバージョン管理対象ではありません")

    def _ensure_checkout_for_mutating_command_locked(self, command: str, target: str) -> None:
        if command not in self._checkout_required_commands:
            return
        session = self._sessions.get(target)
        if session is None:
            return
        handle = session.get_project_handle()
        domain_path = self._session_domain_path(session)
        status = handle.get_sync_status(domain_path)
        if not status.get("is_versioned"):
            return
        if status.get("is_checked_out"):
            return
        raise RuntimeError(
            "CHECKOUT_REQUIRED: 共有プロジェクトの更新系操作には checkout が必要です。"
            "先に checkout_project_program を実行してください"
        )

    def call(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        with self._registry_lock.read_lock():
            self._ensure(target)
            lock = self._lock(target)
            with lock:
                self._ensure_checkout_for_mutating_command_locked(command, target)
                result = self._core_accessor().execute(command, params or {}, key=target)
                return self._normalize_result(result)
