# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.26.0,<2",
#     "pyghidra>=2.0.0",
#     "fasteners>=0.19",
# ]
# ///

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import fasteners
import threading
from pydantic import Field
from typing import Annotated, Any, Dict, List, Optional

import pyghidra
import pyghidra.core as pycore
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ghidra_headless.session import ProgramSession, ProjectHandle

logger = logging.getLogger(__name__)

mcp = FastMCP("GhidraMCP Headless")
_core_module = None
_shared_project_sync_tools_registered = False
_PASSWORD_CLIENT_AUTHENTICATOR_CLASS = None
_CLIENT_UTIL_CLASS = None


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: Dict[str, ProgramSession] = {}
        self._locks: Dict[str, threading.RLock] = {}
        self._target_projects: Dict[str, tuple[str, str]] = {}
        self._project_handles: Dict[tuple[str, str], ProjectHandle] = {}
        self._registry_lock = fasteners.ReaderWriterLock()

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
                _core().initialize(program, key=name)
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
                    _core().remove_context(name)
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
            handle = self._get_target_handle_locked(name)
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
                _core().initialize(new_program, key=name)
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

    def get_project_sync_status(self, name: str) -> Dict[str, Any]:
        with self._registry_lock.read_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                handle = session.get_project_handle()
                domain_path = self._session_domain_path(session)
                status = handle.get_sync_status(domain_path)
                return {"target": name, "program": domain_path, **status}

    def checkout_project_program(self, name: str, *, exclusive: bool = False) -> Dict[str, Any]:
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                handle = session.get_project_handle()
                domain_path = self._session_domain_path(session)
                status = handle.get_sync_status(domain_path)
                self._ensure_versioned_project(status)
                if status.get("is_checked_out"):
                    return {
                        "status": "ok",
                        "target": name,
                        "program": domain_path,
                        "checked_out": True,
                        "already_checked_out": True,
                        "exclusive": bool(status.get("is_checked_out_exclusive")),
                    }
                checked_out = handle.checkout_program(domain_path, exclusive=exclusive)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
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
    ) -> Dict[str, Any]:
        text = (comment or "").strip()
        if not text:
            raise ValueError("comment を指定してください")
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                domain_path = self._session_domain_path(session)
                status = self._current_sync_status_locked(name)
                if status.get("is_versioned"):
                    return {
                        "status": "noop",
                        "reason": "already_versioned",
                        "target": name,
                        "program": domain_path,
                        "version": status.get("version"),
                    }
                if not status.get("can_add_to_repository"):
                    raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControlできない状態です")

                self._run_with_reopened_program_locked(
                    name,
                    operation=lambda active_handle, active_domain_path: active_handle.add_program_to_version_control(
                        active_domain_path,
                        text,
                        keep_checked_out=keep_checked_out,
                    ),
                    save_before_close=True,
                )
                updated = self._current_sync_status_locked(name)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
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
    ) -> Dict[str, Any]:
        text = (message or "").strip()
        if not text:
            raise ValueError("message を指定してください")
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                handle = session.get_project_handle()
                domain_path = self._session_domain_path(session)

                status = handle.get_sync_status(domain_path)
                self._ensure_versioned_project(status)
                if not status.get("is_checked_out"):
                    if auto_checkout and status.get("can_checkout"):
                        handle.checkout_program(domain_path, exclusive=False)
                        status = handle.get_sync_status(domain_path)
                    else:
                        raise RuntimeError("NOT_CHECKED_OUT: checkout済みではありません")

                status = handle.get_sync_status(domain_path)
                if status.get("can_merge"):
                    action = self._run_with_reopened_program_locked(
                        name,
                        operation=lambda active_handle, active_domain_path: self._discard_conflict_checkout_operation(
                            active_handle,
                            active_domain_path,
                        ),
                        save_before_close=False,
                    )
                    updated = self._current_sync_status_locked(name)
                    return {
                        "status": "noop",
                        "reason": "conflict_discarded",
                        "target": name,
                        "program": domain_path,
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
                            "program": domain_path,
                            "checked_out": bool(status.get("is_checked_out")),
                            "version": status.get("version"),
                        }
                    raise RuntimeError("CHECKIN_NOT_ALLOWED: checkinできない状態です")

                self._run_with_reopened_program_locked(
                    name,
                    operation=lambda active_handle, active_domain_path: active_handle.commit_program(
                        active_domain_path,
                        text,
                        keep_checked_out=keep_checked_out,
                    ),
                    save_before_close=True,
                )
                updated = self._current_sync_status_locked(name)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
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
    ) -> Dict[str, Any]:
        normalized = (on_local_changes or "abort").strip().lower()
        if normalized not in {"abort", "discard"}:
            raise ValueError("on_local_changes は 'abort' または 'discard' を指定してください")
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                domain_path = self._session_domain_path(session)
                status = self._current_sync_status_locked(name)
                self._ensure_versioned_project(status)

                if status.get("modified_since_checkout") and normalized == "abort":
                    raise RuntimeError("LOCAL_CHANGES_EXIST: ローカル変更があるためpullを中止しました")

                needs_operation = bool(status.get("modified_since_checkout")) or bool(status.get("can_merge"))
                action = {
                    "discarded_local_changes": False,
                    "merged": False,
                }
                if needs_operation:
                    action = self._run_with_reopened_program_locked(
                        name,
                        operation=lambda active_handle, active_domain_path: self._pull_operation(
                            active_handle,
                            active_domain_path,
                            on_local_changes=normalized,
                        ),
                        save_before_close=False,
                    )

                updated = self._current_sync_status_locked(name)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
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
    ) -> Dict[str, Any]:
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                domain_path = self._session_domain_path(session)
                status = self._current_sync_status_locked(name)
                self._ensure_versioned_project(status)
                if not status.get("is_checked_out"):
                    return {
                        "status": "noop",
                        "reason": "not_checked_out",
                        "target": name,
                        "program": domain_path,
                    }

                keep = not bool(discard_local_changes)
                self._run_with_reopened_program_locked(
                    name,
                    operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                        active_domain_path,
                        keep=keep,
                    ),
                    save_before_close=False,
                )
                updated = self._current_sync_status_locked(name)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
                    "checked_out": bool(updated.get("is_checked_out")),
                    "version": updated.get("version"),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }

    def terminate_project_program_checkout(self, name: str, checkout_id: int) -> Dict[str, Any]:
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                handle = session.get_project_handle()
                domain_path = self._session_domain_path(session)
                status = handle.get_sync_status(domain_path)
                self._ensure_versioned_project(status)
                handle.terminate_checkout_program(domain_path, checkout_id)
                updated = handle.get_sync_status(domain_path)
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
                    "checkout_id": int(checkout_id),
                    "active_checkouts": updated.get("checkouts"),
                }

    def reload_project_program(self, name: str) -> Dict[str, Any]:
        with self._registry_lock.write_lock():
            session = self._ensure(name)
            lock = self._lock(name)
            with lock:
                domain_path = self._session_domain_path(session)
                self._run_with_reopened_program_locked(
                    name,
                    operation=lambda active_handle, active_domain_path: None,
                    save_before_close=True,
                )
                return {
                    "status": "ok",
                    "target": name,
                    "program": domain_path,
                    "reloaded": True,
                }

    def _current_sync_status_locked(self, name: str) -> Dict[str, Any]:
        session = self._ensure(name)
        handle = session.get_project_handle()
        domain_path = self._session_domain_path(session)
        return handle.get_sync_status(domain_path)

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

        if save_before_close:
            try:
                handle.project.save(program)
            except Exception:
                pass

        session.close()
        if handle.is_closed():
            self._project_handles.pop(handle.get_key(), None)

        active_handle = self._get_or_create_project_handle(project_location, project_name)
        operation_error = None
        operation_result = None
        try:
            operation_result = operation(active_handle, domain_path)
        except Exception as exc:  # noqa: BLE001
            operation_error = exc

        reopen_error = None
        try:
            reopened = active_handle.open_program(domain_path)
            try:
                _core().initialize(reopened.get_program(), key=name)
                self._sessions[name] = reopened
            except Exception:
                try:
                    reopened.close()
                except Exception:
                    pass
                raise
        except Exception as exc:  # noqa: BLE001
            reopen_error = exc

        if active_handle.is_closed():
            self._project_handles.pop(active_handle.get_key(), None)

        if reopen_error is not None:
            self._sessions.pop(name, None)
            self._locks.pop(name, None)
            try:
                _core().remove_context(name)
            except Exception:
                pass
            if operation_error is not None:
                raise RuntimeError(
                    f"SYNC_OPERATION_FAILED: {operation_error}; REOPEN_FAILED: {reopen_error}"
                ) from operation_error
            raise RuntimeError(f"REOPEN_FAILED: {reopen_error}") from reopen_error

        if operation_error is not None:
            raise operation_error

        return operation_result

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
        session = self._sessions.pop(name, None)
        if session is None:
            raise RuntimeError(f"セッション '{name}' は存在しません")
        self._locks.pop(name, None)
        self._target_projects.pop(name, None)
        handle = session.get_project_handle()
        self._cleanup_session(
            name,
            session,
            handle,
            remove_registry_entry=False,
            remove_program=remove_program,
        )

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
            _core().clear_contexts()

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
            _core().remove_context(name)

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
                return _core().execute(command, params or {}, key=target)

_registry = SessionRegistry()


def _core():
    global _core_module
    if _core_module is None:
        from ghidra_headless.handlers import core as core_module
        _core_module = core_module
    return _core_module


def _password_client_authenticator_class():
    global _PASSWORD_CLIENT_AUTHENTICATOR_CLASS
    if _PASSWORD_CLIENT_AUTHENTICATOR_CLASS is None:
        _PASSWORD_CLIENT_AUTHENTICATOR_CLASS = pycore.JClass("ghidra.framework.client.PasswordClientAuthenticator")
    return _PASSWORD_CLIENT_AUTHENTICATOR_CLASS


def _client_util_class():
    global _CLIENT_UTIL_CLASS
    if _CLIENT_UTIL_CLASS is None:
        _CLIENT_UTIL_CLASS = pycore.JClass("ghidra.framework.client.ClientUtil")
    return _CLIENT_UTIL_CLASS


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, target: str = "default") -> List[str]:
    return _registry.call("list_methods", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_classes", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def decompile_function(name: str, target: str = "default") -> str:
    return _registry.call("decompile_function", {"name": name}, target)


@mcp.tool()
def rename_function(old_name: str, new_name: str, target: str = "default"):
    return _registry.call(
        "rename_function",
        {"oldName": old_name, "newName": new_name},
        target,
    )


@mcp.tool()
def rename_data(address: str, new_name: str, target: str = "default"):
    return _registry.call("rename_data", {"address": address, "newName": new_name}, target)


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_segments", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_imports", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_exports", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_namespaces", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_data_items", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def search_functions_by_name(
    query: str,
    offset: int = 0,
    limit: int = 100,
    target: str = "default",
):
    if not query:
        raise ValueError("queryが必要です")
    return _registry.call(
        "search_functions_by_name",
        {"query": query, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def rename_variable(
    function_name: str,
    old_name: str,
    new_name: str,
    target: str = "default",
):
    return _registry.call(
        "rename_variable",
        {"functionName": function_name, "oldName": old_name, "newName": new_name},
        target,
    )


@mcp.tool()
def get_function_by_address(address: str, target: str = "default"):
    return _registry.call("get_function_by_address", {"address": address}, target)


@mcp.tool(
    description=(
        "List all functions in the loaded program for the target session. "
        "Requires an initialized target with a loaded program; call list_targets first, "
        "then use create_session or load_project_program when needed."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
)
def list_functions(offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call("list_functions", {"offset": offset, "limit": limit}, target)


@mcp.tool()
def decompile_function_by_address(address: str, target: str = "default") -> str:
    return _registry.call("decompile_function_by_address", {"address": address}, target)


@mcp.tool()
def disassemble_function(address: str, target: str = "default"):
    return _registry.call("disassemble_function", {"address": address}, target)


@mcp.tool()
def set_decompiler_comment(address: str, comment: str, target: str = "default"):
    return _registry.call(
        "set_decompiler_comment",
        {"address": address, "comment": comment},
        target,
    )


@mcp.tool()
def set_disassembly_comment(address: str, comment: str, target: str = "default"):
    return _registry.call(
        "set_disassembly_comment",
        {"address": address, "comment": comment},
        target,
    )


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, target: str = "default"):
    return _registry.call(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
        target,
    )


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, target: str = "default"):
    return _registry.call(
        "set_function_prototype",
        {"function_address": function_address, "prototype": prototype},
        target,
    )


@mcp.tool()
def set_local_variable_type(
    function_address: str,
    variable_name: str,
    new_type: str,
    target: str = "default",
):
    return _registry.call(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
        target,
    )


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_xrefs_to", {"address": address, "offset": offset, "limit": limit}, target
    )


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_xrefs_from",
        {"address": address, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "get_function_xrefs",
        {"name": name, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def list_strings(
    offset: int = 0,
    limit: int = 2000,
    filter: str | None = None,
    target: str = "default",
):
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return _registry.call("list_strings", params, target)


@mcp.tool()
def create_struct(
    name: str,
    category: str | None = None,
    size: int = 0,
    members: list[dict] | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"name": name, "size": size}
    if category:
        params["category"] = category
    if members:
        params["members"] = members
    return _registry.call("create_struct", params, target)


@mcp.tool()
def add_struct_members(
    struct_name: str,
    members: list[dict],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"struct_name": struct_name, "members": members}
    if category:
        params["category"] = category
    return _registry.call("add_struct_members", params, target)


@mcp.tool()
def clear_struct(struct_name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"struct_name": struct_name}
    if category:
        params["category"] = category
    return _registry.call("clear_struct", params, target)


@mcp.tool()
def get_struct(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return _registry.call("get_struct", params, target)


@mcp.tool()
def get_data_by_label(label: str, target: str = "default"):
    return _registry.call("get_data_by_label", {"label": label}, target)


@mcp.tool()
def get_bytes(address: str, size: int = 16, target: str = "default"):
    return _registry.call("get_bytes", {"address": address, "size": size}, target)


@mcp.tool()
def search_bytes(pattern: str, offset: int = 0, limit: int = 100, target: str = "default"):
    return _registry.call(
        "search_bytes",
        {"bytes": pattern, "offset": offset, "limit": limit},
        target,
    )


@mcp.tool()
def create_enum(
    name: str,
    category: str | None = None,
    size: int = 4,
    values: list[dict] | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"name": name, "size": size}
    if category:
        params["category"] = category
    if values:
        params["values"] = values
    return _registry.call("create_enum", params, target)


@mcp.tool()
def add_enum_values(
    enum_name: str,
    values: list[dict],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"enum_name": enum_name, "values": values}
    if category:
        params["category"] = category
    return _registry.call("add_enum_values", params, target)


@mcp.tool()
def get_enum(name: str, category: str | None = None, target: str = "default"):
    params: Dict[str, Any] = {"name": name}
    if category:
        params["category"] = category
    return _registry.call("get_enum", params, target)


@mcp.tool()
def set_global_data_type(
    address: str,
    data_type: str,
    length: int | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"address": address, "data_type": data_type}
    if length is not None:
        params["length"] = length
    return _registry.call("set_global_data_type", params, target)


@mcp.tool()
def add_class_members(
    class_name: str,
    members: list[dict],
    parent_namespace: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"class_name": class_name, "members": members}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace
    return _registry.call("add_class_members", params, target)


@mcp.tool()
def remove_class_members(
    class_name: str,
    members: list[str],
    parent_namespace: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"class_name": class_name, "members": members}
    if parent_namespace:
        params["parent_namespace"] = parent_namespace
    return _registry.call("remove_class_members", params, target)


@mcp.tool()
def remove_enum_values(
    enum_name: str,
    values: list[str],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"enum_name": enum_name, "values": values}
    if category:
        params["category"] = category
    return _registry.call("remove_enum_values", params, target)


@mcp.tool()
def remove_struct_members(
    struct_name: str,
    members: list[str],
    category: str | None = None,
    target: str = "default",
):
    params: Dict[str, Any] = {"struct_name": struct_name, "members": members}
    if category:
        params["category"] = category
    return _registry.call("remove_struct_members", params, target)


@mcp.tool()
def set_bytes(address: str, bytes_hex: str, target: str = "default"):
    return _registry.call("set_bytes", {"address": address, "bytes": bytes_hex}, target)


@mcp.tool()
def get_callee(address: str, target: str = "default"):
    return _registry.call("get_callee", {"address": address}, target)


@mcp.tool()
def add_bookmark(
    address: str,
    category: str,
    comment: str,
    type: str,
    target: str = "default",
):
    return _registry.call(
        "add_bookmark",
        {"address": address, "category": category, "comment": comment, "type": type},
        target,
    )


@mcp.tool(
    description=(
        "List registered targets and their state, including project info and whether a program "
        "is loaded (domain_path). Call this before target-scoped operations."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
)
def list_targets() -> List[Dict[str, Optional[str]]]:
    return _registry.list_targets()


@mcp.tool()
def list_project_programs(target: str):
    return _registry.list_programs(target)


@mcp.tool(
    description=(
        "Load or switch a program for an existing target by domain path. "
        "Use this for targets that already exist (including project-only targets) "
        "instead of create_session."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        idempotentHint=False,
    ),
)
def load_project_program(
    target: str,
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
):
    loaded_domain_path = _registry.load_program(target, domain_path=domain_path)
    return {"status": "ok", "target": target, "program": loaded_domain_path}


@mcp.tool(description="Import a binary or Ghidra archive (.gzf) into the current target's project")
def import_program(
    target: str,
    binary_path: Annotated[str, Field(description="Path to the binary or Ghidra archive (.gzf) to import")],
):
    imported_domain_path = _registry.import_program(target, binary_path=binary_path)
    return {"status": "ok", "target": target, "program": imported_domain_path}


@mcp.tool(
    description=(
        "Create a new target session by opening a program in a Ghidra project. "
        "This is non-idempotent and fails if the target already exists. "
        "If the target already exists, use load_project_program."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        idempotentHint=False,
    ),
)
def create_session(
    target: str,
    project_location: Annotated[str, Field(description="Path to the Ghidra project (.gpr) file or project directory")],
    domain_path: Annotated[str, Field(description="Domain path of the program to open (e.g. /folder/program)")],
    project_name: Annotated[str | None, Field(description="Project name; required when project_location is a directory")] = None,
):
    try:
        _registry.create_session(
            target,
            project_location=project_location,
            project_name=project_name,
            domain_path=domain_path,
        )
        return {"status": "ok", "target": target}
    except Exception as exc:
        raise RuntimeError(f"セッション '{target}' の作成に失敗しました: {exc}")


@mcp.tool()
def close_session(target: str):
    try:
        _registry.close_session(target)
        return {"status": "ok", "target": target}
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"セッション '{target}' のクローズに失敗しました: {exc}")


@mcp.tool()
def close_session_and_remove_program(target: str):
    try:
        _registry.close_session(target, remove_program=True)
        return {"status": "ok", "target": target}
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"セッション '{target}' のクローズ/削除に失敗しました: {exc}")


def get_project_sync_status(target: str):
    return _registry.get_project_sync_status(target)


def checkout_project_program(
    target: str,
    exclusive: Annotated[bool, Field(description="Trueの場合は排他的checkoutを試行")] = False,
):
    return _registry.checkout_project_program(target, exclusive=exclusive)


def add_project_program_to_version_control(
    target: str,
    comment: Annotated[str, Field(description="バージョン管理追加時のコメント")],
    keep_checked_out: Annotated[bool, Field(description="追加後もcheckout状態を維持する")] = False,
):
    return _registry.add_project_program_to_version_control(
        target,
        comment=comment,
        keep_checked_out=keep_checked_out,
    )


def commit_project_program(
    target: str,
    message: Annotated[str, Field(description="check-in時のコメント")],
    keep_checked_out: Annotated[bool, Field(description="check-in後もcheckout状態を維持する")] = False,
    auto_checkout: Annotated[bool, Field(description="未checkout時に自動checkoutを試行する")] = True,
):
    return _registry.commit_project_program(
        target,
        message=message,
        keep_checked_out=keep_checked_out,
        auto_checkout=auto_checkout,
    )


def pull_project_program(
    target: str,
    on_local_changes: Annotated[
        str,
        Field(description="ローカル変更がある場合の挙動: abort または discard"),
    ] = "abort",
):
    return _registry.pull_project_program(target, on_local_changes=on_local_changes)


def undo_checkout_project_program(
    target: str,
    discard_local_changes: Annotated[bool, Field(description="Trueならローカル変更を破棄")] = True,
):
    return _registry.undo_checkout_project_program(
        target,
        discard_local_changes=discard_local_changes,
    )


def terminate_project_program_checkout(
    target: str,
    checkout_id: Annotated[int, Field(description="終了したいcheckout id")],
):
    return _registry.terminate_project_program_checkout(target, checkout_id=checkout_id)


def reload_project_program(target: str):
    return _registry.reload_project_program(target)


def register_shared_project_sync_tools() -> None:
    global _shared_project_sync_tools_registered
    if _shared_project_sync_tools_registered:
        return

    mcp.add_tool(
        get_project_sync_status,
        description="Get shared-project version-control status for the target program",
    )
    mcp.add_tool(
        checkout_project_program,
        description="Checkout the target program in a shared project",
    )
    mcp.add_tool(
        add_project_program_to_version_control,
        description="Add the target program to shared-project version control",
    )
    mcp.add_tool(
        commit_project_program,
        description="Check-in changes of the target program to the shared project server",
    )
    mcp.add_tool(
        pull_project_program,
        description="Pull/merge latest remote changes for the target program",
    )
    mcp.add_tool(
        undo_checkout_project_program,
        description="Undo checkout for the target program (optionally discard local changes)",
    )
    mcp.add_tool(
        terminate_project_program_checkout,
        description="Terminate a stale checkout by checkout id for the target program",
    )
    mcp.add_tool(
        reload_project_program,
        description="Reload the target program by closing and reopening the current domain path",
    )
    _shared_project_sync_tools_registered = True


def configure_logging(level: int) -> None:
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def _parse_session_definition(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"セッション定義に'='が含まれていません: {part}")
        key, value = part.split("=", 1)
        result[key.strip()] = value.strip()
    if "name" not in result:
        raise ValueError("session定義にはname=...が必須です")
    if "project_location" not in result:
        raise ValueError("session定義にはproject_locationが必要です")
    return result


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(description="PyGhidraベースのGhidra MCPサーバー")
    parser.add_argument("--project-location", help="デフォルトセッション用のGhidraプロジェクトディレクトリ")
    parser.add_argument("--project-name", help="デフォルトセッションのプロジェクト名")
    parser.add_argument("--domain-path", help="デフォルトセッションのドメインパス (例: /folder/program)")
    parser.add_argument("--target-name", default="default", help="デフォルトセッションのターゲット名")
    parser.add_argument(
        "--session",
        action="append",
        metavar="name=...,project_location=...,domain_path=...",
        help="追加セッション定義をカンマ区切りで指定 (繰り返し可)",
    )
    parser.add_argument("--ghidra-path", help="Ghidraインストールパス。未指定時は環境変数GHIDRA_INSTALL_DIRを利用")
    parser.add_argument(
        "--ghidra-server-user",
        help="shared project接続時に利用するGhidra serverユーザー名",
    )
    parser.add_argument(
        "--ghidra-server-password-env",
        help="Ghidra serverパスワードを保持した環境変数名",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "http", "streamable-http"],
        help="MCPのトランスポート",
    )
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="SSE/Streamable HTTPホスト (stdioでは未使用)")
    parser.add_argument("--mcp-port", type=int, help="SSE/Streamable HTTPポート (stdioでは未使用)")
    parser.add_argument("--mcp-path", type=str, default="/mcp", help="Streamable HTTPパス (例: /mcp)")
    parser.add_argument(
        "--enable-shared-project-sync",
        action="store_true",
        help="shared project向けのcommit/pull/checkout系ツールを公開する",
    )
    parser.add_argument("--log-level", default="INFO", help="ログレベル")
    return parser.parse_args(argv)


def _normalize_transport(transport: str) -> str:
    return "streamable-http" if transport == "http" else transport


def _normalize_streamable_http_path(path: str) -> str:
    normalized = (path or "").strip()
    if not normalized:
        return "/mcp"
    if not normalized.startswith("/"):
        return "/" + normalized
    return normalized


def configure_ghidra_server_auth(args) -> None:
    username = (getattr(args, "ghidra_server_user", None) or "").strip()
    password_env_name = (getattr(args, "ghidra_server_password_env", None) or "").strip()
    if not username and not password_env_name:
        return
    if not username or not password_env_name:
        raise ValueError("--ghidra-server-user と --ghidra-server-password-env はセットで指定してください")

    password = os.environ.get(password_env_name)
    if password is None:
        raise ValueError(f"環境変数 '{password_env_name}' が未設定です")
    if password == "":
        raise ValueError(f"環境変数 '{password_env_name}' が空です")

    authenticator = _password_client_authenticator_class()(username, password)
    _client_util_class().setClientAuthenticator(authenticator)
    logger.info(
        "Ghidra server認証を設定しました (user=%s, password_env=%s)",
        username,
        password_env_name,
    )


def main(argv: list[str] | None = None) -> int:
    global _core_module
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    configure_logging(getattr(logging, args.log_level.upper(), logging.INFO))
    logger.info("PyGhidra MCPサーバーを起動します")

    ghidra_path = args.ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_path:
        logger.debug("pyghidra.start install_dir=%s", ghidra_path)
        pyghidra.start(install_dir=ghidra_path)
    else:
        pyghidra.start()

    try:
        configure_ghidra_server_auth(args)
    except Exception as exc:  # noqa: BLE001
        logger.error("Ghidra server認証設定に失敗: %s", exc)
        return 1

    if args.session:
        for definition in args.session:
            try:
                config = _parse_session_definition(definition)
                domain_path = config.get("domain_path")
                if domain_path:
                    _registry.create_session(
                        config["name"],
                        project_location=config.get("project_location"),
                        project_name=config.get("project_name"),
                        domain_path=domain_path,
                    )
                    logger.info("セッション '%s' をロードしました", config["name"])
                else:
                    _registry.register_target(
                        config["name"],
                        project_location=config.get("project_location"),
                        project_name=config.get("project_name"),
                    )
                    logger.info("ターゲット '%s' をプロジェクトのみで登録しました", config["name"])
            except Exception as exc:  # noqa: BLE001
                logger.error("セッション定義 '%s' の処理中にエラー: %s", definition, exc)
                _registry.close_all()
                return 1

    if args.project_location:
        try:
            if args.domain_path:
                _registry.create_session(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                    domain_path=args.domain_path,
                )
                logger.info("デフォルトターゲット '%s' をロードしました", args.target_name)
            else:
                _registry.register_target(
                    args.target_name,
                    project_location=args.project_location,
                    project_name=args.project_name,
                )
                logger.info(
                    "デフォルトターゲット '%s' をプロジェクトのみで登録しました（program未ロード）",
                    args.target_name,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("デフォルトセッション初期化に失敗: %s", exc)
            _registry.close_all()
            return 1

    if not _registry.has_targets():
        logger.error("少なくとも1つのターゲットを --session または --project-location で指定してください")
        return 1

    _core_module = _core()

    def _shutdown_handler(signum, frame):
        logger.info("シグナル %s を受信したため終了処理を開始します", signum)
        _registry.close_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    if args.enable_shared_project_sync:
        register_shared_project_sync_tools()
        logger.info("shared project同期ツールを有効化しました")

    transport = _normalize_transport(args.transport)
    if transport == "sse":
        configure_mcp_for_sse(args)
    elif transport == "streamable-http":
        configure_mcp_for_streamable_http(args)

    try:
        mcp.run(transport=transport)
    finally:
        _registry.close_all()
    return 0


def configure_mcp_for_sse(args) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    logger.info("MCPをSSEモードで起動: http://%s:%s/sse", mcp.settings.host, mcp.settings.port)


def configure_mcp_for_streamable_http(args) -> None:
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    mcp.settings.log_level = args.log_level.upper()
    mcp.settings.host = args.mcp_host
    mcp.settings.port = args.mcp_port or 8081
    mcp.settings.streamable_http_path = _normalize_streamable_http_path(args.mcp_path)
    logger.info(
        "MCPをStreamable HTTPモードで起動: http://%s:%s%s",
        mcp.settings.host,
        mcp.settings.port,
        mcp.settings.streamable_http_path,
    )


if __name__ == "__main__":
    sys.exit(main())
