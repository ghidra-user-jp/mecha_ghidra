"""Shared project sync operations for runtime backend."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import pathlib
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any, Dict

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.infrastructure.ghidra_adapter.program_lease import ProgramLease
from ghidra_headless.session import ProjectHandle, path_utils

from .session_store import RuntimeSessionStore

logger = logging.getLogger(__name__)


class RuntimeSyncOperations:
    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    @contextlib.contextmanager
    def _target_operation(self, name: str, *, exclusive: bool = False) -> Iterator[None]:
        operation_lock = (
            self._store.operation_lock.write_lock()
            if exclusive
            else self._store.operation_lock.read_lock()
        )
        with operation_lock:
            with self._store.registry_lock.write_lock():
                lock = self._store.ensure_lock(name)
                project_key = self._store.get_target_project_key_locked(name)
                requested_handle = self._store.get_target_handle_locked(name)
                project_keys = {project_key}
                for candidate_key, candidate_handle in self._store.project_handles.items():
                    try:
                        if candidate_handle.is_closed():
                            continue
                        if self._handles_share_project_identity(requested_handle, candidate_handle):
                            project_keys.add(candidate_key)
                    except Exception as exc:  # noqa: BLE001
                        raise RuntimeError(
                            "SYNC_STATUS_UNAVAILABLE: failed to determine project lock identity: "
                            f"{exc}"
                        ) from exc
                project_locks = [
                    self._store.ensure_project_lock(key)
                    for key in sorted(project_keys, key=lambda item: (str(item[0]), str(item[1])))
                ]
            with lock:
                with contextlib.ExitStack() as stack:
                    for project_lock in project_locks:
                        stack.enter_context(project_lock)
                    yield

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path)
            status = self._overlay_active_program_sync_status_locked(
                active_target,
                resolved_domain_path,
                status=status,
            )
            return {"target": name, "program": resolved_domain_path, **status}

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            if active_target is not None and not status.get("is_versioned"):
                self._refresh_loaded_target_sync_state_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                )
                with self._store.registry_lock.write_lock():
                    handle = self._store.get_target_handle_locked(name)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = handle.get_sync_status(resolved_domain_path)
            self._ensure_versioned_project(status)
            if status.get("is_checked_out"):
                if active_target is not None and not self._active_program_is_changed_locked(
                    active_target,
                    resolved_domain_path,
                ):
                    self._reload_loaded_target_after_checkout_locked(
                        handle=handle,
                        domain_path=resolved_domain_path,
                    )
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "checked_out": True,
                    "already_checked_out": True,
                    "exclusive": bool(status.get("is_checked_out_exclusive")),
                }
            if active_target is not None and self._active_program_is_changed_locked(active_target, resolved_domain_path):
                raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
            checked_out = handle.checkout_program(resolved_domain_path, exclusive=exclusive)
            if not checked_out:
                mode = "exclusive " if exclusive else ""
                raise RuntimeError(
                    "CHECKOUT_UNAVAILABLE: "
                    f"the requested {mode}checkout was refused by the repository"
                )
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(name, resolved_domain_path)
            self._reload_after_completed_checkout_locked(
                handle=handle,
                domain_path=resolved_domain_path,
                operation="checkout_project_program",
            )
            updated = self._read_postcondition_sync_status_locked(
                name,
                domain_path=resolved_domain_path,
                operation="checkout_project_program",
            )
            if not updated.get("is_checked_out"):
                raise self._partial_success_error(
                    operation="checkout_project_program",
                    message="repository accepted checkout but post-checkout state is not checked out",
                )
            return {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "checked_out": True,
                "already_checked_out": False,
                "exclusive": bool(updated.get("is_checked_out_exclusive")),
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
            raise ValueError("comment is required")
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            if status.get("is_versioned"):
                return {
                    "status": "noop",
                    "reason": "already_versioned",
                    "target": name,
                    "program": resolved_domain_path,
                    "version": status.get("version"),
                }
            if not status.get("can_add_to_repository"):
                raise RuntimeError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed")

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
            updated = self._read_postcondition_sync_status_locked(
                name,
                domain_path=resolved_domain_path,
                operation="add_project_program_to_version_control",
            )
            if not updated.get("is_versioned"):
                raise self._partial_success_error(
                    operation="add_project_program_to_version_control",
                    message="add operation returned but the program is still not versioned",
                )
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
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        text = (message or "").strip()
        if not text:
            raise ValueError("message is required")
        conflict_action = (on_conflict or "abort").strip().lower()
        if conflict_action not in {"abort", "discard"}:
            raise ValueError("on_conflict must be either 'abort' or 'discard'")
        with self._target_operation(name):
            auto_checkout_created = False
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)

            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            if active_target is not None and not status.get("is_versioned"):
                self._refresh_loaded_target_sync_state_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                )
                with self._store.registry_lock.write_lock():
                    handle = self._store.get_target_handle_locked(name)
                active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                status = handle.get_sync_status(resolved_domain_path)
            if not status.get("is_versioned") and status.get("can_add_to_repository"):
                return {
                    "status": "noop",
                    "reason": "not_versioned",
                    "target": name,
                    "program": resolved_domain_path,
                    "required_action": "add_project_program_to_version_control",
                    "can_add_to_repository": True,
                    "message": (
                        "Program is not under version control; "
                        "run add_project_program_to_version_control before commit_project_program."
                    ),
                }
            self._ensure_versioned_project(status)
            status = self._overlay_active_program_sync_status_locked(
                active_target,
                resolved_domain_path,
                status=status,
            )
            if not status.get("is_checked_out"):
                if auto_checkout and status.get("can_checkout"):
                    if active_target is not None and self._active_program_is_changed_locked(
                        active_target,
                        resolved_domain_path,
                    ):
                        raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
                    checked_out = handle.checkout_program(resolved_domain_path, exclusive=False)
                    if not checked_out:
                        raise RuntimeError("CHECKOUT_UNAVAILABLE: automatic checkout was refused")
                    auto_checkout_created = True
                    self._reload_after_completed_checkout_locked(
                        handle=handle,
                        domain_path=resolved_domain_path,
                        operation="commit_project_program.auto_checkout",
                    )
                    with self._store.registry_lock.write_lock():
                        handle = self._store.get_target_handle_locked(name)
                    status = self._read_postcondition_sync_status_locked(
                        name,
                        domain_path=resolved_domain_path,
                        operation="commit_project_program.auto_checkout",
                    )
                    status = self._overlay_active_program_sync_status_locked(
                        active_target,
                        resolved_domain_path,
                        status=status,
                    )
                    if not status.get("is_checked_out"):
                        raise self._partial_success_error(
                            operation="commit_project_program.auto_checkout",
                            message="automatic checkout returned but post-checkout state is not checked out",
                        )
                else:
                    raise RuntimeError("NOT_CHECKED_OUT: program is not checked out")

            conflict_result = self._handle_commit_conflict_locked(
                name,
                resolved_domain_path,
                active_target=active_target,
                status=status,
                conflict_action=conflict_action,
                auto_checkout_created=auto_checkout_created,
            )
            if conflict_result is not None:
                return conflict_result

            saved_active_program = False
            if active_target is not None:
                saved_active_program = self._save_active_program_if_needed_locked(
                    active_target,
                    resolved_domain_path,
                    handle=handle,
                )
                if self._refresh_active_versioned_program_state_locked(
                    active_target,
                    resolved_domain_path,
                    status=status,
                    save_before_close=False,
                    force=saved_active_program,
                ):
                    with self._store.registry_lock.write_lock():
                        handle = self._store.get_target_handle_locked(name)
            # This refresh still precedes check-in.  Do not label a failure here
            # as a completed/partial commit: callers may safely retry after the
            # repository connection recovers because commit_program() has not run.
            handle, resolved_domain_path = self._resolve_sync_target_locked(
                name,
                resolved_domain_path,
            )
            status = self._get_refreshed_sync_status_locked(
                handle,
                resolved_domain_path,
                require_refresh=True,
            )
            status = self._overlay_active_program_sync_status_locked(
                active_target,
                resolved_domain_path,
                status=status,
            )
            conflict_result = self._handle_commit_conflict_locked(
                name,
                resolved_domain_path,
                active_target=active_target,
                status=status,
                conflict_action=conflict_action,
                auto_checkout_created=auto_checkout_created,
            )
            if conflict_result is not None:
                return conflict_result
            if not status.get("can_checkin"):
                if not status.get("modified_since_checkout"):
                    if auto_checkout_created:
                        status = self._rollback_auto_checkout_locked(
                            name,
                            domain_path=resolved_domain_path,
                        )
                    return {
                        "status": "noop",
                        "reason": "not_modified",
                        "target": name,
                        "program": resolved_domain_path,
                        "checked_out": bool(status.get("is_checked_out")),
                        "version": status.get("version"),
                    }
                if auto_checkout_created:
                    self._rollback_auto_checkout_locked(name, domain_path=resolved_domain_path)
                raise RuntimeError("CHECKIN_NOT_ALLOWED: checkin is not allowed")

            previous_version = status.get("version")
            previous_latest_version = status.get("latest_version")
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
            updated = self._read_postcondition_sync_status_locked(
                name,
                domain_path=resolved_domain_path,
                operation="commit_project_program",
            )
            self._verify_commit_postcondition(
                updated,
                previous_version=previous_version,
                previous_latest_version=previous_latest_version,
            )
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
            raise ValueError("on_local_changes must be either 'abort' or 'discard'")
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
            loaded_version = self._active_program_version_locked(active_target, resolved_domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            active_program_changed = (
                active_target is not None
                and self._active_program_is_changed_locked(active_target, resolved_domain_path)
            )

            if status.get("is_hijacked"):
                if normalized == "abort":
                    raise RuntimeError(
                        "HIJACKED_PROGRAM: pull aborted because a private local file shadows the "
                        "repository file; pass on_local_changes='discard' to remove the local shadow"
                    )
                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=self._discard_hijacked_file_operation,
                    save_before_close=False,
                )
                updated = self._read_postcondition_sync_status_locked(
                    name,
                    domain_path=resolved_domain_path,
                    operation="pull_project_program.discard_hijack",
                )
                if updated.get("is_hijacked") or not updated.get("is_versioned"):
                    raise self._partial_success_error(
                        operation="pull_project_program.discard_hijack",
                        message="local hijacked file was removed but repository state was not restored",
                    )
                self._ensure_latest_version_postcondition(
                    updated,
                    operation="pull_project_program.discard_hijack",
                    operation_completed=True,
                )
                return {
                    "status": "ok",
                    "target": name,
                    "program": resolved_domain_path,
                    "updated": True,
                    "merged": False,
                    "discarded_local_changes": True,
                    "discarded_hijacked_file": True,
                    "followed_latest": True,
                    "reloaded": active_target is not None,
                    "version": updated.get("version"),
                    "latest_version": updated.get("latest_version"),
                    "is_latest_version": bool(updated.get("is_latest_version")),
                }

            self._ensure_versioned_project(status)
            status = self._overlay_active_program_sync_status_locked(
                active_target,
                resolved_domain_path,
                status=status,
            )

            if (status.get("modified_since_checkout") or active_program_changed) and normalized == "abort":
                raise RuntimeError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")

            needs_operation = bool(status.get("modified_since_checkout")) or bool(status.get("can_merge"))
            discarded_unsaved_active_changes = (
                normalized == "discard"
                and active_target is not None
                and active_program_changed
            )
            action = {
                "discarded_local_changes": False,
                "merged": False,
                "followed_latest": False,
                "reloaded": False,
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
                if discarded_unsaved_active_changes:
                    action["discarded_local_changes"] = True
                action["reloaded"] = active_target is not None
            elif active_target is not None:
                # ProjectData.refresh() can advance folder metadata while the already-open
                # Program object remains pinned to the old version.  Reopening is the only
                # reliable way to make read APIs observe the new server contents.
                self._run_sync_operation_for_domain_locked(
                    name,
                    resolved_domain_path,
                    operation=lambda _active_handle, _active_domain_path: None,
                    save_before_close=False,
                )
                action["reloaded"] = True
                # Ghidra may advance DomainFile metadata before the open Program
                # object's contents are refreshed, so version-number comparison is
                # not reliable here.  A successful close/reopen is itself the
                # operation that makes the active object follow repository latest.
                action["followed_latest"] = True
                if discarded_unsaved_active_changes:
                    action["discarded_local_changes"] = True

            if needs_operation or active_target is not None:
                updated = self._read_postcondition_sync_status_locked(
                    name,
                    domain_path=resolved_domain_path,
                    operation="pull_project_program",
                )
            else:
                # An unloaded, already-current program is a true no-op.  A
                # second refresh failure must not claim that a remote operation
                # completed or discourage a safe retry.
                handle, resolved_domain_path = self._resolve_sync_target_locked(
                    name,
                    resolved_domain_path,
                )
                updated = self._get_refreshed_sync_status_locked(
                    handle,
                    resolved_domain_path,
                    require_refresh=True,
                )
            self._ensure_latest_version_postcondition(
                updated,
                operation="pull_project_program",
                operation_completed=bool(needs_operation or active_target is not None),
            )
            current_version = updated.get("version")
            if (
                action["reloaded"]
                and loaded_version is not None
                and current_version is not None
                and int(loaded_version) != int(current_version)
            ):
                action["followed_latest"] = True
            return {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "updated": bool(action["merged"] or action["discarded_local_changes"] or action["followed_latest"]),
                "merged": bool(action["merged"]),
                "discarded_local_changes": bool(action["discarded_local_changes"]),
                "followed_latest": bool(action["followed_latest"]),
                "reloaded": bool(action["reloaded"]),
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
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            self._ensure_versioned_project(status)
            status = self._overlay_active_program_sync_status_locked(
                active_target,
                resolved_domain_path,
                status=status,
            )
            if not status.get("is_checked_out"):
                return {
                    "status": "noop",
                    "reason": "not_checked_out",
                    "target": name,
                    "program": resolved_domain_path,
                }

            was_active = active_target is not None
            has_local_changes = bool(status.get("modified_since_checkout"))
            if active_target is not None:
                has_local_changes = has_local_changes or self._active_program_is_changed_locked(
                    active_target,
                    resolved_domain_path,
                )
            # Ghidra's undoCheckout(keep=True) renames the local checkout to a
            # .keep file even when it is clean.  Only request keep when there is
            # actually something to preserve.
            keep = not bool(discard_local_changes) and has_local_changes
            keep_path_resolver: Callable[[ProjectHandle, str], str] | None = None
            existing_program_paths: set[str] | None = None
            if keep:
                existing_program_paths = self._list_program_paths_locked(handle)

            if keep and was_active:

                def resolve_keep_path(active_handle, active_domain_path):  # noqa: ANN001
                    assert existing_program_paths is not None
                    return self._resolve_new_keep_domain_path(
                        active_handle,
                        active_domain_path,
                        existing_program_paths,
                    )

                keep_path_resolver = resolve_keep_path

            self._run_sync_operation_for_domain_locked(
                name,
                resolved_domain_path,
                operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                    active_domain_path,
                    keep=keep,
                ),
                save_before_close=keep,
                reopen_domain_path_resolver=keep_path_resolver,
            )
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(name, resolved_domain_path)
            updated = self._read_postcondition_sync_status_locked(
                name,
                domain_path=resolved_domain_path,
                operation="undo_checkout_project_program",
            )
            if updated.get("is_checked_out"):
                raise self._partial_success_error(
                    operation="undo_checkout_project_program",
                    message="undo checkout returned but the program is still checked out",
                )
            kept_program: str | None = None
            if keep and not was_active:
                assert existing_program_paths is not None
                try:
                    kept_program = self._resolve_new_keep_domain_path(
                        handle,
                        resolved_domain_path,
                        existing_program_paths,
                    )
                except Exception as exc:  # noqa: BLE001
                    raise self._partial_success_error(
                        operation="undo_checkout_project_program",
                        message=(
                            "undo checkout completed with keep=True, but the preserved .keep "
                            f"file could not be identified: {exc}"
                        ),
                    ) from exc
            result = {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "checked_out": bool(updated.get("is_checked_out")),
                "version": updated.get("version"),
                "is_latest_version": bool(updated.get("is_latest_version")),
            }
            if keep and was_active:
                with self._store.registry_lock.read_lock():
                    session = self._store.sessions.get(active_target)
                if session is not None:
                    active_domain_path = self._store.session_domain_path(session)
                    if active_domain_path != resolved_domain_path:
                        kept_program = active_domain_path
            if kept_program is not None:
                result["kept_program"] = kept_program
            return result

    def terminate_project_program_checkout(
        self,
        name: str,
        checkout_id: int,
        *,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        # Terminating a checkout is destructive repository state mutation.  Hold
        # the global writer lock so another local-cache target cannot be created
        # after the cross-cache active-checkout guard has taken its snapshot.
        with self._target_operation(name, exclusive=True):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            self._ensure_versioned_project(status)
            self._ensure_checkout_status_consistent(
                status,
                context=f"target '{name}'",
            )
            active_checkout_status = status.get("checkout_status") or {}
            active_checkout_id = active_checkout_status.get("checkout_id")
            is_local_checkout = active_checkout_id is not None and int(active_checkout_id) == int(checkout_id)
            if not self._status_contains_checkout_id(status, checkout_id):
                raise RuntimeError(
                    f"CHECKOUT_NOT_FOUND: checkout_id {int(checkout_id)} is not active for "
                    f"{resolved_domain_path}"
                )
            loaded_checkout_owner = None
            if not is_local_checkout:
                loaded_checkout_owner = self._find_loaded_checkout_owner_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                    checkout_id=checkout_id,
                )
            if is_local_checkout or loaded_checkout_owner is not None:
                raise RuntimeError(
                    "UNSAFE_ACTIVE_CHECKOUT_TERMINATE: terminating the active checkout would hijack the local file; "
                    "use undo_checkout_project_program instead"
                )
            handle.terminate_checkout_program(resolved_domain_path, checkout_id)
            updated = self._read_postcondition_sync_status_locked(
                name,
                domain_path=resolved_domain_path,
                operation="terminate_project_program_checkout",
            )
            if self._status_contains_checkout_id(updated, checkout_id):
                raise self._partial_success_error(
                    operation="terminate_project_program_checkout",
                    message=(
                        "terminate checkout returned but checkout_id "
                        f"{int(checkout_id)} is still active"
                    ),
                )
            return {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "checkout_id": int(checkout_id),
                "active_checkouts": updated.get("checkouts"),
            }

    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
        allow_non_atomic_versioned_delete: bool = False,
    ) -> Dict[str, Any]:
        if not (domain_path or "").strip():
            raise ValueError("domain_path is required")
        # The loaded-target check and delete must be one atomic local-runtime
        # critical section.  Reader mode lets create_session() for another local
        # cache slip between them and open the file immediately before deletion.
        with self._target_operation(name, exclusive=True):
            with self._store.registry_lock.write_lock():
                handle = self._store.get_target_handle_locked(name)
            resolved_domain_path = self._normalize_domain_path_locked(handle, domain_path)
            confirmation = (confirm or "").strip()
            if confirmation != resolved_domain_path:
                raise ValueError(
                    "confirm must exactly match the normalized domain_path "
                    f"({resolved_domain_path})"
                )

            active_target = self._find_loaded_target_across_shared_project_locked(
                handle=handle,
                domain_path=resolved_domain_path,
            )
            if active_target is not None:
                details = {
                    "operation": "delete_shared_project_file",
                    "target": name,
                    "domain_path": resolved_domain_path,
                }
                if active_target != name:
                    details["owner_target"] = active_target
                raise DomainError(
                    code=ErrorCode.TARGET_ALREADY_LOADED,
                    message=f"TARGET_ALREADY_LOADED: program already loaded: {resolved_domain_path}",
                    hint="Close the loaded target before deleting the shared project file",
                    retryable=False,
                    details=details,
                )

            status = self._get_refreshed_sync_status_locked(
                handle,
                resolved_domain_path,
                require_refresh=True,
            )
            was_versioned = bool(status.get("is_versioned"))
            latest_version = status.get("latest_version")
            version = status.get("version")
            self._ensure_delete_allowed(status, allow_private=allow_private)
            if was_versioned and not allow_non_atomic_versioned_delete:
                raise RuntimeError(
                    "UNSAFE_VERSIONED_DELETE: Ghidra does not provide an atomic compare-and-delete "
                    "operation for versioned files; pass allow_non_atomic_versioned_delete=true "
                    "only after excluding concurrent repository writers"
                )
            if was_versioned and expected_latest_version is None:
                raise ValueError(
                    "expected_latest_version is required when allow_non_atomic_versioned_delete=true"
                )
            if expected_latest_version is not None:
                expected = int(expected_latest_version)
                if expected < 1:
                    raise ValueError("expected_latest_version must be >= 1")
                if latest_version is None or int(latest_version) != expected:
                    raise RuntimeError(
                        "LATEST_VERSION_MISMATCH: delete aborted because latest_version "
                        f"is {latest_version}, expected {expected}"
                    )
            try:
                delete_result = handle.delete_domain_file(resolved_domain_path)
            except Exception as exc:
                if str(exc).startswith("DELETE_POSTCONDITION_FAILED:"):
                    raise self._partial_success_error(
                        operation="delete_shared_project_file",
                        message=str(exc),
                    ) from exc
                raise
            if delete_result.get("deleted_verified") is False:
                raise self._partial_success_error(
                    operation="delete_shared_project_file",
                    message="delete returned but the domain path still exists",
                )
            with self._store.registry_lock.write_lock():
                self._store.clear_dirty_program(name, resolved_domain_path)
            return {
                "status": "ok",
                "target": name,
                "program": resolved_domain_path,
                "domain_path": resolved_domain_path,
                "deleted": True,
                "content_type": delete_result.get("content_type"),
                "was_versioned": was_versioned,
                "version": version,
                "latest_version": latest_version,
                "atomic_version_guard": not was_versioned,
            }

    def reload_project_program(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            if self._is_active_domain_path_locked(name, resolved_domain_path):
                save_before_close = self._active_program_is_changed_locked(name, resolved_domain_path)
                self._run_with_reopened_program_locked(
                    name,
                    operation=lambda _active_handle, _active_domain_path: None,
                    save_before_close=save_before_close,
                )
            else:
                owner_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
                if owner_target is not None:
                    details = {
                        "operation": "reload_project_program",
                        "target": name,
                        "domain_path": resolved_domain_path,
                    }
                    if owner_target != name:
                        details["owner_target"] = owner_target
                    raise DomainError(
                        code=ErrorCode.TARGET_ALREADY_LOADED,
                        message=f"TARGET_ALREADY_LOADED: program already loaded: {resolved_domain_path}",
                        hint="Use the existing target directly instead of reloading the same program",
                        retryable=False,
                        details=details,
                    )
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
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            self._ensure_versioned_project(self._get_refreshed_sync_status_locked(handle, resolved_domain_path))
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
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            self._ensure_versioned_project(self._get_refreshed_sync_status_locked(handle, resolved_domain_path))
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

    def _get_refreshed_sync_status_locked(
        self,
        handle: ProjectHandle,
        domain_path: str,
        *,
        require_refresh: bool = False,
    ) -> Dict[str, Any]:
        self._refresh_project_sync_state_locked(handle, required=require_refresh)
        return handle.get_sync_status(domain_path)

    def _overlay_active_program_sync_status_locked(
        self,
        active_target: str | None,
        domain_path: str,
        *,
        status: Dict[str, Any],
    ) -> Dict[str, Any]:
        if active_target is None:
            return status
        if not status.get("is_versioned"):
            return status
        if not status.get("is_checked_out"):
            return status
        if not self._active_program_is_changed_locked(active_target, domain_path):
            return status

        updated = dict(status)
        updated["modified_since_checkout"] = True
        if not updated.get("can_merge") and not updated.get("is_hijacked"):
            updated["can_checkin"] = True
        return updated

    def _active_program_is_changed_locked(self, name: str, domain_path: str) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        with self._store.registry_lock.read_lock():
            runtime_dirty = self._store.is_dirty_program(name, domain_path)
            session = self._store.sessions.get(name)
        if runtime_dirty:
            return True
        if session is None:
            return False
        program = session.get_program()
        try:
            return bool(program.isChanged())
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "failed to determine active program dirty state for target '%s'; assuming changed: %s",
                name,
                exc,
            )
            return True

    def _active_program_version_locked(self, name: str | None, domain_path: str) -> int | None:
        if name is None or not self._is_active_domain_path_locked(name, domain_path):
            return None
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            return None
        try:
            domain_file = session.get_program().getDomainFile()
            get_version = getattr(domain_file, "getVersion", None)
            if get_version is None:
                return None
            value = int(get_version())
            return value if value > 0 else None
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to inspect loaded program version for '%s': %s", name, exc)
            return None

    def _refresh_active_versioned_program_state_locked(
        self,
        name: str,
        domain_path: str,
        *,
        status: Dict[str, Any] | None = None,
        save_before_close: bool,
        force: bool = False,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        effective_status = status or self._current_sync_status_locked(name, domain_path=domain_path)
        if not effective_status.get("is_versioned"):
            return False
        if not effective_status.get("is_checked_out"):
            return False
        if not force and not self._active_program_is_changed_locked(name, domain_path):
            return False
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=save_before_close,
        )
        return True

    def _reload_active_program_after_checkout_locked(
        self,
        name: str,
        domain_path: str,
        *,
        remove_target_lock_on_cleanup: bool = True,
    ) -> None:
        if not self._is_active_domain_path_locked(name, domain_path):
            return
        self._run_with_reopened_program_locked(
            name,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
            remove_target_lock_on_cleanup=remove_target_lock_on_cleanup,
        )

    def _reload_loaded_target_after_checkout_locked(self, *, handle: ProjectHandle, domain_path: str) -> None:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return
        if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
            return
        self._reload_active_program_after_checkout_locked(
            loaded_target,
            domain_path,
            remove_target_lock_on_cleanup=False,
        )

    def _reload_after_completed_checkout_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        operation: str,
    ) -> None:
        """Reload locally after a repository checkout that already succeeded."""
        try:
            self._reload_loaded_target_after_checkout_locked(
                handle=handle,
                domain_path=domain_path,
            )
        except Exception as exc:  # noqa: BLE001
            raise self._partial_success_error(
                operation=operation,
                message=(
                    "repository checkout completed, but the loaded program could not be "
                    f"reopened: {exc}"
                ),
            ) from exc

    @staticmethod
    def _refresh_project_sync_state_locked(handle: ProjectHandle, *, required: bool = False) -> bool:
        refresh_project_data = getattr(handle, "refresh_project_data", None)
        if refresh_project_data is None:
            if required:
                raise RuntimeError(
                    "SYNC_REFRESH_FAILED: project handle does not support required sync refresh"
                )
            return False
        try:
            refresh_project_data(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to refresh project sync state: %s", exc)
            if required:
                raise RuntimeError(f"SYNC_REFRESH_FAILED: failed to refresh project sync state: {exc}") from exc
            return False
        return True

    def _refresh_loaded_target_sync_state_locked(self, *, handle: ProjectHandle, domain_path: str) -> bool:
        loaded_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if loaded_target is None:
            return False
        if self._find_loaded_target_locked(handle=handle, domain_path=domain_path) != loaded_target:
            return False
        if self._active_program_is_changed_locked(loaded_target, domain_path):
            raise RuntimeError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
        self._run_with_reopened_program_locked(
            loaded_target,
            operation=lambda _active_handle, _active_domain_path: None,
            save_before_close=False,
            remove_target_lock_on_cleanup=False,
        )
        return True

    def _handle_commit_conflict_locked(
        self,
        name: str,
        domain_path: str,
        *,
        active_target: str | None,
        status: Dict[str, Any],
        conflict_action: str,
        auto_checkout_created: bool = False,
    ) -> Dict[str, Any] | None:
        if not status.get("can_merge"):
            return None
        if conflict_action == "abort":
            if auto_checkout_created:
                self._rollback_auto_checkout_locked(name, domain_path=domain_path)
            raise RuntimeError(
                "UNSAFE_MERGE_REQUIRED: remote changes require a merge before check-in; "
                "pass on_conflict='discard' to drop this checkout and follow the latest server state"
            )
        discarded_unsaved_active_changes = (
            active_target is not None
            and self._active_program_is_changed_locked(active_target, domain_path)
        )
        action = self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=lambda active_handle, active_domain_path: self._discard_conflict_checkout_operation(
                active_handle,
                active_domain_path,
            ),
            save_before_close=False,
        )
        if discarded_unsaved_active_changes:
            action["discarded_local_changes"] = True
        updated = self._read_postcondition_sync_status_locked(
            name,
            domain_path=domain_path,
            operation="commit_project_program.discard_conflict",
        )
        if updated.get("is_checked_out") or updated.get("can_merge"):
            raise self._partial_success_error(
                operation="commit_project_program.discard_conflict",
                message="conflict discard returned but the checkout or merge state is still active",
            )
        self._ensure_latest_version_postcondition(
            updated,
            operation="commit_project_program.discard_conflict",
            operation_completed=True,
        )
        return {
            "status": "ok",
            "reason": "conflict_discarded",
            "committed": False,
            "conflict_discarded": True,
            "target": name,
            "program": domain_path,
            "discarded_local_changes": bool(action["discarded_local_changes"]),
            "merged": bool(action["merged"]),
            "version": updated.get("version"),
            "latest_version": updated.get("latest_version"),
            "is_latest_version": bool(updated.get("is_latest_version")),
            "checked_out": bool(updated.get("is_checked_out")),
        }

    def _resolve_sync_target_locked(
        self,
        name: str,
        domain_path: str | None,
    ) -> tuple[ProjectHandle, str]:
        resolved_domain_path = (domain_path or "").strip()
        if resolved_domain_path:
            with self._store.registry_lock.write_lock():
                handle = self._store.get_target_handle_locked(name)
            return handle, self._normalize_domain_path_locked(handle, resolved_domain_path)

        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        return handle, self._store.session_domain_path(session)

    @staticmethod
    def _normalize_domain_path_locked(handle: ProjectHandle, domain_path: str | None) -> str:
        domain_dir, domain_name = path_utils._parse_domain_path(handle.project, domain_path)
        normalized_path = (pathlib.PurePosixPath(domain_dir) / domain_name).as_posix()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        return normalized_path

    def _is_active_domain_path_locked(self, name: str, domain_path: str) -> bool:
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            return False
        return self._store.session_domain_path(session) == domain_path

    def _find_loaded_target_locked(self, *, handle: ProjectHandle, domain_path: str) -> str | None:
        requested_key = handle.get_key()
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target "
                    f"'{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if session_handle.get_key() == requested_key:
                return target_name
        return None

    def _find_loaded_target_across_shared_project_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
    ) -> str | None:
        local_target = self._find_loaded_target_locked(handle=handle, domain_path=domain_path)
        if local_target is not None:
            return local_target
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to inspect loaded target "
                    f"'{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if self._handles_share_destructive_file_identity(
                handle,
                session_handle,
                domain_path=domain_path,
            ):
                return target_name
        return None

    def _find_loaded_checkout_owner_locked(
        self,
        *,
        handle: ProjectHandle,
        domain_path: str,
        checkout_id: int,
    ) -> str | None:
        with self._store.registry_lock.read_lock():
            sessions = list(self._store.sessions.items())
        for target_name, session in sessions:
            try:
                session_handle = session.get_project_handle()
                session_domain_path = self._store.session_domain_path(session)
            except Exception as exc:
                if self._session_lookup_error_is_closed(exc):
                    continue
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to inspect loaded checkout owner "
                    f"'{target_name}': {exc}"
                ) from exc
            if session_domain_path != domain_path:
                continue
            if not self._handles_share_destructive_file_identity(
                handle,
                session_handle,
                domain_path=domain_path,
            ):
                continue
            try:
                self._refresh_project_sync_state_locked(session_handle, required=True)
                loaded_status = session_handle.get_sync_status(domain_path)
                self._ensure_checkout_status_consistent(
                    loaded_status,
                    context=f"loaded target '{target_name}'",
                )
                checkout_status = loaded_status.get("checkout_status") or {}
            except Exception as exc:
                raise RuntimeError(
                    "SYNC_STATUS_UNAVAILABLE: failed to inspect loaded checkout state "
                    f"for '{target_name}': {exc}"
                ) from exc
            local_checkout_id = checkout_status.get("checkout_id")
            if local_checkout_id is not None and int(local_checkout_id) == int(checkout_id):
                return target_name
        return None

    @staticmethod
    def _ensure_checkout_status_consistent(status: Dict[str, Any], *, context: str) -> None:
        is_checked_out = bool(status.get("is_checked_out"))
        has_checkout_status = status.get("checkout_status") is not None
        if is_checked_out != has_checkout_status:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: inconsistent checkout state for "
                f"{context} (is_checked_out={is_checked_out}, "
                f"checkout_status_present={has_checkout_status})"
            )

    @staticmethod
    def _handles_share_project_identity(first: ProjectHandle, second: ProjectHandle) -> bool:
        first_shared = RuntimeSyncOperations._shared_project_identity(first)
        if first_shared is None:
            return first.get_key() == second.get_key()
        second_shared = RuntimeSyncOperations._shared_project_identity(second)
        return second_shared is not None and first_shared == second_shared

    @staticmethod
    def _handles_share_destructive_file_identity(
        first: ProjectHandle,
        second: ProjectHandle,
        *,
        domain_path: str,
    ) -> bool:
        """Identify one repository file across caches, including DNS URL aliases.

        Project URLs are sufficient for the normal case.  When two local caches
        reached the same Ghidra Server through different DNS aliases, however,
        URL comparison cannot prove identity.  Version-controlled Ghidra files
        retain the same file ID across checkouts/caches, so destructive guards
        use it as a second, path-scoped identity and otherwise fail closed.
        """
        if first.get_key() == second.get_key():
            return True

        first_shared = RuntimeSyncOperations._shared_project_identity(first)
        second_shared = RuntimeSyncOperations._shared_project_identity(second)
        if first_shared is None or second_shared is None:
            return False
        if first_shared == second_shared:
            return True

        first_file_id = RuntimeSyncOperations._domain_file_identity(first, domain_path)
        second_file_id = RuntimeSyncOperations._domain_file_identity(second, domain_path)
        return first_file_id == second_file_id

    @staticmethod
    def _domain_file_identity(handle: ProjectHandle, domain_path: str) -> str:
        get_file_id = getattr(handle, "get_domain_file_id", None)
        if get_file_id is None:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: project handle does not support domain file ID lookup"
            )
        try:
            file_id = get_file_id(domain_path)
        except Exception as exc:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: failed to inspect domain file ID: "
                f"{exc}"
            ) from exc
        normalized_id = str(file_id or "").strip()
        if not normalized_id:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: domain file ID is unavailable for destructive identity check"
            )
        return normalized_id

    @staticmethod
    def _shared_project_identity(handle: ProjectHandle) -> str | None:
        get_url = getattr(handle, "get_shared_project_url", None)
        if get_url is None:
            return None
        try:
            value = get_url()
        except Exception as exc:
            raise RuntimeError(f"SYNC_STATUS_UNAVAILABLE: failed to inspect shared project URL: {exc}") from exc
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None
        try:
            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise RuntimeError(
                f"SYNC_STATUS_UNAVAILABLE: invalid shared project URL: {exc}"
            ) from exc
        if not scheme or host is None or parsed.username is not None or parsed.password is not None:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: shared project URL lacks a safe scheme/host identity"
            )
        if parsed.query or parsed.fragment:
            raise RuntimeError(
                "SYNC_STATUS_UNAVAILABLE: shared project URL must not contain query or fragment data"
            )

        normalized_host = host.rstrip(".").lower()
        try:
            address = ipaddress.ip_address(normalized_host)
        except ValueError:
            if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
                normalized_host = "loopback"
        else:
            normalized_host = "loopback" if address.is_loopback else address.compressed

        # Ghidra uses 13100 as its default repository server base port.  Include
        # the effective port so an omitted default and an explicit :13100 share
        # one identity while different server instances remain isolated.
        effective_port = 13100 if scheme == "ghidra" and port is None else port
        host_text = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        authority = host_text if effective_port is None else f"{host_text}:{effective_port}"
        path = parsed.path.rstrip("/") or "/"
        return urllib.parse.urlunsplit((scheme, authority, path, "", ""))

    def _save_active_program_if_needed_locked(
        self,
        name: str,
        domain_path: str,
        *,
        handle: ProjectHandle | None = None,
    ) -> bool:
        if not self._is_active_domain_path_locked(name, domain_path):
            return False
        with self._store.registry_lock.read_lock():
            session = self._store.sessions.get(name)
        if session is None:
            return False
        if not self._active_program_is_changed_locked(name, domain_path):
            return False
        program = session.get_program()

        active_handle = handle or session.get_project_handle()
        try:
            active_handle.project.save(program)
        except Exception as exc:
            raise RuntimeError(f"SAVE_FAILED: failed to save program: {exc}") from exc
        with self._store.registry_lock.write_lock():
            self._store.clear_dirty_program(name, domain_path)
        return True

    def _rollback_auto_checkout_locked(
        self,
        name: str,
        *,
        domain_path: str,
    ) -> Dict[str, Any]:
        self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                active_domain_path,
                keep=False,
            ),
            save_before_close=False,
        )
        updated = self._read_postcondition_sync_status_locked(
            name,
            domain_path=domain_path,
            operation="commit_project_program.rollback_auto_checkout",
        )
        if updated.get("is_checked_out"):
            raise self._partial_success_error(
                operation="commit_project_program.rollback_auto_checkout",
                message="automatic checkout rollback returned but the program is still checked out",
            )
        return updated

    def _read_postcondition_sync_status_locked(
        self,
        name: str,
        *,
        domain_path: str,
        operation: str,
    ) -> Dict[str, Any]:
        try:
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            return self._get_refreshed_sync_status_locked(
                handle,
                resolved_domain_path,
                require_refresh=True,
            )
        except Exception as exc:  # noqa: BLE001
            raise self._partial_success_error(
                operation=operation,
                message=f"operation completed but postcondition status could not be read: {exc}",
            ) from exc

    def _verify_commit_postcondition(
        self,
        status: Dict[str, Any],
        *,
        previous_version: Any,
        previous_latest_version: Any,
    ) -> None:
        try:
            new_version = int(status.get("version"))
            prior_versions = [
                int(value)
                for value in (previous_version, previous_latest_version)
                if value is not None
            ]
        except (TypeError, ValueError) as exc:
            raise self._partial_success_error(
                operation="commit_project_program",
                message=f"commit returned but version state is unavailable: {exc}",
            ) from exc
        if new_version < 1 or (prior_versions and new_version <= max(prior_versions)):
            prior_text = max(prior_versions) if prior_versions else None
            raise self._partial_success_error(
                operation="commit_project_program",
                message=(
                    "commit returned but the program version did not advance "
                    f"(before={prior_text}, after={new_version})"
                ),
            )

    @staticmethod
    def _status_contains_checkout_id(status: Dict[str, Any], checkout_id: int) -> bool:
        expected = int(checkout_id)
        checkout_status = status.get("checkout_status") or {}
        values = [checkout_status.get("checkout_id")]
        values.extend(item.get("checkout_id") for item in (status.get("checkouts") or []))
        for value in values:
            if value is None:
                continue
            try:
                if int(value) == expected:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    @staticmethod
    def _partial_success_error(*, operation: str, message: str) -> DomainError:
        return DomainError(
            code=ErrorCode.SYNC_OPERATION_FAILED,
            message=f"SYNC_OPERATION_FAILED: {message}",
            hint="Inspect the repository state before deciding whether it is safe to retry",
            retryable=False,
            details={
                "operation": operation,
                "operation_completed": True,
                "partial_success": True,
            },
        )

    def _ensure_latest_version_postcondition(
        self,
        status: Dict[str, Any],
        *,
        operation: str,
        operation_completed: bool,
    ) -> None:
        version = status.get("version")
        latest_version = status.get("latest_version")
        try:
            versions_match = (
                version is not None
                and latest_version is not None
                and int(version) >= 1
                and int(version) == int(latest_version)
            )
        except (TypeError, ValueError):
            versions_match = False
        if status.get("is_latest_version") is True and versions_match:
            return

        message = (
            "FOLLOW_LATEST_FAILED: refreshed program is not at repository latest "
            f"(version={version}, latest_version={latest_version}, "
            f"is_latest_version={status.get('is_latest_version')})"
        )
        if operation_completed:
            raise self._partial_success_error(operation=operation, message=message)
        raise DomainError(
            code=ErrorCode.SYNC_OPERATION_FAILED,
            message=f"SYNC_OPERATION_FAILED: {message}",
            hint="Retry after the repository refresh path is available",
            retryable=True,
            details={
                "operation": operation,
                "operation_completed": False,
                "partial_success": False,
            },
        )

    @staticmethod
    def _list_program_paths_locked(handle: ProjectHandle) -> set[str]:
        return {
            str(item.get("domain_path"))
            for item in handle.list_programs()
            if str(item.get("domain_path") or "")
        }

    @staticmethod
    def _resolve_new_keep_domain_path(
        handle: ProjectHandle,
        domain_path: str,
        existing_program_paths: set[str],
    ) -> str:
        keep_prefix = f"{domain_path}.keep"
        current_paths = {
            str(item.get("domain_path"))
            for item in handle.list_programs()
            if str(item.get("domain_path") or "")
        }
        new_keep_paths = sorted(
            (path for path in current_paths if path.startswith(keep_prefix) and path not in existing_program_paths),
            key=lambda path: RuntimeSyncOperations._keep_path_sort_key(path, keep_prefix),
        )
        if new_keep_paths:
            return new_keep_paths[-1]
        raise RuntimeError(f"KEEP_FILE_NOT_FOUND: no new keep file was created for {domain_path}")

    @staticmethod
    def _keep_path_sort_key(path: str, keep_prefix: str) -> tuple[int, int, str]:
        suffix = path[len(keep_prefix) :]
        if suffix == "":
            return (1, 0, path)
        if suffix.startswith(".") and suffix[1:].isdigit():
            return (1, int(suffix[1:]), path)
        return (0, 0, path)

    def _run_sync_operation_for_domain_locked(
        self,
        name: str,
        domain_path: str,
        operation,
        *,
        save_before_close: bool,
        reopen_domain_path_resolver=None,
    ):
        with self._store.registry_lock.write_lock():
            handle = self._store.get_target_handle_locked(name)
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
    ):
        with self._store.registry_lock.read_lock():
            session = self._store.ensure_session(name)
        handle = session.get_project_handle()
        project_location = handle.get_project_location()
        project_name = handle.get_project_name()
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
            with self._store.registry_lock.write_lock():
                active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            return operation(active_handle, domain_path)

        def _reopen() -> None:
            nonlocal reopened_session_bound
            nonlocal active_handle
            if active_handle is None:
                with self._store.registry_lock.write_lock():
                    active_handle = self._store.get_or_create_project_handle(project_location, project_name)
            reopen_domain_path = domain_path
            if reopen_domain_path_resolver is not None:
                reopen_domain_path = reopen_domain_path_resolver(active_handle, domain_path)
            reopened = active_handle.open_program(reopen_domain_path)
            try:
                self._store.core_accessor().initialize(reopened.get_program(), key=name)
                with self._store.registry_lock.write_lock():
                    self._store.sessions[name] = reopened
                reopened_session_bound = True
            except Exception as init_error:  # noqa: BLE001
                try:
                    reopened.close()
                except Exception as close_exc:
                    with self._store.registry_lock.write_lock():
                        self._store.sessions[name] = reopened
                    reopened_session_bound = True
                    raise RuntimeError(
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
                raise RuntimeError(f"SAVE_FAILED: {exc.message}") from exc

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
                    raise exc
                if operation_error:
                    raise RuntimeError(
                        f"SYNC_OPERATION_FAILED: {operation_error}; REOPEN_FAILED: {exc.message}"
                    ) from exc
                if "operation_result" in details or (
                    preserve_none_operation_completion and details.get("operation_completed")
                ):
                    raise exc
                raise RuntimeError(f"REOPEN_FAILED: {exc.message}") from exc

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

    def _discard_hijacked_file_operation(self, handle: ProjectHandle, domain_path: str) -> None:
        status = handle.get_sync_status(domain_path)
        if not status.get("is_hijacked"):
            raise RuntimeError(
                "HIJACK_STATE_CHANGED: local file is no longer hijacked; no file was deleted"
            )
        try:
            handle.delete_domain_file(domain_path)
        except Exception as exc:
            if str(exc).startswith("DELETE_POSTCONDITION_FAILED:"):
                raise self._partial_success_error(
                    operation="pull_project_program.discard_hijack",
                    message=str(exc),
                ) from exc
            raise

    def _pull_operation(
        self,
        handle: ProjectHandle,
        domain_path: str,
        *,
        on_local_changes: str,
    ) -> Dict[str, bool]:
        status = handle.get_sync_status(domain_path)
        pending_merge_before_discard = bool(status.get("can_merge"))
        discarded_local_changes = False
        if status.get("modified_since_checkout"):
            if on_local_changes == "abort":
                raise RuntimeError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")
            handle.undo_checkout_program(domain_path, keep=False)
            discarded_local_changes = True
            status = self._read_handle_status_after_side_effect(
                handle,
                domain_path=domain_path,
                operation="pull_project_program.discard_local_changes",
            )
            if status.get("is_checked_out"):
                raise self._partial_success_error(
                    operation="pull_project_program.discard_local_changes",
                    message="undo checkout returned but the program is still checked out",
                )
            if status.get("can_merge"):
                raise self._partial_success_error(
                    operation="pull_project_program.discard_local_changes",
                    message="undo checkout returned but the program still reports a pending merge",
                )

        merged = False
        # undoCheckout(false) drops the stale checkout as well as its local
        # changes.  If the checkout already needed a merge, reopening now follows
        # the server's latest version even though canMerge becomes false afterward.
        followed_latest = discarded_local_changes and pending_merge_before_discard
        if status.get("can_merge"):
            if not status.get("is_checked_out"):
                raise RuntimeError(
                    "UNSAFE_MERGE_REQUIRED: remote changes require a Ghidra merge, "
                    "but automatic merge is disabled because PropertyList merges can crash. "
                    "Reopen the program from the latest version or re-checkout before retrying."
                )

            # Avoid DomainFile.merge() here. In Ghidra 12.0.4 the PropertyList merge path can
            # throw a NullPointerException when comment/property state diverges. Dropping a stale
            # checkout and reopening is safer when we only need to follow the latest server state.
            handle.undo_checkout_program(domain_path, keep=False)
            status = self._read_handle_status_after_side_effect(
                handle,
                domain_path=domain_path,
                operation="pull_project_program.follow_latest",
            )
            if status.get("is_checked_out") or status.get("can_merge"):
                raise self._partial_success_error(
                    operation="pull_project_program.follow_latest",
                    message=(
                        "checkout drop returned but the checkout or pending merge state "
                        "is still active"
                    ),
                )
            followed_latest = True
        return {
            "discarded_local_changes": discarded_local_changes,
            "merged": merged,
            "followed_latest": followed_latest,
        }

    def _read_handle_status_after_side_effect(
        self,
        handle: ProjectHandle,
        *,
        domain_path: str,
        operation: str,
    ) -> Dict[str, Any]:
        try:
            self._refresh_project_sync_state_locked(handle, required=True)
            return handle.get_sync_status(domain_path)
        except Exception as exc:  # noqa: BLE001
            raise self._partial_success_error(
                operation=operation,
                message=f"operation completed but postcondition status could not be read: {exc}",
            ) from exc

    @staticmethod
    def _ensure_delete_allowed(status: Dict[str, Any], *, allow_private: bool) -> None:
        if status.get("is_hijacked"):
            raise RuntimeError(
                "HIJACKED_PROGRAM: refusing generic delete for a hijacked file; use "
                "pull_project_program(on_local_changes='discard') to reveal the repository version"
            )
        if not status.get("is_versioned"):
            if not allow_private:
                raise RuntimeError(
                    "PRIVATE_FILE_DELETE_NOT_ALLOWED: target file is not under shared-project "
                    "version control; pass allow_private=true only when deleting a private project file"
                )
            return

        checkouts = status.get("checkouts") or []
        if status.get("is_checked_out") or status.get("checkout_status") or checkouts:
            raise RuntimeError(
                "SHARED_FILE_DELETE_BLOCKED: delete aborted because the file has an active checkout"
            )
        if status.get("can_merge"):
            raise RuntimeError(
                "SHARED_FILE_DELETE_BLOCKED: delete aborted because the file requires merge handling"
            )

    @staticmethod
    def _ensure_versioned_project(status: Dict[str, Any]) -> None:
        if status.get("is_hijacked"):
            raise RuntimeError(
                "HIJACKED_PROGRAM: a private local file shadows the repository version; use "
                "pull_project_program(on_local_changes='discard') to recover it"
            )
        if not status.get("is_versioned"):
            if status.get("can_add_to_repository"):
                raise DomainError(
                    code=ErrorCode.ADD_TO_VERSION_CONTROL_REQUIRED,
                    message=(
                        "ADD_TO_VERSION_CONTROL_REQUIRED: target program is not under shared-project "
                        "version control; run add_project_program_to_version_control first"
                    ),
                    hint="Run add_project_program_to_version_control before shared-project sync operations",
                    retryable=False,
                    details={
                        "required_action": "add_project_program_to_version_control",
                        "can_add_to_repository": True,
                    },
                )
            raise RuntimeError("NOT_SHARED_PROJECT: target program is not under shared-project version control")


__all__ = ["RuntimeSyncOperations"]
