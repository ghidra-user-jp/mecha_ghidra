"""Shared project sync operations for runtime backend."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Dict

from ghidra_headless.errors import HeadlessError, error_code_of
from ghidra_headless.session import ProjectHandle
from ghidra_mcp.domain import DomainError, ErrorCode, get_exclusive_checkout_default

from .session_store import RuntimeSessionStore
from .sync_active_program import SyncActiveProgramMixin
from .sync_identity import SyncIdentityMixin
from .sync_locking import SyncLockingMixin
from .sync_postconditions import SyncPostconditionMixin
from .sync_reopen import SyncReopenMixin

logger = logging.getLogger(__name__)


class RuntimeSyncOperations(
    SyncLockingMixin, SyncIdentityMixin, SyncPostconditionMixin, SyncActiveProgramMixin, SyncReopenMixin
):
    """Shared-project sync operations exposed through the runtime backend.

    The public methods live here; lock handling, identity checks, postcondition
    verification, active-program refresh and the reopen lifecycle are mixins in
    the sibling ``sync_*`` modules.
    """

    def __init__(self, *, store: RuntimeSessionStore) -> None:
        self._store = store

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
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
            return {"target": name, "program": resolved_domain_path, **status}

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool | None = None,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        # ``None`` means "whatever the operator configured" (see
        # --shared-sync-exclusive-checkout); an explicit value always wins.
        exclusive = get_exclusive_checkout_default() if exclusive is None else bool(exclusive)
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            active_target = self._find_loaded_target_locked(handle=handle, domain_path=resolved_domain_path)
            status = self._get_refreshed_sync_status_locked(handle, resolved_domain_path, require_refresh=True)
            if active_target is not None and not status.get("is_versioned"):
                self._refresh_loaded_target_sync_state_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                )
                handle = self._store.get_target_handle(name)
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
            if active_target is not None and self._active_program_is_changed_locked(
                active_target, resolved_domain_path
            ):
                raise HeadlessError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
            checked_out = handle.checkout_program(resolved_domain_path, exclusive=exclusive)
            if not checked_out:
                mode = "exclusive " if exclusive else ""
                raise HeadlessError(f"CHECKOUT_UNAVAILABLE: the requested {mode}checkout was refused by the repository")
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
                raise HeadlessError("ADD_TO_VERSION_CONTROL_NOT_ALLOWED: addToVersionControl is not allowed")

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
        if conflict_action not in {"abort", "discard", "keep"}:
            raise ValueError("on_conflict must be 'abort', 'discard', or 'keep'")
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
                handle = self._store.get_target_handle(name)
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
                        raise HeadlessError("LOCAL_CHANGES_EXIST: checkout aborted due to local changes")
                    checked_out = handle.checkout_program(
                        resolved_domain_path,
                        exclusive=get_exclusive_checkout_default(),
                    )
                    if not checked_out:
                        raise HeadlessError("CHECKOUT_UNAVAILABLE: automatic checkout was refused")
                    auto_checkout_created = True
                    self._reload_after_completed_checkout_locked(
                        handle=handle,
                        domain_path=resolved_domain_path,
                        operation="commit_project_program.auto_checkout",
                    )
                    handle = self._store.get_target_handle(name)
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
                    raise HeadlessError("NOT_CHECKED_OUT: program is not checked out")

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
                    handle = self._store.get_target_handle(name)
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
                raise HeadlessError("CHECKIN_NOT_ALLOWED: checkin is not allowed")

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
            active_program_changed = active_target is not None and self._active_program_is_changed_locked(
                active_target, resolved_domain_path
            )

            if status.get("is_hijacked"):
                if normalized == "abort":
                    raise HeadlessError(
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
                    "checked_out": bool(updated.get("is_checked_out")),
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
                raise HeadlessError("LOCAL_CHANGES_EXIST: pull aborted due to local changes")

            needs_operation = bool(status.get("modified_since_checkout")) or bool(status.get("can_merge"))
            discarded_unsaved_active_changes = (
                normalized == "discard" and active_target is not None and active_program_changed
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
                # Following the latest version drops a stale checkout; report it so
                # callers know a new checkout is needed before mutating again.
                "checked_out": bool(updated.get("is_checked_out")),
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

                def resolve_keep_path(active_handle, active_domain_path):
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
                except Exception as exc:
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
                raise HeadlessError(
                    f"CHECKOUT_NOT_FOUND: checkout_id {int(checkout_id)} is not active for {resolved_domain_path}"
                )
            loaded_checkout_owner = None
            if not is_local_checkout:
                loaded_checkout_owner = self._find_loaded_checkout_owner_locked(
                    handle=handle,
                    domain_path=resolved_domain_path,
                    checkout_id=checkout_id,
                )
            if is_local_checkout or loaded_checkout_owner is not None:
                raise HeadlessError(
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
                    message=(f"terminate checkout returned but checkout_id {int(checkout_id)} is still active"),
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
            handle = self._store.get_target_handle(name)
            resolved_domain_path = self._normalize_domain_path_locked(handle, domain_path)
            confirmation = (confirm or "").strip()
            if confirmation != resolved_domain_path:
                raise ValueError(f"confirm must exactly match the normalized domain_path ({resolved_domain_path})")

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
                raise HeadlessError(
                    "UNSAFE_VERSIONED_DELETE: Ghidra does not provide an atomic compare-and-delete "
                    "operation for versioned files; pass allow_non_atomic_versioned_delete=true "
                    "only after excluding concurrent repository writers"
                )
            if was_versioned and expected_latest_version is None:
                raise ValueError("expected_latest_version is required when allow_non_atomic_versioned_delete=true")
            if expected_latest_version is not None:
                expected = int(expected_latest_version)
                if expected < 1:
                    raise ValueError("expected_latest_version must be >= 1")
                if latest_version is None or int(latest_version) != expected:
                    raise HeadlessError(
                        "LATEST_VERSION_MISMATCH: delete aborted because latest_version "
                        f"is {latest_version}, expected {expected}"
                    )
            try:
                delete_result = handle.delete_domain_file(resolved_domain_path)
            except Exception as exc:
                if error_code_of(exc) == "DELETE_POSTCONDITION_FAILED":
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

    def get_version_history(
        self,
        name: str,
        *,
        domain_path: str | None = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            self._ensure_versioned_project(
                self._get_refreshed_sync_status_locked(
                    handle,
                    resolved_domain_path,
                    require_refresh=True,
                )
            )
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
        include_details: bool = False,
        details_limit: int = 20,
    ) -> Dict[str, Any]:
        with self._target_operation(name):
            handle, resolved_domain_path = self._resolve_sync_target_locked(name, domain_path)
            self._ensure_versioned_project(
                self._get_refreshed_sync_status_locked(
                    handle,
                    resolved_domain_path,
                    require_refresh=True,
                )
            )
            diff = handle.get_version_diff(
                resolved_domain_path,
                from_version=from_version,
                to_version=to_version,
                range_limit=range_limit,
                include_details=include_details,
                details_limit=details_limit,
            )
            return {
                "target": name,
                "program": resolved_domain_path,
                **diff,
            }

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
            raise HeadlessError(
                "UNSAFE_MERGE_REQUIRED: remote changes require a merge before check-in; "
                "pass on_conflict='keep' to preserve the local edits as a .keep copy and follow the latest "
                "server state, or on_conflict='discard' to drop them"
            )
        if conflict_action == "keep":
            return self._keep_commit_conflict_locked(
                name,
                domain_path,
                active_target=active_target,
                status=status,
            )
        discarded_unsaved_active_changes = active_target is not None and self._active_program_is_changed_locked(
            active_target, domain_path
        )
        action = self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=self._discard_conflict_checkout_operation,
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

    def _keep_commit_conflict_locked(
        self,
        name: str,
        domain_path: str,
        *,
        active_target: str | None,
        status: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve a stale checkout by saving the local edits aside as a ``.keep`` file.

        Ghidra's ``undoCheckout(keep=True)`` renames the checked-out local copy to
        ``<name>.keep`` (or ``.keep.N``) and reveals the repository's latest version
        at the original path.  A loaded target follows the kept copy so the edits
        stay open; nothing is lost and nothing is checked out afterwards.
        """
        handle = self._store.get_target_handle(name)
        was_active = active_target is not None
        has_local_changes = bool(status.get("modified_since_checkout"))
        if was_active:
            has_local_changes = has_local_changes or self._active_program_is_changed_locked(active_target, domain_path)
        # A clean checkout has nothing worth preserving; keep=True would still
        # create an empty .keep copy, so only request it when edits exist.
        keep = has_local_changes
        existing_program_paths = self._list_program_paths_locked(handle) if keep else None
        keep_path_resolver: Callable[[ProjectHandle, str], str] | None = None
        if keep and was_active:

            def resolve_keep_path(active_handle, active_domain_path):
                assert existing_program_paths is not None
                return self._resolve_new_keep_domain_path(active_handle, active_domain_path, existing_program_paths)

            keep_path_resolver = resolve_keep_path

        self._run_sync_operation_for_domain_locked(
            name,
            domain_path,
            operation=lambda active_handle, active_domain_path: active_handle.undo_checkout_program(
                active_domain_path,
                keep=keep,
            ),
            save_before_close=keep,
            reopen_domain_path_resolver=keep_path_resolver,
        )
        with self._store.registry_lock.write_lock():
            self._store.clear_dirty_program(name, domain_path)
        updated = self._read_postcondition_sync_status_locked(
            name,
            domain_path=domain_path,
            operation="commit_project_program.keep_conflict",
        )
        if updated.get("is_checked_out") or updated.get("can_merge"):
            raise self._partial_success_error(
                operation="commit_project_program.keep_conflict",
                message="keep-conflict undo returned but the checkout or merge state is still active",
            )
        self._ensure_latest_version_postcondition(
            updated,
            operation="commit_project_program.keep_conflict",
            operation_completed=True,
        )
        kept_program: str | None = None
        if keep and not was_active:
            assert existing_program_paths is not None
            try:
                kept_program = self._resolve_new_keep_domain_path(handle, domain_path, existing_program_paths)
            except Exception as exc:
                raise self._partial_success_error(
                    operation="commit_project_program.keep_conflict",
                    message=(
                        "the conflicted checkout was undone with keep=True, but the preserved .keep "
                        f"file could not be identified: {exc}"
                    ),
                ) from exc
        if keep and was_active:
            with self._store.registry_lock.read_lock():
                session = self._store.sessions.get(active_target)
            if session is not None:
                active_domain_path = self._store.session_domain_path(session)
                if active_domain_path != domain_path:
                    kept_program = active_domain_path
        return {
            "status": "ok",
            "reason": "conflict_kept",
            "committed": False,
            "conflict_discarded": False,
            "conflict_kept": True,
            "kept_program": kept_program,
            "target": name,
            "program": domain_path,
            "discarded_local_changes": False,
            "merged": False,
            "version": updated.get("version"),
            "latest_version": updated.get("latest_version"),
            "is_latest_version": bool(updated.get("is_latest_version")),
            "checked_out": bool(updated.get("is_checked_out")),
        }
