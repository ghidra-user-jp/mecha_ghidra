"""Compatibility facade delegating to application services."""

from __future__ import annotations

from typing import Any, Callable

from ghidra_mcp.application.services import RuntimeState, SyncService, TargetService
from ghidra_mcp.domain import DomainError


class SessionRegistry:
    def __init__(
        self,
        *,
        core_accessor: Callable[[], Any],
        checkout_required_commands: set[str],
        normalize_result: Callable[[Any], Any],
    ) -> None:
        self._runtime = RuntimeState(
            core_accessor=core_accessor,
            checkout_required_commands=checkout_required_commands,
            normalize_result=normalize_result,
        )
        # Keep runtime private helper patchable via SessionRegistry for legacy tests.
        self._runtime_get_or_create_project_handle = self._runtime._get_or_create_project_handle
        self._runtime._get_or_create_project_handle = self._forward_get_or_create_project_handle
        self._runtime_ensure = self._runtime._ensure
        self._runtime._ensure = self._forward_ensure
        self._runtime_lock = self._runtime._lock
        self._runtime._lock = self._forward_lock
        self._target_service = TargetService(self._runtime)
        self._sync_service = SyncService(self._runtime)
        self._bind_runtime_attrs()

    def _bind_runtime_attrs(self) -> None:
        # Keep compatibility for tests/introspection touching private members.
        self._core_accessor = self._runtime._core_accessor
        self._checkout_required_commands = self._runtime._checkout_required_commands
        self._normalize_result = self._runtime._normalize_result
        self._sessions = self._runtime._sessions
        self._locks = self._runtime._locks
        self._target_projects = self._runtime._target_projects
        self._project_handles = self._runtime._project_handles
        self._registry_lock = self._runtime._registry_lock

    @staticmethod
    def _rethrow_domain_error(exc: DomainError) -> None:
        raise RuntimeError(str(exc)) from exc

    def _forward_get_or_create_project_handle(self, project_location: str, project_name: str | None):
        return self._get_or_create_project_handle(project_location, project_name)

    def _get_or_create_project_handle(self, project_location: str, project_name: str | None):
        return self._runtime_get_or_create_project_handle(project_location, project_name)

    def _forward_ensure(self, name: str):
        return self._ensure(name)

    def _ensure(self, name: str):
        return self._runtime_ensure(name)

    def _forward_lock(self, name: str):
        return self._lock(name)

    def _lock(self, name: str):
        return self._runtime_lock(name)

    def __getattr__(self, name: str):
        return getattr(self._runtime, name)

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        try:
            return self._target_service.create_session(
                name,
                project_location,
                project_name=project_name,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None):
        try:
            return self._target_service.register_target(name, project_location, project_name=project_name)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def list_targets(self):
        return self._target_service.list_targets()

    def list_programs(self, name: str):
        try:
            return self._target_service.list_programs(name)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def load_program(self, name: str, domain_path: str):
        try:
            return self._target_service.load_program(name, domain_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def import_program(self, name: str, binary_path: str):
        try:
            return self._target_service.import_program(name, binary_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def close_session(self, name: str, *, remove_program: bool = False):
        try:
            return self._target_service.close_session(name, remove_program=remove_program)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def close_all(self) -> None:
        self._target_service.close_all()

    def has_sessions(self) -> bool:
        return self._target_service.has_sessions()

    def has_targets(self) -> bool:
        return self._target_service.has_targets()

    def call(
        self,
        command: str,
        params: dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        return self._runtime.call(command, params, target)

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None):
        try:
            return self._sync_service.get_project_sync_status(name, domain_path=domain_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.checkout_project_program(name, exclusive=exclusive, domain_path=domain_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.add_project_program_to_version_control(
                name,
                comment,
                keep_checked_out=keep_checked_out,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.commit_project_program(
                name,
                message,
                keep_checked_out=keep_checked_out,
                auto_checkout=auto_checkout,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.pull_project_program(
                name,
                on_local_changes=on_local_changes,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.undo_checkout_project_program(
                name,
                discard_local_changes=discard_local_changes,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def terminate_project_program_checkout(
        self,
        name: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.terminate_project_program_checkout(
                name,
                checkout_id=checkout_id,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def reload_project_program(self, name: str, *, domain_path: str | None = None):
        try:
            return self._sync_service.reload_project_program(name, domain_path=domain_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None):
        try:
            return self._sync_service.get_version_history(name, limit=limit, domain_path=domain_path)
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        try:
            return self._sync_service.get_version_diff(
                name,
                from_version=from_version,
                to_version=to_version,
                range_limit=range_limit,
                domain_path=domain_path,
            )
        except DomainError as exc:
            self._rethrow_domain_error(exc)

    # Keep private helper used by legacy tests.
    def _cleanup_session(
        self,
        name: str,
        session,
        handle,
        *,
        remove_registry_entry: bool,
        remove_context: bool,
        remove_program: bool = False,
    ) -> None:
        self._runtime._cleanup_session(
            name,
            session,
            handle,
            remove_registry_entry=remove_registry_entry,
            remove_context=remove_context,
            remove_program=remove_program,
        )


__all__ = ["SessionRegistry"]
