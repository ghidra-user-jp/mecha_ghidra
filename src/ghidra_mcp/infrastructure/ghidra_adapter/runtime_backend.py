"""Ghidra runtime backend implementing target/sync/core operations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_headless.session import ProgramSession

from .runtime.errors import to_domain_error
from .runtime import RuntimeCoreExecution, RuntimeSessionStore, RuntimeSyncOperations, RuntimeTargetLifecycle


class RuntimeBackend:
    """Façade that preserves the legacy RuntimeBackend public contract."""

    def __init__(
        self,
        *,
        state: RuntimeState,
    ) -> None:
        store = RuntimeSessionStore(state=state, core_accessor=state.core_accessor)
        self._store = store
        self._target_lifecycle = RuntimeTargetLifecycle(store=store)
        self._sync_operations = RuntimeSyncOperations(store=store)
        self._core_execution = RuntimeCoreExecution(
            store=store,
            checkout_required_commands=set(state.checkout_required_commands),
            normalize_result=state.normalize_result,
        )

    def _invoke(
        self,
        *,
        operation: str,
        func,
        target: str | None = None,
        domain_path: str | None = None,
    ):
        try:
            return func()
        except Exception as exc:  # noqa: BLE001
            raise to_domain_error(
                exc,
                operation=operation,
                target=target,
                domain_path=domain_path,
            ) from exc

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ) -> ProgramSession:
        return self._invoke(
            operation="create_session",
            target=name,
            domain_path=domain_path,
            func=lambda: self._target_lifecycle.create_session(
                name,
                project_location,
                project_name=project_name,
                domain_path=domain_path,
            ),
        )

    def register_target(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
    ) -> Dict[str, Optional[str]]:
        return self._invoke(
            operation="register_target",
            target=name,
            func=lambda: self._target_lifecycle.register_target(
                name,
                project_location,
                project_name=project_name,
            ),
        )

    def list_targets(self) -> List[Dict[str, Optional[str]]]:
        return self._invoke(operation="list_targets", func=self._target_lifecycle.list_targets)

    def list_programs(self, name: str):
        return self._invoke(operation="list_programs", target=name, func=lambda: self._target_lifecycle.list_programs(name))

    def load_program(
        self,
        name: str,
        domain_path: str,
    ) -> str:
        return self._invoke(
            operation="load_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._target_lifecycle.load_program(name, domain_path),
        )

    def import_program(self, name: str, binary_path: str, **kwargs) -> str:
        return self._invoke(
            operation="import_program",
            target=name,
            func=lambda: self._target_lifecycle.import_program(name, binary_path, **kwargs),
        )

    def execute_core_command(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        *,
        target: str = "default",
    ) -> Any:
        return self._invoke(
            operation=command,
            target=target,
            func=lambda: self._core_execution.call(command, params or {}, target=target),
        )

    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        return self._invoke(
            operation="get_project_sync_status",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.get_project_sync_status(name, domain_path=domain_path),
        )

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="checkout_project_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.checkout_project_program(
                name,
                exclusive=exclusive,
                domain_path=domain_path,
            ),
        )

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="add_project_program_to_version_control",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.add_project_program_to_version_control(
                name,
                comment,
                keep_checked_out=keep_checked_out,
                domain_path=domain_path,
            ),
        )

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="commit_project_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.commit_project_program(
                name,
                message,
                keep_checked_out=keep_checked_out,
                auto_checkout=auto_checkout,
                domain_path=domain_path,
            ),
        )

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="pull_project_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.pull_project_program(
                name,
                on_local_changes=on_local_changes,
                domain_path=domain_path,
            ),
        )

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="undo_checkout_project_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.undo_checkout_project_program(
                name,
                discard_local_changes=discard_local_changes,
                domain_path=domain_path,
            ),
        )

    def terminate_project_program_checkout(
        self,
        name: str,
        checkout_id: int,
        *,
        domain_path: str | None = None,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="terminate_project_program_checkout",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.terminate_project_program_checkout(
                name,
                checkout_id,
                domain_path=domain_path,
            ),
        )

    def reload_project_program(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]:
        return self._invoke(
            operation="reload_project_program",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.reload_project_program(name, domain_path=domain_path),
        )

    def get_version_history(
        self,
        name: str,
        *,
        domain_path: str | None = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="get_version_history",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.get_version_history(name, domain_path=domain_path, limit=limit),
        )

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        domain_path: str | None = None,
        range_limit: int = 200,
    ) -> Dict[str, Any]:
        return self._invoke(
            operation="get_version_diff",
            target=name,
            domain_path=domain_path,
            func=lambda: self._sync_operations.get_version_diff(
                name,
                from_version=from_version,
                to_version=to_version,
                domain_path=domain_path,
                range_limit=range_limit,
            ),
        )

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        self._invoke(
            operation="close_session",
            target=name,
            func=lambda: self._target_lifecycle.close_session(name, remove_program=remove_program),
        )

    def close_all(self) -> None:
        self._invoke(operation="close_all", func=self._target_lifecycle.close_all)

    def has_sessions(self) -> bool:
        return self._store.has_sessions()

    def has_targets(self) -> bool:
        return self._store.has_targets()

    def project_lock_key(self, name: str) -> str | None:
        return self._store.project_lock_key(name)

    def call(
        self,
        command: str,
        params: Dict[str, Any] | None = None,
        target: str = "default",
    ) -> Any:
        return self._invoke(
            operation="call",
            target=target,
            func=lambda: self._core_execution.call(command, params, target=target),
        )


__all__ = ["RuntimeBackend"]
