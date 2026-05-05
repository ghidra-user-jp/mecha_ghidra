"""Runtime wiring for presentation CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.types import CallToolResult, TextContent

from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.application.services.sync_service import SyncService
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.infrastructure import CoreGateway, LockManager, RuntimeBackend
from ghidra_mcp.presentation.mcp_server import MCPServerRuntime, create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


def _normalize_empty_list_result(result: Any) -> Any:
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


class _RuntimeBackendCoreExecutor:
    """Delegate core commands through RuntimeBackend for consistent state tracking."""

    def __init__(self, runtime_backend: RuntimeBackend) -> None:
        self._runtime_backend = runtime_backend

    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        return self._runtime_backend.execute_core_command(command, params, target=key)


class ServiceRegistryAdapter:
    """Facade bridging dispatcher calls to core/target/sync services."""

    def __init__(
        self,
        *,
        core_command_service: CoreCommandService,
        target_service: TargetService,
        sync_service: SyncService,
    ) -> None:
        self._core_command_service = core_command_service
        self._target_service = target_service
        self._sync_service = sync_service

    # core command path
    def call(self, command: str, params: dict[str, Any], target: str):
        return self._core_command_service.call(command, params, target)

    # target/project path
    def list_targets(self):
        return self._target_service.list_targets()

    def list_programs(self, target: str):
        return self._target_service.list_programs(target)

    def register_target(self, target: str, *, project_location: str, project_name: str | None = None):
        return self._target_service.register_target(
            target,
            project_location,
            project_name=project_name,
        )

    def load_program(self, target: str, domain_path: str):
        return self._target_service.load_program(target, domain_path)

    def import_program(self, target: str, binary_path: str, **kwargs):
        return self._target_service.import_program(target, binary_path, **kwargs)

    def create_session(
        self,
        target: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        if domain_path is None:
            raise ValueError("domain_path is required")
        return self._target_service.create_session(
            target,
            project_location,
            project_name=project_name,
            domain_path=domain_path,
        )

    def close_session(self, target: str, *, remove_program: bool = False):
        return self._target_service.close_session(target, remove_program=remove_program)

    # shared-sync path
    def get_project_sync_status(self, target: str, *, domain_path: str | None = None):
        return self._sync_service.get_project_sync_status(target, domain_path=domain_path)

    def checkout_project_program(self, target: str, *, exclusive: bool = False, domain_path: str | None = None):
        return self._sync_service.checkout_project_program(target, exclusive=exclusive, domain_path=domain_path)

    def add_project_program_to_version_control(
        self,
        target: str,
        *,
        comment: str,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        return self._sync_service.add_project_program_to_version_control(
            target,
            comment,
            keep_checked_out=keep_checked_out,
            domain_path=domain_path,
        )

    def commit_project_program(
        self,
        target: str,
        *,
        message: str,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ):
        return self._sync_service.commit_project_program(
            target,
            message,
            keep_checked_out=keep_checked_out,
            auto_checkout=auto_checkout,
            on_conflict=on_conflict,
            domain_path=domain_path,
        )

    def pull_project_program(
        self,
        target: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ):
        return self._sync_service.pull_project_program(
            target,
            on_local_changes=on_local_changes,
            domain_path=domain_path,
        )

    def undo_checkout_project_program(
        self,
        target: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ):
        return self._sync_service.undo_checkout_project_program(
            target,
            discard_local_changes=discard_local_changes,
            domain_path=domain_path,
        )

    def terminate_project_program_checkout(
        self,
        target: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ):
        return self._sync_service.terminate_project_program_checkout(
            target,
            checkout_id=checkout_id,
            domain_path=domain_path,
        )

    def delete_shared_project_file(
        self,
        target: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
    ):
        return self._sync_service.delete_shared_project_file(
            target,
            domain_path=domain_path,
            confirm=confirm,
            expected_latest_version=expected_latest_version,
            allow_private=allow_private,
        )

    def reload_project_program(self, target: str, *, domain_path: str | None = None):
        return self._sync_service.reload_project_program(target, domain_path=domain_path)

    def get_version_history(self, target: str, *, limit: int = 50, domain_path: str | None = None):
        return self._sync_service.get_version_history(target, limit=limit, domain_path=domain_path)

    def get_version_diff(
        self,
        target: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        return self._sync_service.get_version_diff(
            target,
            from_version=from_version,
            to_version=to_version,
            range_limit=range_limit,
            domain_path=domain_path,
        )

    def has_targets(self) -> bool:
        return self._target_service.has_targets()

    def close_all(self) -> None:
        self._target_service.close_all()


@dataclass(slots=True)
class CLIRuntimeBundle:
    registry: ServiceRegistryAdapter
    runtime: MCPServerRuntime
    runtime_backend: RuntimeBackend
    lock_manager: LockManager
    target_service: TargetService
    sync_service: SyncService
    core_command_service: CoreCommandService


def create_cli_runtime(
    *,
    registered_specs: dict[str, ToolSpec],
    core_accessor: Callable[[], Any],
    checkout_required_commands: set[str],
    dispatcher_provider: Callable[[], Callable[..., Any]] | None = None,
    registry_provider: Callable[[], Any] | None = None,
) -> CLIRuntimeBundle:
    runtime_state = RuntimeState(
        core_accessor=core_accessor,
        checkout_required_commands=set(checkout_required_commands),
        normalize_result=_normalize_empty_list_result,
    )
    runtime_backend = RuntimeBackend(state=runtime_state)
    lock_manager = LockManager()
    target_service = TargetService(runtime_backend, lock_manager=lock_manager)
    sync_service = SyncService(runtime_backend, lock_manager=lock_manager)
    core_gateway = CoreGateway(_RuntimeBackendCoreExecutor(runtime_backend))
    core_command_service = CoreCommandService(core_gateway)
    registry = ServiceRegistryAdapter(
        core_command_service=core_command_service,
        target_service=target_service,
        sync_service=sync_service,
    )
    effective_dispatcher_provider = dispatcher_provider or (lambda: dispatch_tool)
    effective_registry_provider = registry_provider or (lambda: registry)
    runtime = create_mcp_server(
        specs=registered_specs,
        registry_provider=effective_registry_provider,
        dispatcher_provider=effective_dispatcher_provider,
    )
    return CLIRuntimeBundle(
        registry=registry,
        runtime=runtime,
        runtime_backend=runtime_backend,
        lock_manager=lock_manager,
        target_service=target_service,
        sync_service=sync_service,
        core_command_service=core_command_service,
    )


__all__ = ["CLIRuntimeBundle", "ServiceRegistryAdapter", "create_cli_runtime"]
