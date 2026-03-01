"""Runtime wiring for presentation CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.types import CallToolResult, TextContent

from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.application.services.sync_service import SyncService
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.infrastructure import CoreGateway, LockManager, RuntimeBackend
from ghidra_mcp.presentation.mcp_server import MCPServerRuntime, create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


def _normalize_empty_list_result(result: Any) -> Any:
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


class _LazyCoreExecutor:
    """Resolve ghidra core module lazily to avoid import-time dependency on started JVM."""

    def __init__(self, core_accessor: Callable[[], Any]) -> None:
        self._core_accessor = core_accessor

    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        return self._core_accessor().execute(command, params, key=key)


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

    def import_program(self, target: str, binary_path: str):
        return self._target_service.import_program(target, binary_path)

    def create_session(
        self,
        target: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ):
        if domain_path is None:
            raise ValueError("domain_path を指定してください")
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
        domain_path: str | None = None,
    ):
        return self._sync_service.commit_project_program(
            target,
            message,
            keep_checked_out=keep_checked_out,
            auto_checkout=auto_checkout,
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
    core_gateway = CoreGateway(_LazyCoreExecutor(core_accessor))
    core_command_service = CoreCommandService(core_gateway)
    registry = ServiceRegistryAdapter(
        core_command_service=core_command_service,
        target_service=target_service,
        sync_service=sync_service,
    )
    effective_dispatcher_provider = dispatcher_provider or (lambda: dispatch_tool)
    effective_registry_provider = registry_provider or (lambda: registry)
    runtime = create_mcp_server(
        registry_provider=effective_registry_provider,
        dispatcher_provider=effective_dispatcher_provider,
        include_shared_sync=False,
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
