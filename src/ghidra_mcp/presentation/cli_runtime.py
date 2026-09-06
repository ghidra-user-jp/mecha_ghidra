"""Runtime wiring for presentation CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ghidra_mcp.application.services.bsim_service import BsimConfig, BsimService
from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.application.services.sync_service import SyncService
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.infrastructure import CoreGateway, LockManager, RuntimeBackend
from ghidra_mcp.infrastructure.bsim import BsimJavaBackend
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import MCPServerRuntime, create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool, normalize_empty_list_result


class ServiceRegistryAdapter:
    """Facade the tool dispatcher calls by method name.

    Every registry/shared-sync tool spec names a method here.  Most of them are
    straight pass-throughs to one service, so they are declared in
    ``_FORWARDED`` (method name -> service attribute) and resolved by
    ``__getattr__``; only methods that add behaviour are written out.
    """

    _FORWARDED: dict[str, str] = {
        # target/project lifecycle
        "list_targets": "_target_service",
        "create_project": "_target_service",
        "list_programs": "_target_service",
        "register_target": "_target_service",
        "load_program": "_target_service",
        "import_program": "_target_service",
        "save_project_program": "_target_service",
        "close_session": "_target_service",
        "has_targets": "_target_service",
        "close_all": "_target_service",
        # shared-project sync
        "get_project_sync_status": "_sync_service",
        "checkout_project_program": "_sync_service",
        "add_project_program_to_version_control": "_sync_service",
        "commit_project_program": "_sync_service",
        "pull_project_program": "_sync_service",
        "undo_checkout_project_program": "_sync_service",
        "terminate_project_program_checkout": "_sync_service",
        "delete_shared_project_file": "_sync_service",
        "get_version_history": "_sync_service",
        "get_version_diff": "_sync_service",
        # bsim
        "get_bsim_database_status": "_bsim_service",
        "bsim_add_executable_category": "_bsim_service",
        "list_bsim_executables": "_bsim_service",
        "get_bsim_executable": "_bsim_service",
        "bsim_update_executable_metadata": "_bsim_service",
        "bsim_query_target": "_bsim_service",
        "bsim_query_function": "_bsim_service",
        "bsim_load_matched_executable": "_bsim_service",
        "bsim_register_target": "_bsim_service",
        "bsim_apply_matches": "_bsim_service",
        "bsim_update_target_signatures": "_bsim_service",
        "bsim_delete_executable": "_bsim_service",
    }

    def __init__(
        self,
        *,
        core_command_service: CoreCommandService,
        target_service: TargetService,
        sync_service: SyncService,
        bsim_service: BsimService,
    ) -> None:
        self._core_command_service = core_command_service
        self._target_service = target_service
        self._sync_service = sync_service
        self._bsim_service = bsim_service

    def __getattr__(self, name: str) -> Any:
        service_attr = self._FORWARDED.get(name)
        if service_attr is None:
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")
        return getattr(getattr(self, service_attr), name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(self._FORWARDED))

    # core command path
    def call(self, command: str, params: dict[str, Any], target: str):
        return self._core_command_service.call(command, params, target)

    def export_program(
        self,
        target: str,
        output_path: str,
        *,
        format: str = "gzf",
        overwrite: bool = False,
    ):
        """Export runs in the JVM, but the output path is an operator-policed filesystem write."""
        self._target_service.validate_export_path(output_path)
        return self._core_command_service.call(
            "export_program",
            {"output_path": output_path, "format": format, "overwrite": overwrite},
            target,
        )

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


@dataclass(slots=True)
class CLIRuntimeBundle:
    registry: ServiceRegistryAdapter
    runtime: MCPServerRuntime
    runtime_backend: RuntimeBackend
    lock_manager: LockManager
    target_service: TargetService
    sync_service: SyncService
    bsim_service: BsimService
    core_command_service: CoreCommandService


def create_cli_runtime(
    *,
    registered_specs: dict[str, ToolSpec],
    core_accessor: Callable[[], Any],
    checkout_required_commands: set[str],
    bsim_config: BsimConfig | None = None,
    presentation_config: ToolPresentationConfig | None = None,
    dispatcher_provider: Callable[[], Callable[..., Any]] | None = None,
    registry_provider: Callable[[], Any] | None = None,
    server_log_level: str | None = None,
    path_policy: PathPolicy | None = None,
) -> CLIRuntimeBundle:
    runtime_state = RuntimeState(
        core_accessor=core_accessor,
        checkout_required_commands=set(checkout_required_commands),
        normalize_result=normalize_empty_list_result,
    )
    runtime_backend = RuntimeBackend(state=runtime_state)
    lock_manager = LockManager()
    target_service = TargetService(runtime_backend, lock_manager=lock_manager, path_policy=path_policy)
    sync_service = SyncService(runtime_backend, lock_manager=lock_manager)
    core_gateway = CoreGateway(runtime_backend)
    core_command_service = CoreCommandService(core_gateway)
    bsim_service = BsimService(
        core_command_service=core_command_service,
        target_service=target_service,
        config=bsim_config,
        java_backend=BsimJavaBackend(),
    )
    registry = ServiceRegistryAdapter(
        core_command_service=core_command_service,
        target_service=target_service,
        sync_service=sync_service,
        bsim_service=bsim_service,
    )
    effective_dispatcher_provider = dispatcher_provider or (lambda: dispatch_tool)
    effective_registry_provider = registry_provider or (lambda: registry)
    runtime = create_mcp_server(
        specs=registered_specs,
        registry_provider=effective_registry_provider,
        dispatcher_provider=effective_dispatcher_provider,
        presentation_config=presentation_config,
        server_log_level=server_log_level,
    )
    return CLIRuntimeBundle(
        registry=registry,
        runtime=runtime,
        runtime_backend=runtime_backend,
        lock_manager=lock_manager,
        target_service=target_service,
        sync_service=sync_service,
        bsim_service=bsim_service,
        core_command_service=core_command_service,
    )


__all__ = ["CLIRuntimeBundle", "ServiceRegistryAdapter", "create_cli_runtime"]
