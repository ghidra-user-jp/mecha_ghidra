"""Runtime wiring for presentation CLI."""

from __future__ import annotations

import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable

from ghidra_mcp.application.services.bsim_service import BsimConfig, BsimService
from ghidra_mcp.application.services.core_command_service import CoreCommandService
from ghidra_mcp.application.services.operations import PENDING_STATES, OperationManager
from ghidra_mcp.application.services.path_policy import PathPolicy
from ghidra_mcp.application.services.runtime_state import RuntimeState
from ghidra_mcp.application.services.script_service import ScriptConfig, ScriptService
from ghidra_mcp.application.services.sync_service import SyncService
from ghidra_mcp.application.services.target_service import TargetService
from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.infrastructure import CoreGateway, LockManager, RuntimeBackend
from ghidra_mcp.infrastructure.bsim import BsimJavaBackend
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.error_mapper import operation_error_payload
from ghidra_mcp.presentation.mcp_server import MCPServerRuntime, create_mcp_server
from ghidra_mcp.presentation.operation_presentation import present_operation_outcome
from ghidra_mcp.presentation.startup import StartupGate
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool, normalize_empty_list_result

# The signals that stop the server with the same cleanup: SIGHUP comes when the
# terminal or ssh session closes.  Windows has no SIGHUP.
SHUTDOWN_SIGNALS = tuple(getattr(signal, name) for name in ("SIGTERM", "SIGINT", "SIGHUP") if hasattr(signal, name))


def _attach_server_thread() -> None:
    """Attach a tool call's thread to the JVM under its own name (see attach_server_thread)."""
    from ghidra_headless.scripts.execution import attach_server_thread

    attach_server_thread()


@contextmanager
def _defer_shutdown_signals():
    """Finish worker/project cleanup before delivering a main-thread exit signal."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    handlers = {}
    pending = None

    def defer(signum, _frame):
        nonlocal pending
        if pending is None:
            pending = signum

    try:
        for signum in SHUTDOWN_SIGNALS:
            previous = signal.getsignal(signum)
            if previous != signal.SIG_IGN:
                handlers[signum] = signal.signal(signum, defer)
        yield
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        if pending is not None:
            signal.raise_signal(pending)


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
        "save_project_program": "_target_service",
        "close_session": "_target_service",
        "has_targets": "_target_service",
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
        "bsim_query": "_bsim_service",
        "bsim_load_matched_executable": "_bsim_service",
        "bsim_register_target": "_bsim_service",
        "bsim_apply_matches": "_bsim_service",
        "bsim_update_target_signatures": "_bsim_service",
        "bsim_delete_executable": "_bsim_service",
        # scripts
        "list_scripts": "_script_service",
        "get_script_info": "_script_service",
    }

    def __init__(
        self,
        *,
        core_command_service: CoreCommandService,
        target_service: TargetService,
        sync_service: SyncService,
        bsim_service: BsimService,
        script_service: ScriptService | None = None,
    ) -> None:
        self._core_command_service = core_command_service
        self._target_service = target_service
        self._sync_service = sync_service
        self._bsim_service = bsim_service
        # A disabled ScriptService keeps every forwarded name resolvable and answers SCRIPTS_DISABLED.
        self._script_service = script_service or ScriptService(None, config=ScriptConfig())
        self.operations = OperationManager(
            target_service, script_service=self._script_service, public_error=operation_error_payload
        )

    def __getattr__(self, name: str) -> Any:
        service_attr = self._FORWARDED.get(name)
        if service_attr is None:
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")
        service = getattr(self, service_attr)
        if service is None:
            raise AttributeError(f"{name!r} is not available: its service is not configured")
        return getattr(service, name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(self._FORWARDED))

    # background jobs
    def import_program(self, target: str, *, wait_seconds: float = 0, **kwargs):
        record = self.operations.submit_import(target, **kwargs)
        return self._wait_for_operation(record, wait_seconds)

    def analyze_program(self, target: str, *, wait_seconds: float = 0, **kwargs):
        record = self.operations.submit_analysis(target, **kwargs)
        return self._wait_for_operation(record, wait_seconds)

    def run_script(self, target: str, *, wait_seconds: float = 0, **kwargs):
        record = self.operations.submit_script(target, **kwargs)
        return self._wait_for_operation(record, wait_seconds)

    def get_operation(self, *, operation_id=None, request_id=None, wait_seconds: float = 0):
        record = self.operations.get(operation_id=operation_id, request_id=request_id)
        return self._wait_for_operation(record, wait_seconds)

    def cancel_operation(self, *, operation_id: str):
        return self.operations.cancel(operation_id)

    def _wait_for_operation(self, record: dict[str, Any], wait_seconds: float) -> dict[str, Any]:
        # Blocking wait for direct (non-MCP) callers; the MCP binding waits
        # asynchronously and always calls these with wait_seconds=0.
        if wait_seconds <= 0 or record["state"] not in PENDING_STATES:
            return record
        latest = self.operations.wait_for(record["operation_id"], wait_seconds)
        if "replayed" in record:
            latest["replayed"] = record["replayed"]
        return latest

    # core command path

    def close_all(self) -> None:
        # Join before any project/provider teardown, including stdio EOF.
        # Deferring signals also avoids interrupting Thread.join's bookkeeping.
        with _defer_shutdown_signals():
            self.operations.shutdown()
            self._target_service.close_all()

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
        output_path = self._target_service.validate_export_path(output_path)
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
    script_service: ScriptService


def create_cli_runtime(
    *,
    registered_specs: dict[str, ToolSpec],
    core_accessor: Callable[[], Any],
    checkout_required_commands: set[str],
    bsim_config: BsimConfig | None = None,
    presentation_config: ToolPresentationConfig | None = None,
    dispatcher_provider: Callable[[], Callable[..., Any]] | None = None,
    registry_provider: Callable[[], Any] | None = None,
    path_policy: PathPolicy | None = None,
    script_config: ScriptConfig | None = None,
    startup_gate: StartupGate | None = None,
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
    script_service = ScriptService(runtime_backend, config=script_config, lock_manager=lock_manager)
    registry = ServiceRegistryAdapter(
        core_command_service=core_command_service,
        target_service=target_service,
        sync_service=sync_service,
        bsim_service=bsim_service,
        script_service=script_service,
    )
    effective_dispatcher_provider = dispatcher_provider or (lambda: dispatch_tool)
    effective_registry_provider = registry_provider or (lambda: registry)
    runtime = create_mcp_server(
        specs=registered_specs,
        registry_provider=effective_registry_provider,
        dispatcher_provider=effective_dispatcher_provider,
        presentation_config=presentation_config,
        prepare_thread=_attach_server_thread,
        startup_gate=startup_gate,
        # The headless core's command_source: where the thread's last command left its program.
        command_source=lambda: core_accessor().command_source(),
    )
    # Large job results and script diagnostics go to the same result store as
    # any tool's, so job records stay small.
    registry.operations.present = partial(
        present_operation_outcome, config=runtime.presentation_config, store=runtime.result_store
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
        script_service=script_service,
    )


__all__ = ["SHUTDOWN_SIGNALS", "CLIRuntimeBundle", "ServiceRegistryAdapter", "create_cli_runtime"]
