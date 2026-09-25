"""Application service port contracts.

Infrastructure adapters implement these protocols; application code imports
only the protocols so the dependency direction stays application -> ports.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


class CoreGatewayPort(Protocol):
    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any: ...


class BsimBackendPort(Protocol):
    def get_ghidra_version(self) -> str | None: ...

    def get_database_status(self, bsim_url: str) -> dict[str, Any]: ...

    def list_categories(self, bsim_url: str) -> dict[str, Any]: ...

    def add_executable_category(self, bsim_url: str, *, category: str) -> dict[str, Any]: ...

    def list_executables(
        self,
        bsim_url: str,
        *,
        name: str | None = None,
        md5: str | None = None,
        arch: str | None = None,
        compiler: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]: ...

    def get_executable(self, bsim_url: str, *, md5: str | None = None, name: str | None = None) -> dict[str, Any]: ...

    def update_executable_metadata(
        self,
        bsim_url: str,
        *,
        categories: dict[str, list[str]],
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]: ...

    def delete_executable(
        self,
        bsim_url: str,
        *,
        md5: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]: ...


class OperationControl(Protocol):
    """Job control handed to a background import or analysis; the runtime drives it.

    ``expected_project_key`` is the project admission resolved; the runtime
    refuses to work anywhere else. An analysis also carries the
    ``expected_generation`` of the session it was accepted for (``None`` for an
    import); the runtime refuses to analyze any other session. ``check_active``
    raises once shutdown has begun; the runtime calls it as soon as it holds the
    job's locks and before it opens or changes anything. ``begin`` is called
    immediately before the loader or the analysis writes anything: from then on
    a failure may have left changes. ``bind_cancel`` registers (or with ``None``
    clears) the callable that cancels the running analysis; it runs at once if
    cancellation was already requested.
    """

    expected_project_key: str
    expected_generation: int | None

    def check_active(self) -> None: ...

    def begin(self) -> None: ...

    def bind_cancel(self, cancel: Callable[[], None] | None) -> None: ...


@dataclass(frozen=True)
class LoadedProgram:
    """The program a target holds, as analysis admission records it."""

    project_key: str
    domain_path: str
    # Changes whenever the target's session is replaced (load, reload, reopen, close).
    generation: int


class TargetRuntimePort(Protocol):
    def create_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]: ...

    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
        validate: Callable[[], None] | None = None,
    ) -> Any: ...

    def register_target(
        self, name: str, project_location: str, *, project_name: str | None = None
    ) -> dict[str, Any]: ...

    def list_targets(self) -> list[dict[str, Any]]: ...

    def list_programs(self, name: str) -> Any: ...

    def load_program(self, name: str, domain_path: str, *, version: int | None = None) -> dict[str, Any]: ...

    def create_repository_cache_project(
        self,
        project_location: str,
        *,
        project_name: str | None = None,
        repository_url: str,
    ) -> dict[str, Any]: ...

    def import_program(
        self,
        name: str,
        binary_path: str,
        *,
        control: OperationControl | None = None,
        **options: Any,
    ) -> str: ...

    def loaded_program(self, name: str) -> LoadedProgram: ...

    def analyze_program(self, name: str, *, force: bool = False, control: OperationControl) -> dict[str, Any]: ...

    def save_project_program(self, name: str, *, domain_path: str | None = None) -> dict[str, Any]: ...

    def close_session(self, name: str, *, remove_program: bool = False, discard_changes: bool = False) -> None: ...

    def close_all(self) -> None: ...

    def has_sessions(self) -> bool: ...

    def has_targets(self) -> bool: ...

    def project_lock_key(self, name: str) -> str | None: ...


class SyncRuntimePort(Protocol):
    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> dict[str, Any]: ...

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool | None = None,
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def terminate_project_program_checkout(
        self,
        name: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
        allow_non_atomic_versioned_delete: bool = False,
    ) -> dict[str, Any]: ...

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None) -> dict[str, Any]: ...

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        include_details: bool = False,
        details_limit: int = 20,
        domain_path: str | None = None,
    ) -> dict[str, Any]: ...

    def project_lock_key(self, name: str) -> str | None: ...


class ScriptRuntimePort(Protocol):
    """Runtime side of Ghidra script execution (JVM-bound)."""

    def script_runtime_availability(self) -> dict[str, bool]: ...

    def run_script(
        self, name: str, *, request: dict[str, Any], control: OperationControl | None = None
    ) -> dict[str, Any]: ...

    def project_lock_key(self, name: str) -> str | None: ...

    def loaded_program(self, name: str) -> LoadedProgram: ...


__all__ = [
    "BsimBackendPort",
    "CoreGatewayPort",
    "LoadedProgram",
    "OperationControl",
    "ScriptRuntimePort",
    "SyncRuntimePort",
    "TargetRuntimePort",
]
