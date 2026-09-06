"""Ghidra runtime backend implementing target/sync/core operations.

``RuntimeBackend`` is the single entry point the application services talk to.
Each public method forwards to one of three runtime components and converts
any failure into a ``DomainError`` tagged with the operation name, the target,
and the domain path.  The forwarding is declared once by the ``_delegate``
decorator so the methods below only spell out their public signatures.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, Dict, List, Optional

from ghidra_headless.session import ProgramSession
from ghidra_mcp.application.services.runtime_state import RuntimeState

from .runtime import RuntimeCoreExecution, RuntimeSessionStore, RuntimeSyncOperations, RuntimeTargetLifecycle
from .runtime.errors import to_domain_error


def _delegate(component: str, *, operation: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Forward the decorated method to ``self.<component>.<same name>``.

    ``target`` is read from the ``name``/``target`` argument and ``domain_path``
    from the argument of that name, so error details stay consistent without
    repeating them at every call site.
    """

    def decorator(method: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(method)
        operation_name = operation or method.__name__

        @functools.wraps(method)
        def wrapper(self: RuntimeBackend, *args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(self, *args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            arguments.pop("self", None)
            target = arguments.get("name", arguments.get("target"))
            domain_path = arguments.get("domain_path")
            impl = getattr(getattr(self, component), method.__name__)
            try:
                return impl(*args, **kwargs)
            except Exception as exc:
                raise to_domain_error(
                    exc,
                    operation=operation_name,
                    target=target,
                    domain_path=domain_path if isinstance(domain_path, str) else None,
                ) from exc

        return wrapper

    return decorator


class RuntimeBackend:
    """Façade over the runtime components with uniform error mapping."""

    def __init__(self, *, state: RuntimeState) -> None:
        store = RuntimeSessionStore(state=state, core_accessor=state.core_accessor)
        self._store = store
        self._target_lifecycle = RuntimeTargetLifecycle(store=store)
        self._sync_operations = RuntimeSyncOperations(store=store)
        self._core_execution = RuntimeCoreExecution(
            store=store,
            checkout_required_commands=set(state.checkout_required_commands),
            normalize_result=state.normalize_result,
        )

    # ---- target lifecycle -------------------------------------------------

    @_delegate("_target_lifecycle")
    def create_project(
        self, project_location: str, *, project_name: str | None = None, overwrite: bool = False
    ) -> Dict[str, Any]: ...

    @_delegate("_target_lifecycle")
    def create_session(
        self, name: str, project_location: str, *, project_name: str | None = None, domain_path: str | None = None
    ) -> ProgramSession: ...

    @_delegate("_target_lifecycle")
    def register_target(
        self, name: str, project_location: str, *, project_name: str | None = None
    ) -> Dict[str, Optional[str]]: ...

    @_delegate("_target_lifecycle")
    def list_targets(self) -> List[Dict[str, Optional[str]]]: ...

    @_delegate("_target_lifecycle")
    def list_programs(self, name: str): ...

    @_delegate("_target_lifecycle")
    def load_program(self, name: str, domain_path: str, *, version: int | None = None) -> Dict[str, Any]: ...

    @_delegate("_target_lifecycle")
    def create_repository_cache_project(
        self, project_location: str, *, project_name: str | None = None, repository_url: str
    ) -> Dict[str, Any]: ...

    @_delegate("_target_lifecycle")
    def import_program(self, name: str, binary_path: str, **kwargs) -> str: ...

    @_delegate("_target_lifecycle")
    def save_project_program(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]: ...

    @_delegate("_target_lifecycle")
    def close_session(self, name: str, *, remove_program: bool = False) -> None: ...

    @_delegate("_target_lifecycle")
    def close_all(self) -> None: ...

    # ---- core commands ----------------------------------------------------

    def execute_core_command(
        self, command: str, params: Dict[str, Any] | None = None, *, target: str = "default"
    ) -> Any:
        try:
            return self._core_execution.call(command, params or {}, target=target)
        except Exception as exc:
            raise to_domain_error(exc, operation=command, target=target) from exc

    # ---- shared-project sync ----------------------------------------------

    @_delegate("_sync_operations")
    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def checkout_project_program(
        self, name: str, *, exclusive: bool | None = None, domain_path: str | None = None
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def add_project_program_to_version_control(
        self, name: str, comment: str, *, keep_checked_out: bool = False, domain_path: str | None = None
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        on_conflict: str = "abort",
        domain_path: str | None = None,
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def pull_project_program(
        self, name: str, *, on_local_changes: str = "abort", domain_path: str | None = None
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def undo_checkout_project_program(
        self, name: str, *, discard_local_changes: bool = True, domain_path: str | None = None
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def terminate_project_program_checkout(
        self, name: str, checkout_id: int, *, domain_path: str | None = None
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def delete_shared_project_file(
        self,
        name: str,
        *,
        domain_path: str,
        confirm: str,
        expected_latest_version: int | None = None,
        allow_private: bool = False,
        allow_non_atomic_versioned_delete: bool = False,
    ) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
    def get_version_history(self, name: str, *, domain_path: str | None = None, limit: int = 50) -> Dict[str, Any]: ...

    @_delegate("_sync_operations")
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
    ) -> Dict[str, Any]: ...

    # ---- state queries (no error mapping needed) -------------------------

    def has_sessions(self) -> bool:
        return self._store.has_sessions()

    def has_targets(self) -> bool:
        return self._store.has_targets()

    def project_lock_key(self, name: str) -> str | None:
        return self._store.project_lock_key(name)


__all__ = ["RuntimeBackend"]
