"""Application service port contracts."""

from __future__ import annotations

from typing import Any, Protocol


class CoreCommandRuntimePort(Protocol):
    def call(self, command: str, params: dict[str, Any] | None = None, target: str = "default") -> Any:
        ...


class TargetRuntimePort(Protocol):
    def create_session(
        self,
        name: str,
        project_location: str,
        *,
        project_name: str | None = None,
        domain_path: str | None = None,
    ) -> Any:
        ...

    def register_target(self, name: str, project_location: str, *, project_name: str | None = None) -> dict[str, Any]:
        ...

    def list_targets(self) -> list[dict[str, Any]]:
        ...

    def list_programs(self, name: str) -> Any:
        ...

    def load_program(self, name: str, domain_path: str) -> str:
        ...

    def import_program(self, name: str, binary_path: str) -> str:
        ...

    def close_session(self, name: str, *, remove_program: bool = False) -> None:
        ...

    def close_all(self) -> None:
        ...

    def has_sessions(self) -> bool:
        ...

    def has_targets(self) -> bool:
        ...

    def project_lock_key(self, name: str) -> str | None:
        ...


class SyncRuntimePort(Protocol):
    def get_project_sync_status(self, name: str, *, domain_path: str | None = None) -> dict[str, Any]:
        ...

    def checkout_project_program(
        self,
        name: str,
        *,
        exclusive: bool = False,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def add_project_program_to_version_control(
        self,
        name: str,
        comment: str,
        *,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def commit_project_program(
        self,
        name: str,
        message: str,
        *,
        keep_checked_out: bool = False,
        auto_checkout: bool = True,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def pull_project_program(
        self,
        name: str,
        *,
        on_local_changes: str = "abort",
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def undo_checkout_project_program(
        self,
        name: str,
        *,
        discard_local_changes: bool = True,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def terminate_project_program_checkout(
        self,
        name: str,
        *,
        checkout_id: int,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def reload_project_program(self, name: str, *, domain_path: str | None = None) -> dict[str, Any]:
        ...

    def get_version_history(self, name: str, *, limit: int = 50, domain_path: str | None = None) -> dict[str, Any]:
        ...

    def get_version_diff(
        self,
        name: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ) -> dict[str, Any]:
        ...

    def project_lock_key(self, name: str) -> str | None:
        ...


__all__ = ["CoreCommandRuntimePort", "SyncRuntimePort", "TargetRuntimePort"]
