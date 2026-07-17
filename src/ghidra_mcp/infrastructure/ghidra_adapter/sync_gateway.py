"""Gateway for shared-project synchronization operations."""

from __future__ import annotations

from typing import Any


class SyncGateway:
    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def get_project_sync_status(self, target: str, *, domain_path: str | None = None):
        return self._registry.get_project_sync_status(target, domain_path=domain_path)

    def checkout_project_program(self, target: str, *, exclusive: bool = False, domain_path: str | None = None):
        return self._registry.checkout_project_program(target, exclusive=exclusive, domain_path=domain_path)

    def add_project_program_to_version_control(
        self,
        target: str,
        *,
        comment: str,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        return self._registry.add_project_program_to_version_control(
            target,
            comment=comment,
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
        return self._registry.commit_project_program(
            target,
            message=message,
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
        return self._registry.pull_project_program(
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
        return self._registry.undo_checkout_project_program(
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
        return self._registry.terminate_project_program_checkout(
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
        allow_non_atomic_versioned_delete: bool = False,
    ):
        return self._registry.delete_shared_project_file(
            target,
            domain_path=domain_path,
            confirm=confirm,
            expected_latest_version=expected_latest_version,
            allow_private=allow_private,
            allow_non_atomic_versioned_delete=allow_non_atomic_versioned_delete,
        )

    def reload_project_program(self, target: str, *, domain_path: str | None = None):
        return self._registry.reload_project_program(target, domain_path=domain_path)

    def get_version_history(self, target: str, *, limit: int = 50, domain_path: str | None = None):
        return self._registry.get_version_history(target, limit=limit, domain_path=domain_path)

    def get_version_diff(
        self,
        target: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        return self._registry.get_version_diff(
            target,
            from_version=from_version,
            to_version=to_version,
            range_limit=range_limit,
            domain_path=domain_path,
        )


__all__ = ["SyncGateway"]
