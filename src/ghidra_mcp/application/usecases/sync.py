"""Target/synchronization application services."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure import LockManager, ProgramLease, ProjectGateway, SyncGateway, TargetRepository


class TargetService:
    def __init__(
        self,
        *,
        project_gateway: ProjectGateway,
        target_repository: TargetRepository,
        lock_manager: LockManager,
    ) -> None:
        self._project_gateway = project_gateway
        self._target_repository = target_repository
        self._lock_manager = lock_manager

    def list_targets(self) -> list[dict[str, Any]]:
        return self._target_repository.list_targets()

    def list_project_programs(self, target: str):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.list_project_programs(target)

    def register_target(self, target: str, *, project_location: str, project_name: str | None = None):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.register_target(
                target,
                project_location=project_location,
                project_name=project_name,
            )

    def load_project_program(self, target: str, *, domain_path: str):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.load_project_program(target, domain_path=domain_path)

    def import_program(self, target: str, *, binary_path: str):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.import_program(target, binary_path=binary_path)

    def create_session(
        self,
        target: str,
        *,
        project_location: str,
        domain_path: str,
        project_name: str | None = None,
    ):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.create_session(
                target,
                project_location=project_location,
                project_name=project_name,
                domain_path=domain_path,
            )

    def close_session(self, target: str, *, remove_program: bool = False):
        with self._lock_manager.acquire(target=target):
            return self._project_gateway.close_session(target, remove_program=remove_program)


class SyncService:
    def __init__(
        self,
        *,
        sync_gateway: SyncGateway,
        target_repository: TargetRepository,
        lock_manager: LockManager,
    ) -> None:
        self._sync_gateway = sync_gateway
        self._target_repository = target_repository
        self._lock_manager = lock_manager

    def _guard_target(self, target: str) -> None:
        self._target_repository.ensure_target_exists(target)

    def get_project_sync_status(self, target: str, *, domain_path: str | None = None):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.get_project_sync_status(target, domain_path=domain_path)

    def checkout_project_program(self, target: str, *, exclusive: bool = False, domain_path: str | None = None):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.checkout_project_program(
                target,
                exclusive=exclusive,
                domain_path=domain_path,
            )

    def add_project_program_to_version_control(
        self,
        target: str,
        *,
        comment: str,
        keep_checked_out: bool = False,
        domain_path: str | None = None,
    ):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.add_project_program_to_version_control(
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
        domain_path: str | None = None,
    ):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.commit_project_program(
                target,
                message=message,
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
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.pull_project_program(
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
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.undo_checkout_project_program(
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
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.terminate_project_program_checkout(
                target,
                checkout_id=checkout_id,
                domain_path=domain_path,
            )

    def reload_project_program(self, target: str, *, domain_path: str | None = None):
        self._guard_target(target)
        lease = ProgramLease(
            before_close=lambda: None,
            do_operation=lambda: self._sync_gateway.reload_project_program(target, domain_path=domain_path),
            reopen=lambda: None,
        )
        with self._lock_manager.acquire(target=target):
            return lease.run()

    def get_version_history(self, target: str, *, limit: int = 50, domain_path: str | None = None):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.get_version_history(target, limit=limit, domain_path=domain_path)

    def get_version_diff(
        self,
        target: str,
        *,
        from_version: int,
        to_version: int,
        range_limit: int = 200,
        domain_path: str | None = None,
    ):
        self._guard_target(target)
        with self._lock_manager.acquire(target=target):
            return self._sync_gateway.get_version_diff(
                target,
                from_version=from_version,
                to_version=to_version,
                range_limit=range_limit,
                domain_path=domain_path,
            )


__all__ = ["SyncService", "TargetService"]
