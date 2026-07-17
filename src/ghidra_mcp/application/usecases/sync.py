"""Shared-sync use cases."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.infrastructure.ghidra_adapter.sync_gateway import SyncGateway


SYNC_COMMANDS: tuple[str, ...] = (
    "get_project_sync_status",
    "checkout_project_program",
    "add_project_program_to_version_control",
    "commit_project_program",
    "pull_project_program",
    "undo_checkout_project_program",
    "terminate_project_program_checkout",
    "delete_shared_project_file",
    "reload_project_program",
    "get_version_history",
    "get_version_diff",
)


class SyncUseCases:
    def __init__(self, sync_gateway: SyncGateway) -> None:
        self._sync_gateway = sync_gateway

    def execute(self, command: str, params: dict[str, Any], *, target: str) -> Any:
        if command not in SYNC_COMMANDS:
            raise ValueError(f"unsupported sync command: {command}")

        if command == "get_project_sync_status":
            return self._sync_gateway.get_project_sync_status(target, domain_path=params.get("domain_path"))
        if command == "checkout_project_program":
            return self._sync_gateway.checkout_project_program(
                target,
                exclusive=bool(params.get("exclusive", False)),
                domain_path=params.get("domain_path"),
            )
        if command == "add_project_program_to_version_control":
            return self._sync_gateway.add_project_program_to_version_control(
                target,
                comment=params["comment"],
                keep_checked_out=bool(params.get("keep_checked_out", False)),
                domain_path=params.get("domain_path"),
            )
        if command == "commit_project_program":
            return self._sync_gateway.commit_project_program(
                target,
                message=params["message"],
                keep_checked_out=bool(params.get("keep_checked_out", False)),
                auto_checkout=bool(params.get("auto_checkout", True)),
                on_conflict=params.get("on_conflict", "abort"),
                domain_path=params.get("domain_path"),
            )
        if command == "pull_project_program":
            return self._sync_gateway.pull_project_program(
                target,
                on_local_changes=params.get("on_local_changes", "abort"),
                domain_path=params.get("domain_path"),
            )
        if command == "undo_checkout_project_program":
            return self._sync_gateway.undo_checkout_project_program(
                target,
                discard_local_changes=bool(params.get("discard_local_changes", True)),
                domain_path=params.get("domain_path"),
            )
        if command == "terminate_project_program_checkout":
            return self._sync_gateway.terminate_project_program_checkout(
                target,
                checkout_id=int(params["checkout_id"]),
                domain_path=params.get("domain_path"),
            )
        if command == "delete_shared_project_file":
            return self._sync_gateway.delete_shared_project_file(
                target,
                domain_path=params["domain_path"],
                confirm=params["confirm"],
                expected_latest_version=params.get("expected_latest_version"),
                allow_private=bool(params.get("allow_private", False)),
                allow_non_atomic_versioned_delete=bool(
                    params.get("allow_non_atomic_versioned_delete", False)
                ),
            )
        if command == "reload_project_program":
            return self._sync_gateway.reload_project_program(target, domain_path=params.get("domain_path"))
        if command == "get_version_history":
            return self._sync_gateway.get_version_history(
                target,
                limit=int(params.get("limit", 50)),
                domain_path=params.get("domain_path"),
            )
        if command == "get_version_diff":
            return self._sync_gateway.get_version_diff(
                target,
                from_version=int(params["from_version"]),
                to_version=int(params["to_version"]),
                range_limit=int(params.get("range_limit", 200)),
                domain_path=params.get("domain_path"),
            )

        raise ValueError(f"unsupported sync command: {command}")


__all__ = ["SYNC_COMMANDS", "SyncUseCases"]
