"""Runtime error normalization helpers."""

from __future__ import annotations

from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.domain.error_mapping import to_domain_error as _to_domain_error

_SYNC_OPERATIONS = frozenset(
    {
        "get_project_sync_status",
        "checkout_project_program",
        "add_project_program_to_version_control",
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "delete_shared_project_file",
        "get_version_history",
        "get_version_diff",
    }
)


def to_domain_error(
    exc: Exception,
    *,
    operation: str,
    target: str | None = None,
    domain_path: str | None = None,
) -> DomainError:
    """Map a runtime failure; unclassified sync operations default to SYNC_OPERATION_FAILED."""

    default_code = ErrorCode.SYNC_OPERATION_FAILED if operation in _SYNC_OPERATIONS else ErrorCode.OPERATION_FAILED
    return _to_domain_error(exc, operation=operation, target=target, domain_path=domain_path, default_code=default_code)


__all__ = ["to_domain_error"]
