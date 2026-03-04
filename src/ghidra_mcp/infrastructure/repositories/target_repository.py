"""Repository for target metadata/state."""

from __future__ import annotations

from typing import Any

from ghidra_mcp.domain import DomainError, ErrorCode


class TargetRepository:
    def __init__(self, registry: Any) -> None:
        self._registry = registry

    def list_targets(self) -> list[dict[str, Any]]:
        return list(self._registry.list_targets())

    def ensure_target_exists(self, target: str) -> None:
        targets = self.list_targets()
        if any(item.get("target") == target for item in targets):
            return
        raise DomainError(
            code=ErrorCode.TARGET_NOT_REGISTERED,
            message=f"Target '{target}' is not registered",
            hint="Run register_target or create_session first",
            retryable=False,
            details={"target": target},
        )


__all__ = ["TargetRepository"]
