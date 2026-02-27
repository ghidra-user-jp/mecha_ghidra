"""Shared dispatcher for declarative tool specs."""

from __future__ import annotations

from typing import Any, Protocol

from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_tool_spec


class CoreExecutorProtocol(Protocol):
    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        """Execute a legacy core command under a target context."""


def normalize_empty_list_result(result: Any) -> Any:
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


def _validate_raw_args(spec_name: str, model_cls, raw_args: dict[str, Any] | None) -> dict[str, Any]:
    try:
        parsed = model_cls.model_validate(raw_args or {})
    except ValidationError as exc:
        raise ValueError(f"{spec_name} の入力検証に失敗しました: {exc}") from exc
    return parsed.model_dump(exclude_none=True)


def dispatch_tool(
    spec_name: str,
    raw_args: dict[str, Any] | None,
    target: str,
    *,
    registry,
    core_executor: CoreExecutorProtocol | None = None,
) -> Any:
    spec = get_tool_spec(spec_name)
    params = _validate_raw_args(spec_name, spec.input_model, raw_args)

    if spec.executor_kind == ExecutorKind.CORE_COMMAND:
        if hasattr(registry, "call"):
            result = registry.call(spec.command_or_method, params, target)
        elif core_executor is not None:
            result = core_executor.execute(spec.command_or_method, params, key=target)
        else:
            raise RuntimeError("CORE_EXECUTOR_UNAVAILABLE: core command dispatcherが利用できません")
        return normalize_empty_list_result(result) if spec.empty_list_policy == "normalize" else result

    method = getattr(registry, spec.command_or_method)
    kwargs = {**params, **spec.static_kwargs}
    if spec.include_target:
        result = method(target, **kwargs)
    else:
        result = method(**kwargs)

    return normalize_empty_list_result(result) if spec.empty_list_policy == "normalize" else result


__all__ = [
    "CoreExecutorProtocol",
    "dispatch_tool",
    "normalize_empty_list_result",
]
