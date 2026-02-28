"""Shared dispatcher for declarative tool specs."""

from __future__ import annotations

from typing import Any, Protocol

from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_tool_spec
from ghidra_mcp.presentation.error_mapper import map_exception


class CoreExecutorProtocol(Protocol):
    def execute(self, command: str, params: dict[str, Any], key: str) -> Any:
        """Execute a legacy core command under a target context."""


def _status_target_ok(_result: Any, target: str) -> dict[str, Any]:
    return {"status": "ok", "target": target}


def _status_program_ok(result: Any, target: str) -> dict[str, Any]:
    return {"status": "ok", "target": target, "program": result}


_RESULT_ADAPTERS = {
    "status_target_ok": _status_target_ok,
    "status_program_ok": _status_program_ok,
}


def _create_session_error(exc: Exception, target: str) -> RuntimeError:
    return RuntimeError(f"セッション '{target}' の作成に失敗しました: {exc}")


def _close_session_error(exc: Exception, target: str) -> RuntimeError:
    return RuntimeError(f"セッション '{target}' のクローズに失敗しました: {exc}")


def _close_remove_error(exc: Exception, target: str) -> RuntimeError:
    return RuntimeError(f"セッション '{target}' のクローズ/削除に失敗しました: {exc}")


_ERROR_ADAPTERS = {
    "create_session_error": _create_session_error,
    "close_session_error": _close_session_error,
    "close_remove_error": _close_remove_error,
}


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


def _validate_output(spec_name: str, model_cls, result: Any) -> Any:
    if model_cls is None:
        return result
    try:
        model_cls.model_validate(result)
    except ValidationError:
        try:
            model_cls.model_validate({"payload": result})
        except ValidationError as exc:
            raise ValueError(f"{spec_name} の出力検証に失敗しました: {exc}") from exc
    return result


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
    result_adapter = None
    if spec.result_adapter:
        result_adapter = _RESULT_ADAPTERS.get(spec.result_adapter)
        if result_adapter is None:
            raise RuntimeError(f"UNKNOWN_RESULT_ADAPTER: {spec.result_adapter}")
    error_adapter = None
    if spec.error_adapter:
        error_adapter = _ERROR_ADAPTERS.get(spec.error_adapter)
        if error_adapter is None:
            raise RuntimeError(f"UNKNOWN_ERROR_ADAPTER: {spec.error_adapter}")

    try:
        if spec.executor_kind == ExecutorKind.CORE_COMMAND:
            if hasattr(registry, "call"):
                result = registry.call(spec.command_or_method, params, target)
            elif core_executor is not None:
                result = core_executor.execute(spec.command_or_method, params, key=target)
            else:
                raise RuntimeError("CORE_EXECUTOR_UNAVAILABLE: core command dispatcherが利用できません")

        else:
            method = getattr(registry, spec.command_or_method)
            kwargs = {**params, **spec.static_kwargs}
            if spec.include_target:
                result = method(target, **kwargs)
            else:
                result = method(**kwargs)

        result = _validate_output(spec_name, spec.output_model, result)
        if result_adapter is not None:
            result = result_adapter(result, target)
    except Exception as exc:
        if error_adapter is not None:
            raise error_adapter(exc, target) from exc
        mapped = map_exception(exc)
        if mapped is not exc:
            raise mapped from exc
        raise

    return normalize_empty_list_result(result) if spec.empty_list_policy == "normalize" else result


__all__ = [
    "CoreExecutorProtocol",
    "dispatch_tool",
    "normalize_empty_list_result",
]
