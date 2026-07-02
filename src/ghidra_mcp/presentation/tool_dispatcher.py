"""Shared dispatcher for declarative tool specs."""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.error_mapper import map_exception
from ghidra_mcp.presentation.result_resources import ResultResourceStore, maybe_compact_tool_result


def _status_target_ok(result: Any, target: str) -> dict[str, Any]:
    if isinstance(result, dict):
        adapted = {"status": "ok", **result}
        adapted.setdefault("target", target)
        return adapted
    return {"status": "ok", "target": target}


def _status_program_ok(result: Any, target: str) -> dict[str, Any]:
    return {"status": "ok", "target": target, "program": result}


_RESULT_ADAPTERS = {
    "status_target_ok": _status_target_ok,
    "status_program_ok": _status_program_ok,
}


def _create_session_error(_exc: Exception, target: str) -> Exception:
    mapped = map_exception(_exc)
    if mapped is not _exc:
        return mapped
    return RuntimeError(f"Failed to create session '{target}'")


def _close_session_error(_exc: Exception, target: str) -> Exception:
    mapped = map_exception(_exc)
    if mapped is not _exc:
        return mapped
    return RuntimeError(f"Failed to close session '{target}'")


def _close_remove_error(_exc: Exception, target: str) -> Exception:
    mapped = map_exception(_exc)
    if mapped is not _exc:
        return mapped
    return RuntimeError(f"Failed to close/remove session '{target}'")


_ERROR_ADAPTERS = {
    "create_session_error": _create_session_error,
    "close_session_error": _close_session_error,
    "close_remove_error": _close_remove_error,
}


def normalize_empty_list_result(result: Any) -> Any:
    if isinstance(result, list) and len(result) == 0:
        return CallToolResult(content=[TextContent(type="text", text="[]")])
    return result


def _empty_list_payload_from_call_tool_result(result: Any) -> list[Any] | None:
    if not isinstance(result, CallToolResult):
        return None
    if result.isError:
        return None
    if len(result.content) != 1:
        return None
    item = result.content[0]
    if not isinstance(item, TextContent):
        return None
    if item.text != "[]":
        return None
    return []


def _validate_raw_args(spec_name: str, model_cls, raw_args: dict[str, Any] | None) -> dict[str, Any]:
    try:
        parsed = model_cls.model_validate(raw_args or {})
    except ValidationError as exc:
        raise ValueError(f"{spec_name} input validation failed: {exc}") from exc
    return parsed.model_dump(exclude_none=True)


def _validate_output(spec_name: str, model_cls, result: Any) -> Any:
    if model_cls is None:
        return result
    empty_list_payload = _empty_list_payload_from_call_tool_result(result)
    if empty_list_payload is not None:
        try:
            model_cls.model_validate({"payload": empty_list_payload})
            return result
        except ValidationError:
            pass
    try:
        model_cls.model_validate(result)
    except ValidationError:
        try:
            model_cls.model_validate({"payload": result})
        except ValidationError as exc:
            raise ValueError(f"{spec_name} output validation failed: {exc}") from exc
    return result


def dispatch_tool(
    spec_name: str,
    raw_args: dict[str, Any] | None,
    target: str,
    *,
    registry,
    presentation_config: ToolPresentationConfig | None = None,
    result_store: ResultResourceStore | None = None,
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
            if not hasattr(registry, "call"):
                raise RuntimeError("CORE_EXECUTOR_UNAVAILABLE: core command dispatcher is unavailable")
            result = registry.call(spec.command_or_method, params, target)

        else:
            method = getattr(registry, spec.command_or_method)
            kwargs = {**params, **spec.static_kwargs}
            if spec.include_target:
                result = method(target, **kwargs)
            else:
                result = method(**kwargs)
    except Exception as exc:
        if error_adapter is not None:
            raise error_adapter(exc, target) from exc
        mapped = map_exception(exc)
        if mapped is not exc:
            raise mapped from exc
        raise

    if result_adapter is not None:
        result = result_adapter(result, target)
    result = _validate_output(spec_name, spec.output_model, result)
    if spec.empty_list_policy == "normalize":
        result = normalize_empty_list_result(result)
    return maybe_compact_tool_result(
        tool_name=spec_name,
        target=target,
        result=result,
        config=presentation_config or ToolPresentationConfig(),
        store=result_store,
    )


__all__ = [
    "dispatch_tool",
    "normalize_empty_list_result",
]
