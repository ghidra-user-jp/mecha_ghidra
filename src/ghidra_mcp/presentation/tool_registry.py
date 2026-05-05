"""Dynamic MCP tool registration from declarative ToolSpec."""

from __future__ import annotations

import inspect
from typing import Any, Callable

from mcp.types import ToolAnnotations

from ghidra_mcp.contracts.tool_spec import (
    ExecutorKind,
    ToolSpec,
)


def _public_name(spec: ToolSpec, raw_key: str) -> str:
    return spec.public_name_overrides.get(raw_key, raw_key)


def _build_signature(spec: ToolSpec) -> inspect.Signature:
    params: list[inspect.Parameter] = []

    if spec.executor_kind in {ExecutorKind.REGISTRY_METHOD, ExecutorKind.SHARED_SYNC_METHOD} and spec.include_target:
        params.append(
            inspect.Parameter(
                "target",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str,
            )
        )

    for raw_key, field in spec.input_model.model_fields.items():
        public_name = _public_name(spec, raw_key)
        default = inspect.Parameter.empty if field.is_required() else field.default
        params.append(
            inspect.Parameter(
                public_name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=field.annotation,
            )
        )

    if spec.executor_kind == ExecutorKind.CORE_COMMAND and spec.include_target:
        params.append(
            inspect.Parameter(
                "target",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default="default",
                annotation=str,
            )
        )

    return inspect.Signature(params)


def _build_raw_args(spec: ToolSpec, bound: inspect.BoundArguments) -> tuple[dict[str, Any], str]:
    raw_args: dict[str, Any] = {}
    for raw_key in spec.input_model.model_fields:
        public_key = _public_name(spec, raw_key)
        value = bound.arguments.get(public_key)
        if raw_key in spec.omit_falsey_keys and not value:
            continue
        if value is None and raw_key not in spec.include_none_keys:
            continue
        raw_args[raw_key] = value

    if spec.executor_kind == ExecutorKind.CORE_COMMAND:
        target = bound.arguments.get("target", "default")
    elif spec.include_target:
        target = bound.arguments["target"]
    else:
        target = "default"

    return raw_args, target


def _build_callable(
    spec: ToolSpec,
    *,
    dispatcher_provider: Callable[[], Callable[..., Any]],
    registry_provider: Callable[[], Any],
) -> Callable[..., Any]:
    signature = _build_signature(spec)

    def _tool_callable(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        if spec.name == "search_functions_by_name" and not bound.arguments.get("query"):
            raise ValueError("query is required")
        raw_args, target = _build_raw_args(spec, bound)
        dispatcher = dispatcher_provider()
        return dispatcher(spec.name, raw_args, target, registry=registry_provider())

    _tool_callable.__name__ = spec.name
    _tool_callable.__qualname__ = spec.name
    _tool_callable.__doc__ = spec.description or f"Auto-generated MCP wrapper for {spec.name}."
    _tool_callable.__signature__ = signature  # type: ignore[attr-defined]
    annotations: dict[str, Any] = {
        param.name: param.annotation
        for param in signature.parameters.values()
        if param.annotation is not inspect.Parameter.empty
    }
    _tool_callable.__annotations__ = annotations
    return _tool_callable


def build_tool_functions(
    *,
    specs: dict[str, ToolSpec],
    dispatcher_provider: Callable[[], Callable[..., Any]],
    registry_provider: Callable[[], Any],
) -> dict[str, Callable[..., Any]]:
    tools: dict[str, Callable[..., Any]] = {}
    for spec in specs.values():
        callable_obj = _build_callable(
            spec,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
        )
        tools[spec.name] = callable_obj
    return tools


def _tool_registration_options(spec: ToolSpec) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if spec.description:
        options["description"] = spec.description
    if (
        spec.read_only_hint is not None
        or spec.destructive_hint is not None
        or spec.idempotent_hint is not None
    ):
        options["annotations"] = ToolAnnotations(
            readOnlyHint=spec.read_only_hint,
            destructiveHint=spec.destructive_hint,
            idempotentHint=spec.idempotent_hint,
        )
    return options


def register_tool_functions(
    mcp,
    *,
    tools: dict[str, Callable[..., Any]],
    specs: dict[str, ToolSpec],
) -> None:
    for spec in specs.values():
        decorator = mcp.tool(**_tool_registration_options(spec))
        decorator(tools[spec.name])


class ToolRegistry:
    @staticmethod
    def register_all(
        mcp,
        specs: dict[str, ToolSpec],
        dispatcher_provider: Callable[[], Callable[..., Any]],
        registry_provider: Callable[[], Any],
    ) -> dict[str, Callable[..., Any]]:
        tools = build_tool_functions(
            specs=specs,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
        )
        register_tool_functions(mcp, tools=tools, specs=specs)
        return tools


__all__ = [
    "ToolRegistry",
    "build_tool_functions",
    "register_tool_functions",
]
