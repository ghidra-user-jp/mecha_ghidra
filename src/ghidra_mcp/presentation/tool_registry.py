"""Dynamic MCP tool registration from declarative ToolSpec."""

from __future__ import annotations

import inspect
import re
from typing import Any, Callable

from mcp.types import ToolAnnotations

from ghidra_mcp.contracts.tool_spec import (
    ExecutorKind,
    ToolSafetyTag,
    ToolSpec,
)
from ghidra_mcp.presentation.config import ToolDescriptionMode, ToolPresentationConfig


_SHORT_DESCRIPTION_MAX_CHARS = 180


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
    presentation_config: ToolPresentationConfig,
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
    _tool_callable.__doc__ = select_tool_description(spec, presentation_config.description_mode)
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
    presentation_config: ToolPresentationConfig | None = None,
) -> dict[str, Callable[..., Any]]:
    effective_config = presentation_config or ToolPresentationConfig()
    tools: dict[str, Callable[..., Any]] = {}
    for spec in specs.values():
        callable_obj = _build_callable(
            spec,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
            presentation_config=effective_config,
        )
        tools[spec.name] = callable_obj
    return tools


def _first_sentence_or_truncate(text: str) -> str:
    normalized = " ".join(text.split())
    if not normalized:
        return ""
    sentence = re.match(r"^.*?[.!?。！？](?:\s|$)", normalized)
    if sentence:
        return sentence.group(0).strip()
    if len(normalized) <= _SHORT_DESCRIPTION_MAX_CHARS:
        return normalized
    return normalized[: _SHORT_DESCRIPTION_MAX_CHARS - 3].rstrip() + "..."


def select_tool_description(spec: ToolSpec, mode: ToolDescriptionMode) -> str | None:
    if mode == "none":
        return None
    if mode == "full":
        return spec.description
    if mode != "short":
        raise ValueError(f"Unsupported tool description mode: {mode!r}")
    if spec.short_description:
        return spec.short_description
    if spec.description:
        shortened = _first_sentence_or_truncate(spec.description)
        if shortened:
            return shortened
    # No synthetic filler: a description-less tool costs less context as None
    # than as boilerplate, and the docs resource carries the details.
    return None


def tool_annotations_for_spec(spec: ToolSpec) -> ToolAnnotations | None:
    read_only_hint = True if spec.safety_tag == ToolSafetyTag.READ_ONLY else None
    destructive_hint = True if spec.safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE else None

    if (
        read_only_hint is not None
        or destructive_hint is not None
        or spec.idempotent_hint is not None
    ):
        return ToolAnnotations(
            readOnlyHint=read_only_hint,
            destructiveHint=destructive_hint,
            idempotentHint=spec.idempotent_hint,
        )
    return None


def _tool_registration_options(
    spec: ToolSpec,
    presentation_config: ToolPresentationConfig | None = None,
) -> dict[str, Any]:
    effective_config = presentation_config or ToolPresentationConfig()
    options: dict[str, Any] = {}
    description = select_tool_description(spec, effective_config.description_mode)
    if description is not None:
        options["description"] = description

    annotations = tool_annotations_for_spec(spec)
    if annotations is not None:
        options["annotations"] = annotations
    return options


def _clear_registered_tool_description(mcp, tool_name: str) -> None:
    tool_manager = getattr(mcp, "_tool_manager", None)
    if tool_manager is None:
        return
    get_tool = getattr(tool_manager, "get_tool", None)
    if get_tool is None:
        return
    tool = get_tool(tool_name)
    if tool is not None:
        tool.description = None  # type: ignore[assignment]


def register_tool_functions(
    mcp,
    *,
    tools: dict[str, Callable[..., Any]],
    specs: dict[str, ToolSpec],
    presentation_config: ToolPresentationConfig | None = None,
) -> None:
    effective_config = presentation_config or ToolPresentationConfig()
    for spec in specs.values():
        tool_fn = tools[spec.name]
        description = select_tool_description(spec, effective_config.description_mode)
        tool_fn.__doc__ = description
        decorator = mcp.tool(**_tool_registration_options(spec, effective_config))
        decorator(tool_fn)
        if description is None:
            # FastMCP falls back to fn.__doc__ or "" when no description is
            # passed; force the registered tool back to None either way.
            _clear_registered_tool_description(mcp, spec.name)


class ToolRegistry:
    @staticmethod
    def register_all(
        mcp,
        specs: dict[str, ToolSpec],
        dispatcher_provider: Callable[[], Callable[..., Any]],
        registry_provider: Callable[[], Any],
        presentation_config: ToolPresentationConfig | None = None,
    ) -> dict[str, Callable[..., Any]]:
        tools = build_tool_functions(
            specs=specs,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
            presentation_config=presentation_config,
        )
        register_tool_functions(mcp, tools=tools, specs=specs, presentation_config=presentation_config)
        return tools


__all__ = [
    "ToolRegistry",
    "build_tool_functions",
    "register_tool_functions",
    "select_tool_description",
    "tool_annotations_for_spec",
]
