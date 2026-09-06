"""Dynamic MCP tool registration from declarative ToolSpec."""

from __future__ import annotations

import functools
import inspect
import re
from typing import Any, Callable

from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.tools.base import Tool
from mcp.types import ToolAnnotations

from ghidra_mcp.contracts.tool_models import PayloadToolOutputModel
from ghidra_mcp.contracts.tool_spec import (
    ExecutorKind,
    ToolSafetyTag,
    ToolSpec,
)
from ghidra_mcp.presentation.config import ToolDescriptionMode, ToolPresentationConfig

_SHORT_DESCRIPTION_MAX_CHARS = 180
_SENTENCE_ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "approx.", "no.", "al.")


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
        if value is None:
            # The dispatcher validates and re-dumps with exclude_none, so a None
            # never reaches the executor; drop it here to keep raw_args honest.
            continue
        raw_args[raw_key] = value

    if spec.executor_kind == ExecutorKind.CORE_COMMAND:
        target = bound.arguments.get("target", "default")
    elif spec.include_target:
        target = bound.arguments["target"]
    else:
        target = "default"

    return raw_args, target


def public_parameter_names(spec: ToolSpec) -> list[str]:
    """Return the public parameter names a client actually calls the tool with.

    This is the authoritative public signature: it applies public_name_overrides
    and includes the injected ``target`` exactly as _build_signature does, so it
    cannot drift from the registered MCP tool.
    """
    return list(_build_signature(spec).parameters.keys())


def public_input_schema(spec: ToolSpec) -> dict[str, Any]:
    """Return a JSON schema matching the tool's public (registered) parameters.

    ``spec.input_model.model_json_schema()`` uses the raw internal field names and
    omits the injected ``target``; publishing it verbatim makes doc-driven calls
    fail validation. Remap property/required names through public_name_overrides
    and inject ``target`` with the same semantics as _build_signature.
    """
    schema = dict(spec.input_model.model_json_schema())
    raw_props: dict[str, Any] = schema.get("properties", {})
    raw_required = schema.get("required", [])

    properties: dict[str, Any] = {_public_name(spec, raw_key): prop for raw_key, prop in raw_props.items()}
    required = [_public_name(spec, raw_key) for raw_key in raw_required]

    if spec.include_target:
        target_prop = {
            "type": "string",
            "title": "Target",
            "description": "Target session name.",
        }
        if spec.executor_kind == ExecutorKind.CORE_COMMAND:
            # Optional: _build_signature gives target a "default" default.
            properties["target"] = {**target_prop, "default": "default"}
        else:
            # REGISTRY_METHOD / SHARED_SYNC_METHOD: target is required and leads.
            properties = {"target": target_prop, **properties}
            if "target" not in required:
                required.insert(0, "target")

    schema["properties"] = properties
    if required:
        schema["required"] = required
    elif "required" in schema:
        del schema["required"]
    return schema


def public_output_schema(spec: ToolSpec) -> dict[str, Any]:
    """Return a JSON schema matching the client-visible result shape.

    List/scalar/map output models validate through an internal
    ``{"payload": ...}`` wrapper that dispatch_tool never returns to clients;
    publishing the wrapper verbatim would recreate on the output side the
    schema drift public_input_schema fixes for inputs.
    """
    schema = dict(spec.output_model.model_json_schema())
    if not issubclass(spec.output_model, PayloadToolOutputModel):
        return schema
    payload_schema = dict(schema.get("properties", {}).get("payload", {}))
    if "$defs" in schema:
        payload_schema["$defs"] = schema["$defs"]
    payload_schema["title"] = schema.get("title", payload_schema.get("title"))
    return payload_schema


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


def _cap_length(text: str) -> str:
    if len(text) <= _SHORT_DESCRIPTION_MAX_CHARS:
        return text
    return text[: _SHORT_DESCRIPTION_MAX_CHARS - 3].rstrip() + "..."


def _ends_with_abbreviation(candidate: str) -> bool:
    lowered = candidate.lower()
    for abbr in _SENTENCE_ABBREVIATIONS:
        if not lowered.endswith(abbr):
            continue
        # Require a word boundary before the abbreviation so sentence-final
        # words that merely share the suffix ("transactional." vs "al.",
        # "piano." vs "no.") are not misread as abbreviations.
        boundary = len(lowered) - len(abbr) - 1
        if boundary < 0 or not lowered[boundary].isalnum():
            return True
    return False


def _first_sentence_or_truncate(text: str) -> str:
    normalized = " ".join(text.split())
    if not normalized:
        return ""
    # Take the first real sentence, skipping terminators that belong to a known
    # abbreviation (so "... e.g. 0x40, ..." is not cut at "e.g."). CJK
    # terminators end a sentence on their own — Japanese never puts a space
    # after 。/！/？ — while ASCII ones need trailing whitespace or end-of-text.  # noqa: RUF003
    # Always cap the result so a single long sentence cannot blow past the
    # short-mode bound.
    for match in re.finditer(r"[.!?](?:\s|$)|[。！？]", normalized):  # noqa: RUF001 - CJK terminators
        candidate = normalized[: match.end()].strip()
        if _ends_with_abbreviation(candidate):
            continue
        return _cap_length(candidate)
    return _cap_length(normalized)


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
    idempotent_hint = spec.idempotent_hint
    if idempotent_hint is None and read_only_hint:
        # A read-only tool is idempotent by definition; clients treat an
        # unset hint as ``False`` and may refuse to retry it.
        idempotent_hint = True

    if read_only_hint is not None or destructive_hint is not None or idempotent_hint is not None:
        return ToolAnnotations(
            read_only_hint=read_only_hint,
            destructive_hint=destructive_hint,
            idempotent_hint=idempotent_hint,
        )
    return None


def as_anticipated_tool_failure(tool_fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool callable so its failures reach MCP clients as ``ToolError``.

    mcp 2.x treats every exception other than ``ToolError`` as a crash and
    replaces its message with ``Error executing tool <name>``.  The dispatcher
    already maps domain errors to public-safe messages (error codes, hints, and
    sanitized causes), so those messages must travel as anticipated failures.
    The ``domain_error`` payload attached by ``error_mapper`` is carried over.
    """

    @functools.wraps(tool_fn)
    def _entry(*args: Any, **kwargs: Any) -> Any:
        try:
            return tool_fn(*args, **kwargs)
        except ToolError:
            raise
        except Exception as exc:
            failure = ToolError(str(exc))
            payload = getattr(exc, "domain_error", None)
            if payload is not None:
                failure.domain_error = payload  # type: ignore[attr-defined]
            raise failure from exc

    return _entry


def build_tool_object(
    spec: ToolSpec,
    tool_fn: Callable[..., Any],
    presentation_config: ToolPresentationConfig | None = None,
) -> Tool:
    """Build the SDK ``Tool`` for one spec through the public ``Tool.from_function``.

    ``Tool.from_function`` substitutes an empty string for a missing description,
    so the description is reset to ``None`` afterwards: a description-less tool
    costs less context as an omitted field than as boilerplate, and the docs
    resource carries the details.
    """
    effective_config = presentation_config or ToolPresentationConfig()
    description = select_tool_description(spec, effective_config.description_mode)
    tool_fn.__doc__ = description
    tool = Tool.from_function(
        as_anticipated_tool_failure(tool_fn),
        name=spec.name,
        description=description,
        annotations=tool_annotations_for_spec(spec),
    )
    if description is None:
        tool.description = None
    return tool


def build_tool_objects(
    *,
    tools: dict[str, Callable[..., Any]],
    specs: dict[str, ToolSpec],
    presentation_config: ToolPresentationConfig | None = None,
) -> list[Tool]:
    return [build_tool_object(spec, tools[spec.name], presentation_config) for spec in specs.values()]


class ToolRegistry:
    @staticmethod
    def build(
        specs: dict[str, ToolSpec],
        dispatcher_provider: Callable[[], Callable[..., Any]],
        registry_provider: Callable[[], Any],
        presentation_config: ToolPresentationConfig | None = None,
    ) -> tuple[dict[str, Callable[..., Any]], list[Tool]]:
        """Return the public tool callables and the SDK ``Tool`` objects for ``specs``."""

        tools = build_tool_functions(
            specs=specs,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
            presentation_config=presentation_config,
        )
        tool_objects = build_tool_objects(tools=tools, specs=specs, presentation_config=presentation_config)
        return tools, tool_objects


__all__ = [
    "ToolRegistry",
    "as_anticipated_tool_failure",
    "build_tool_functions",
    "build_tool_object",
    "build_tool_objects",
    "public_input_schema",
    "public_output_schema",
    "public_parameter_names",
    "select_tool_description",
    "tool_annotations_for_spec",
]
