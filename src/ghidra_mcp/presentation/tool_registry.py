"""Dynamic MCP tool registration from declarative ToolSpec."""

from __future__ import annotations

import inspect
from typing import Any, Callable

from mcp.types import ToolAnnotations

from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolExposure, ToolSpec, get_all_tool_specs


_RAW_TO_PUBLIC_NAME: dict[str, dict[str, str]] = {
    "rename_function": {"oldName": "old_name", "newName": "new_name"},
    "rename_data": {"newName": "new_name"},
    "rename_variable": {
        "functionName": "function_name",
        "oldName": "old_name",
        "newName": "new_name",
    },
    "set_bytes": {"bytes": "bytes_hex"},
    "search_bytes": {"bytes": "pattern"},
}

_ALWAYS_INCLUDE_NONE_KEYS: dict[str, set[str]] = {
    "register_target": {"project_name"},
    "save_project_program": {"domain_path"},
    "create_session": {"project_name"},
    "get_project_sync_status": {"domain_path"},
    "checkout_project_program": {"domain_path"},
    "add_project_program_to_version_control": {"domain_path"},
    "commit_project_program": {"domain_path"},
    "pull_project_program": {"domain_path"},
    "undo_checkout_project_program": {"domain_path"},
    "terminate_project_program_checkout": {"domain_path"},
    "reload_project_program": {"domain_path"},
    "get_version_history": {"domain_path"},
    "get_version_diff": {"domain_path"},
}

_OMIT_FALSEY_KEYS: dict[str, set[str]] = {
    "list_strings": {"filter"},
    "create_struct": {"category", "members"},
    "add_struct_members": {"category"},
    "clear_struct": {"category"},
    "get_struct": {"category"},
    "create_enum": {"category", "values"},
    "add_enum_values": {"category"},
    "get_enum": {"category"},
    "create_class": {"parent_namespace", "members"},
    "add_class_members": {"parent_namespace"},
    "remove_class_members": {"parent_namespace"},
    "remove_enum_values": {"category"},
    "remove_struct_members": {"category"},
    "set_global_data_type": {"clear_mode"},
}

_TOOL_DECORATOR_OPTIONS: dict[str, dict[str, Any]] = {
    "list_functions": {
        "description": (
            "List all functions in the loaded program for the target session. "
            "Requires an initialized target with a loaded program; call list_targets first, "
            "then use create_session or load_project_program when needed."
        ),
        "annotations": ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    },
    "list_targets": {
        "description": (
            "List registered targets and their state, including project info and whether a program "
            "is loaded (domain_path). Call this before target-scoped operations."
        ),
        "annotations": ToolAnnotations(readOnlyHint=True, idempotentHint=True),
    },
    "register_target": {
        "description": (
            "Register a target with project information only, without loading a program yet. "
            "Use load_project_program later to open a domain path."
        ),
        "annotations": ToolAnnotations(readOnlyHint=False, idempotentHint=False),
    },
    "load_project_program": {
        "description": (
            "Load or switch a program for an existing target by domain path. "
            "Use this for targets that already exist (including project-only targets) "
            "instead of create_session."
        ),
        "annotations": ToolAnnotations(readOnlyHint=False, idempotentHint=False),
    },
    "import_program": {
        "description": (
            "Import a binary, Ghidra archive (.gzf), or raw binary / shellcode into the current "
            "target's project. Raw imports support BinaryLoader options such as language_id, "
            "base_address, entry bootstrap, and automatic analysis."
        ),
    },
    "save_project_program": {
        "description": (
            "Persist the currently loaded program for a target into its Ghidra project. "
            "Use this after mutating tools such as rename_function_by_address when changes "
            "must remain visible after reopening the project."
        ),
        "annotations": ToolAnnotations(readOnlyHint=False, idempotentHint=True),
    },
    "create_session": {
        "description": (
            "Create a new target session by opening a program in a Ghidra project. "
            "This is non-idempotent and fails if the target already exists. "
            "If the target already exists, use load_project_program."
        ),
        "annotations": ToolAnnotations(readOnlyHint=False, idempotentHint=False),
    },
}

_SHARED_SYNC_TOOL_ORDER: tuple[str, ...] = (
    "get_project_sync_status",
    "get_version_history",
    "get_version_diff",
    "checkout_project_program",
    "add_project_program_to_version_control",
    "commit_project_program",
    "pull_project_program",
    "undo_checkout_project_program",
    "terminate_project_program_checkout",
    "delete_shared_project_file",
    "reload_project_program",
)

_SHARED_SYNC_DESCRIPTIONS: dict[str, str] = {
    "get_project_sync_status": "Get shared-project version-control status for the target program",
    "get_version_history": "Get version history metadata for the target program in a shared project",
    "get_version_diff": "Get a summary of differences between two shared-project versions of the target program",
    "checkout_project_program": "Checkout the target program in a shared project",
    "add_project_program_to_version_control": "Add the target program to shared-project version control",
    "commit_project_program": "Check-in changes of the target program to the shared project server; on_conflict controls stale checkout handling",
    "pull_project_program": "Pull/merge latest remote changes for the target program",
    "undo_checkout_project_program": "Undo checkout for the target program (optionally discard local changes)",
    "terminate_project_program_checkout": "Terminate a stale checkout by checkout id for the target program",
    "delete_shared_project_file": "Delete a shared-project file after confirmation and checkout safety checks",
    "reload_project_program": "Reload the target program by closing and reopening the current domain path",
}

_SHARED_SYNC_ANNOTATIONS: dict[str, ToolAnnotations] = {
    "get_project_sync_status": ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
    "get_version_history": ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
    "get_version_diff": ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True),
    "checkout_project_program": ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
    "add_project_program_to_version_control": ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
    ),
    "commit_project_program": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    "pull_project_program": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    "undo_checkout_project_program": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    "terminate_project_program_checkout": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    "delete_shared_project_file": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
    "reload_project_program": ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
}


def _public_name(spec_name: str, raw_key: str) -> str:
    return _RAW_TO_PUBLIC_NAME.get(spec_name, {}).get(raw_key, raw_key)


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
        public_name = _public_name(spec.name, raw_key)
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
    include_none_keys = _ALWAYS_INCLUDE_NONE_KEYS.get(spec.name, set())
    omit_falsey = _OMIT_FALSEY_KEYS.get(spec.name, set())

    raw_args: dict[str, Any] = {}
    for raw_key in spec.input_model.model_fields:
        public_key = _public_name(spec.name, raw_key)
        value = bound.arguments.get(public_key)
        if raw_key in omit_falsey and not value:
            continue
        if value is None and raw_key not in include_none_keys:
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
    _tool_callable.__doc__ = f"Auto-generated MCP wrapper for {spec.name}."
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
    specs: dict[str, ToolSpec] | None = None,
    dispatcher_provider: Callable[[], Callable[..., Any]],
    registry_provider: Callable[[], Any],
) -> dict[str, Callable[..., Any]]:
    selected_specs = specs or get_all_tool_specs(include_shared_sync=True)
    tools: dict[str, Callable[..., Any]] = {}
    for spec in selected_specs.values():
        callable_obj = _build_callable(
            spec,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
        )
        tools[spec.name] = callable_obj
    return tools


def register_shared_sync_tools(mcp, *, tools: dict[str, Callable[..., Any]]) -> None:
    for name in _SHARED_SYNC_TOOL_ORDER:
        mcp.add_tool(
            tools[name],
            description=_SHARED_SYNC_DESCRIPTIONS[name],
            annotations=_SHARED_SYNC_ANNOTATIONS[name],
        )


class ToolRegistry:
    @staticmethod
    def register_all(
        mcp,
        specs: dict[str, ToolSpec],
        dispatcher_provider: Callable[[], Callable[..., Any]],
        registry_provider: Callable[[], Any],
        *,
        include_shared_sync: bool = False,
    ) -> dict[str, Callable[..., Any]]:
        tools = build_tool_functions(
            specs=specs,
            dispatcher_provider=dispatcher_provider,
            registry_provider=registry_provider,
        )

        for name, spec in specs.items():
            if spec.exposure != ToolExposure.ALWAYS:
                continue
            options = dict(_TOOL_DECORATOR_OPTIONS.get(name, {}))
            decorator = mcp.tool(**options)
            decorator(tools[name])

        if include_shared_sync:
            register_shared_sync_tools(mcp, tools=tools)

        return tools


__all__ = [
    "ToolRegistry",
    "build_tool_functions",
    "register_shared_sync_tools",
]
