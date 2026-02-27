"""Declarative tool specifications used by MCP wrappers and dispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel

from .tool_models import create_optional_any_input_model, create_typed_input_model


class ToolExposure(str, Enum):
    ALWAYS = "always"
    SHARED_SYNC = "shared_sync"


class ExecutorKind(str, Enum):
    CORE_COMMAND = "core_command"
    REGISTRY_METHOD = "registry_method"
    SHARED_SYNC_METHOD = "shared_sync_method"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    exposure: ToolExposure
    executor_kind: ExecutorKind
    command_or_method: str
    input_model: type[BaseModel]
    annotations: dict[str, Any] = field(default_factory=dict)
    empty_list_policy: str = "normalize"
    include_target: bool = True
    static_kwargs: dict[str, Any] = field(default_factory=dict)


_CORE_COMMAND_PARAM_KEYS: dict[str, tuple[str, ...]] = {
    "list_methods": ("offset", "limit"),
    "list_functions": ("offset", "limit"),
    "list_classes": ("offset", "limit"),
    "decompile_function": ("name",),
    "decompile_function_by_address": ("address",),
    "rename_function": ("oldName", "newName"),
    "rename_function_by_address": ("function_address", "new_name"),
    "rename_data": ("address", "newName"),
    "rename_variable": ("functionName", "oldName", "newName"),
    "list_segments": ("offset", "limit"),
    "list_imports": ("offset", "limit"),
    "list_exports": ("offset", "limit"),
    "list_namespaces": ("offset", "limit"),
    "list_data_items": ("offset", "limit"),
    "search_functions_by_name": ("query", "offset", "limit"),
    "get_function_by_address": ("address",),
    "disassemble_function": ("address",),
    "set_decompiler_comment": ("address", "comment"),
    "set_disassembly_comment": ("address", "comment"),
    "set_function_prototype": ("function_address", "prototype"),
    "set_local_variable_type": ("function_address", "variable_name", "new_type"),
    "get_xrefs_to": ("address", "offset", "limit"),
    "get_xrefs_from": ("address", "offset", "limit"),
    "get_function_xrefs": ("name", "offset", "limit"),
    "list_strings": ("offset", "limit", "filter"),
    "create_struct": ("name", "size", "category", "members"),
    "add_struct_members": ("struct_name", "members", "category"),
    "clear_struct": ("struct_name", "category"),
    "get_struct": ("name", "category"),
    "get_data_by_label": ("label",),
    "get_bytes": ("address", "size"),
    "search_bytes": ("bytes", "offset", "limit"),
    "create_enum": ("name", "size", "category", "values"),
    "add_enum_values": ("enum_name", "values", "category"),
    "get_enum": ("name", "category"),
    "set_global_data_type": ("address", "data_type", "length", "clear_mode"),
    "create_class": ("name", "parent_namespace", "members"),
    "add_class_members": ("class_name", "members", "parent_namespace"),
    "remove_class_members": ("class_name", "members", "parent_namespace"),
    "remove_enum_values": ("enum_name", "values", "category"),
    "remove_struct_members": ("struct_name", "members", "category"),
    "set_bytes": ("address", "bytes"),
    "get_callee": ("address",),
    "add_bookmark": ("address", "category", "comment", "type", "format"),
}

# name -> (registry_method, input_fields, include_target, static_kwargs)
_REGISTRY_METHOD_SPECS: dict[str, tuple[str, tuple[str, ...], bool, dict[str, Any]]] = {
    "list_targets": ("list_targets", (), False, {}),
    "list_project_programs": ("list_programs", (), True, {}),
    "register_target": ("register_target", ("project_location", "project_name"), True, {}),
    "load_project_program": ("load_program", ("domain_path",), True, {}),
    "import_program": ("import_program", ("binary_path",), True, {}),
    "create_session": (
        "create_session",
        ("project_location", "domain_path", "project_name"),
        True,
        {},
    ),
    "close_session": ("close_session", (), True, {}),
    "close_session_and_remove_program": ("close_session", (), True, {"remove_program": True}),
}

# name -> (registry_method, input_fields)
_SHARED_SYNC_METHOD_SPECS: dict[str, tuple[str, tuple[str, ...]]] = {
    "get_project_sync_status": ("get_project_sync_status", ("domain_path",)),
    "get_version_history": ("get_version_history", ("limit", "domain_path")),
    "get_version_diff": (
        "get_version_diff",
        ("from_version", "to_version", "range_limit", "domain_path"),
    ),
    "checkout_project_program": ("checkout_project_program", ("exclusive", "domain_path")),
    "add_project_program_to_version_control": (
        "add_project_program_to_version_control",
        ("comment", "keep_checked_out", "domain_path"),
    ),
    "commit_project_program": (
        "commit_project_program",
        ("message", "keep_checked_out", "auto_checkout", "domain_path"),
    ),
    "pull_project_program": ("pull_project_program", ("on_local_changes", "domain_path")),
    "undo_checkout_project_program": (
        "undo_checkout_project_program",
        ("discard_local_changes", "domain_path"),
    ),
    "terminate_project_program_checkout": (
        "terminate_project_program_checkout",
        ("checkout_id", "domain_path"),
    ),
    "reload_project_program": ("reload_project_program", ("domain_path",)),
}


def _pascal_case(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def _build_input_model(tool_name: str, field_names: tuple[str, ...]) -> type[BaseModel]:
    model_name = f"{_pascal_case(tool_name)}Input"
    typed_fields_by_tool: dict[str, dict[str, tuple[type[Any], Any]]] = {
        "list_methods": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_functions": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_classes": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "search_functions_by_name": {
            "query": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "get_function_by_address": {
            "address": (str, ...),
        },
        "decompile_function": {
            "name": (str, ...),
        },
        "decompile_function_by_address": {
            "address": (str, ...),
        },
        "disassemble_function": {
            "address": (str, ...),
        },
        "get_callee": {
            "address": (str, ...),
        },
        "get_xrefs_to": {
            "address": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "get_xrefs_from": {
            "address": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "get_function_xrefs": {
            "name": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_segments": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_imports": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_exports": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_namespaces": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_data_items": {
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "list_strings": {
            "offset": (int, 0),
            "limit": (int, 2000),
            "filter": (str | None, None),
        },
        "get_data_by_label": {
            "label": (str, ...),
        },
        "get_bytes": {
            "address": (str, ...),
            "size": (int, 16),
        },
        "search_bytes": {
            "bytes": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
        "get_struct": {
            "name": (str, ...),
            "category": (str | None, None),
        },
        "get_enum": {
            "name": (str, ...),
            "category": (str | None, None),
        },
        "rename_function": {
            "oldName": (str, ...),
            "newName": (str, ...),
        },
        "rename_function_by_address": {
            "function_address": (str, ...),
            "new_name": (str, ...),
        },
        "rename_data": {
            "address": (str, ...),
            "newName": (str, ...),
        },
        "rename_variable": {
            "functionName": (str, ...),
            "oldName": (str, ...),
            "newName": (str, ...),
        },
        "set_decompiler_comment": {
            "address": (str, ...),
            "comment": (str, ...),
        },
        "set_disassembly_comment": {
            "address": (str, ...),
            "comment": (str, ...),
        },
        "set_function_prototype": {
            "function_address": (str, ...),
            "prototype": (str, ...),
        },
        "set_local_variable_type": {
            "function_address": (str, ...),
            "variable_name": (str, ...),
            "new_type": (str, ...),
        },
        "create_struct": {
            "name": (str, ...),
            "size": (int, 0),
            "category": (str | None, None),
            "members": (list[dict] | None, None),
        },
        "add_struct_members": {
            "struct_name": (str, ...),
            "members": (list[dict], ...),
            "category": (str | None, None),
        },
        "clear_struct": {
            "struct_name": (str, ...),
            "category": (str | None, None),
        },
        "create_enum": {
            "name": (str, ...),
            "size": (int, 4),
            "category": (str | None, None),
            "values": (list[dict] | None, None),
        },
        "add_enum_values": {
            "enum_name": (str, ...),
            "values": (list[dict], ...),
            "category": (str | None, None),
        },
        "remove_enum_values": {
            "enum_name": (str, ...),
            "values": (list[str], ...),
            "category": (str | None, None),
        },
        "create_class": {
            "name": (str, ...),
            "parent_namespace": (str | None, None),
            "members": (list[dict] | None, None),
        },
        "add_class_members": {
            "class_name": (str, ...),
            "members": (list[dict], ...),
            "parent_namespace": (str | None, None),
        },
        "remove_class_members": {
            "class_name": (str, ...),
            "members": (list[str], ...),
            "parent_namespace": (str | None, None),
        },
        "remove_struct_members": {
            "struct_name": (str, ...),
            "members": (list[str], ...),
            "category": (str | None, None),
        },
        "set_global_data_type": {
            "address": (str, ...),
            "data_type": (str, ...),
            "length": (int | None, None),
            "clear_mode": (str | None, None),
        },
        "set_bytes": {
            "address": (str, ...),
            "bytes": (str, ...),
        },
        "add_bookmark": {
            "address": (str, ...),
            "category": (str, ...),
            "comment": (str, ...),
            "type": (str, ...),
            "format": (str, "json"),
        },
    }
    if tool_name in typed_fields_by_tool:
        return create_typed_input_model(model_name, typed_fields_by_tool[tool_name])
    return create_optional_any_input_model(model_name, field_names)


_TOOL_SPECS: dict[str, ToolSpec] = {}

for command_name, field_names in _CORE_COMMAND_PARAM_KEYS.items():
    _TOOL_SPECS[command_name] = ToolSpec(
        name=command_name,
        exposure=ToolExposure.ALWAYS,
        executor_kind=ExecutorKind.CORE_COMMAND,
        command_or_method=command_name,
        input_model=_build_input_model(command_name, field_names),
    )

for spec_name, (method_name, field_names, include_target, static_kwargs) in _REGISTRY_METHOD_SPECS.items():
    _TOOL_SPECS[spec_name] = ToolSpec(
        name=spec_name,
        exposure=ToolExposure.ALWAYS,
        executor_kind=ExecutorKind.REGISTRY_METHOD,
        command_or_method=method_name,
        input_model=_build_input_model(spec_name, field_names),
        include_target=include_target,
        static_kwargs=dict(static_kwargs),
    )

for spec_name, (method_name, field_names) in _SHARED_SYNC_METHOD_SPECS.items():
    _TOOL_SPECS[spec_name] = ToolSpec(
        name=spec_name,
        exposure=ToolExposure.SHARED_SYNC,
        executor_kind=ExecutorKind.SHARED_SYNC_METHOD,
        command_or_method=method_name,
        input_model=_build_input_model(spec_name, field_names),
    )


def get_tool_spec(name: str) -> ToolSpec:
    try:
        return _TOOL_SPECS[name]
    except KeyError as exc:
        raise KeyError(f"未対応のツール仕様です: {name}") from exc


def get_all_tool_specs(*, include_shared_sync: bool = True) -> dict[str, ToolSpec]:
    if include_shared_sync:
        return dict(_TOOL_SPECS)
    return {name: spec for name, spec in _TOOL_SPECS.items() if spec.exposure == ToolExposure.ALWAYS}


def get_public_tool_names(*, include_shared_sync: bool = True) -> set[str]:
    return set(get_all_tool_specs(include_shared_sync=include_shared_sync).keys())


__all__ = [
    "ExecutorKind",
    "ToolExposure",
    "ToolSpec",
    "get_tool_spec",
    "get_all_tool_specs",
    "get_public_tool_names",
]
