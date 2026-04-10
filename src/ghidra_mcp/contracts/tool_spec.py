"""Declarative tool specifications used by MCP wrappers and dispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel

from .tool_models import (
    create_list_output_model,
    create_map_output_model,
    create_optional_any_input_model,
    create_scalar_output_model,
    create_typed_input_model,
    create_typed_output_model,
)


class ToolCategoryTag(str, Enum):
    CORE = "core"
    FUNCTION_ANALYSIS = "function_analysis"
    MEMORY_DATA = "memory_data"
    SYMBOL_COMMENT_EDIT = "symbol_comment_edit"
    DATATYPE_OPS = "datatype_ops"
    SHARED_SYNC = "shared_sync"


class ToolSafetyTag(str, Enum):
    SAFE_READONLY = "safe_readonly"
    SAFE_NONSEMANTIC_EDIT = "safe_nonsemantic_edit"
    UNSAFE_SEMANTIC_EDIT = "unsafe_semantic_edit"
    UNSAFE_BINARY_DESTRUCTIVE = "unsafe_binary_destructive"
    UNSAFE_NONBINARY_DESTRUCTIVE = "unsafe_nonbinary_destructive"


class ToolOperationLevel(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"


class ToolProfile(str, Enum):
    DEFAULT = "default"
    READONLY = "readonly"
    FULL = "full"


class ExecutorKind(str, Enum):
    CORE_COMMAND = "core_command"
    REGISTRY_METHOD = "registry_method"
    SHARED_SYNC_METHOD = "shared_sync_method"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category_tag: ToolCategoryTag
    safety_tag: ToolSafetyTag
    operation_level: ToolOperationLevel
    executor_kind: ExecutorKind
    command_or_method: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    public_signature: tuple[str, ...] = field(default_factory=tuple)
    error_policy: str = "legacy_compatible"
    annotations: dict[str, Any] = field(default_factory=dict)
    empty_list_policy: str = "normalize"
    include_target: bool = True
    static_kwargs: dict[str, Any] = field(default_factory=dict)
    result_adapter: str | None = None
    error_adapter: str | None = None


@dataclass(frozen=True)
class ToolProfileSpec:
    categories: frozenset[ToolCategoryTag]
    safety_tags: frozenset[ToolSafetyTag] | None = None
    operation_levels: frozenset[ToolOperationLevel] | None = None


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

_RESULT_ADAPTERS_BY_SPEC: dict[str, str] = {
    "load_project_program": "status_program_ok",
    "import_program": "status_program_ok",
    "create_session": "status_target_ok",
    "close_session": "status_target_ok",
    "close_session_and_remove_program": "status_target_ok",
}

_ERROR_ADAPTERS_BY_SPEC: dict[str, str] = {
    "create_session": "create_session_error",
    "close_session": "close_session_error",
    "close_session_and_remove_program": "close_remove_error",
}


_LIST_OUTPUT_TOOLS: set[str] = {
    "list_methods",
    "list_functions",
    "list_classes",
    "search_functions_by_name",
    "disassemble_function",
    "get_callee",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_function_xrefs",
    "list_segments",
    "list_imports",
    "list_exports",
    "list_namespaces",
    "list_data_items",
    "list_strings",
    "get_data_by_label",
    "search_bytes",
    "list_targets",
    "list_project_programs",
}

_SCALAR_OUTPUT_TYPES: dict[str, type[Any]] = {
    "decompile_function": str,
    "decompile_function_by_address": str,
    "get_bytes": str,
    "load_project_program": str,
    "import_program": str,
}

_DIRECT_OUTPUT_FIELDS: dict[str, dict[str, tuple[type[Any], Any]]] = {
    "create_session": {
        "target": (str, ...),
        "project_location": (str, ...),
        "project_name": (str | None, None),
        "domain_path": (str | None, None),
    },
    "close_session": {
        "closed": (bool, ...),
        "target": (str, ...),
        "remove_program": (bool, ...),
    },
    "close_session_and_remove_program": {
        "closed": (bool, ...),
        "target": (str, ...),
        "remove_program": (bool, ...),
    },
}

_TOOL_CATEGORY_BY_NAME: dict[str, ToolCategoryTag] = {
    # core
    "list_targets": ToolCategoryTag.CORE,
    "create_session": ToolCategoryTag.CORE,
    "register_target": ToolCategoryTag.CORE,
    "close_session": ToolCategoryTag.CORE,
    "close_session_and_remove_program": ToolCategoryTag.CORE,
    "list_project_programs": ToolCategoryTag.CORE,
    "import_program": ToolCategoryTag.CORE,
    "load_project_program": ToolCategoryTag.CORE,
    # function_analysis
    "list_methods": ToolCategoryTag.FUNCTION_ANALYSIS,
    "list_functions": ToolCategoryTag.FUNCTION_ANALYSIS,
    "list_classes": ToolCategoryTag.FUNCTION_ANALYSIS,
    "list_namespaces": ToolCategoryTag.FUNCTION_ANALYSIS,
    "search_functions_by_name": ToolCategoryTag.FUNCTION_ANALYSIS,
    "decompile_function": ToolCategoryTag.FUNCTION_ANALYSIS,
    "decompile_function_by_address": ToolCategoryTag.FUNCTION_ANALYSIS,
    "disassemble_function": ToolCategoryTag.FUNCTION_ANALYSIS,
    "get_function_by_address": ToolCategoryTag.FUNCTION_ANALYSIS,
    "get_function_xrefs": ToolCategoryTag.FUNCTION_ANALYSIS,
    "get_callee": ToolCategoryTag.FUNCTION_ANALYSIS,
    # memory_data
    "list_segments": ToolCategoryTag.MEMORY_DATA,
    "list_imports": ToolCategoryTag.MEMORY_DATA,
    "list_exports": ToolCategoryTag.MEMORY_DATA,
    "list_data_items": ToolCategoryTag.MEMORY_DATA,
    "list_strings": ToolCategoryTag.MEMORY_DATA,
    "get_xrefs_to": ToolCategoryTag.MEMORY_DATA,
    "get_xrefs_from": ToolCategoryTag.MEMORY_DATA,
    "get_data_by_label": ToolCategoryTag.MEMORY_DATA,
    "get_bytes": ToolCategoryTag.MEMORY_DATA,
    "search_bytes": ToolCategoryTag.MEMORY_DATA,
    # symbol_comment_edit
    "rename_function": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "rename_function_by_address": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "rename_variable": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "rename_data": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_function_prototype": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_local_variable_type": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_global_data_type": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_bytes": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_decompiler_comment": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "set_disassembly_comment": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    "add_bookmark": ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    # datatype_ops
    "create_struct": ToolCategoryTag.DATATYPE_OPS,
    "add_struct_members": ToolCategoryTag.DATATYPE_OPS,
    "clear_struct": ToolCategoryTag.DATATYPE_OPS,
    "remove_struct_members": ToolCategoryTag.DATATYPE_OPS,
    "get_struct": ToolCategoryTag.DATATYPE_OPS,
    "create_enum": ToolCategoryTag.DATATYPE_OPS,
    "add_enum_values": ToolCategoryTag.DATATYPE_OPS,
    "remove_enum_values": ToolCategoryTag.DATATYPE_OPS,
    "get_enum": ToolCategoryTag.DATATYPE_OPS,
    "create_class": ToolCategoryTag.DATATYPE_OPS,
    "add_class_members": ToolCategoryTag.DATATYPE_OPS,
    "remove_class_members": ToolCategoryTag.DATATYPE_OPS,
    # shared_sync
    "get_project_sync_status": ToolCategoryTag.SHARED_SYNC,
    "get_version_history": ToolCategoryTag.SHARED_SYNC,
    "get_version_diff": ToolCategoryTag.SHARED_SYNC,
    "checkout_project_program": ToolCategoryTag.SHARED_SYNC,
    "add_project_program_to_version_control": ToolCategoryTag.SHARED_SYNC,
    "commit_project_program": ToolCategoryTag.SHARED_SYNC,
    "pull_project_program": ToolCategoryTag.SHARED_SYNC,
    "undo_checkout_project_program": ToolCategoryTag.SHARED_SYNC,
    "terminate_project_program_checkout": ToolCategoryTag.SHARED_SYNC,
    "reload_project_program": ToolCategoryTag.SHARED_SYNC,
}

_TOOL_SAFETY_BY_NAME: dict[str, ToolSafetyTag] = {
    # core
    "list_targets": ToolSafetyTag.SAFE_READONLY,
    "create_session": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "register_target": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "close_session": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "close_session_and_remove_program": ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
    "list_project_programs": ToolSafetyTag.SAFE_READONLY,
    "import_program": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "load_project_program": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    # function_analysis
    "list_methods": ToolSafetyTag.SAFE_READONLY,
    "list_functions": ToolSafetyTag.SAFE_READONLY,
    "list_classes": ToolSafetyTag.SAFE_READONLY,
    "list_namespaces": ToolSafetyTag.SAFE_READONLY,
    "search_functions_by_name": ToolSafetyTag.SAFE_READONLY,
    "decompile_function": ToolSafetyTag.SAFE_READONLY,
    "decompile_function_by_address": ToolSafetyTag.SAFE_READONLY,
    "disassemble_function": ToolSafetyTag.SAFE_READONLY,
    "get_function_by_address": ToolSafetyTag.SAFE_READONLY,
    "get_function_xrefs": ToolSafetyTag.SAFE_READONLY,
    "get_callee": ToolSafetyTag.SAFE_READONLY,
    # memory_data
    "list_segments": ToolSafetyTag.SAFE_READONLY,
    "list_imports": ToolSafetyTag.SAFE_READONLY,
    "list_exports": ToolSafetyTag.SAFE_READONLY,
    "list_data_items": ToolSafetyTag.SAFE_READONLY,
    "list_strings": ToolSafetyTag.SAFE_READONLY,
    "get_xrefs_to": ToolSafetyTag.SAFE_READONLY,
    "get_xrefs_from": ToolSafetyTag.SAFE_READONLY,
    "get_data_by_label": ToolSafetyTag.SAFE_READONLY,
    "get_bytes": ToolSafetyTag.SAFE_READONLY,
    "search_bytes": ToolSafetyTag.SAFE_READONLY,
    # symbol_comment_edit
    "rename_function": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "rename_function_by_address": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "rename_variable": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "rename_data": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "set_function_prototype": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "set_local_variable_type": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "set_global_data_type": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "set_bytes": ToolSafetyTag.UNSAFE_BINARY_DESTRUCTIVE,
    "set_decompiler_comment": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "set_disassembly_comment": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    "add_bookmark": ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
    # datatype_ops
    "create_struct": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "add_struct_members": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "clear_struct": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "remove_struct_members": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "get_struct": ToolSafetyTag.SAFE_READONLY,
    "create_enum": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "add_enum_values": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "remove_enum_values": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "get_enum": ToolSafetyTag.SAFE_READONLY,
    "create_class": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "add_class_members": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "remove_class_members": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    # shared_sync
    "get_project_sync_status": ToolSafetyTag.SAFE_READONLY,
    "get_version_history": ToolSafetyTag.SAFE_READONLY,
    "get_version_diff": ToolSafetyTag.SAFE_READONLY,
    "checkout_project_program": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "add_project_program_to_version_control": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "commit_project_program": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "pull_project_program": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
    "undo_checkout_project_program": ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
    "terminate_project_program_checkout": ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
    "reload_project_program": ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
}

_TOOL_OPERATION_LEVEL_BY_NAME: dict[str, ToolOperationLevel] = {
    # core
    "list_targets": ToolOperationLevel.BASIC,
    "create_session": ToolOperationLevel.STANDARD,
    "register_target": ToolOperationLevel.STANDARD,
    "close_session": ToolOperationLevel.STANDARD,
    "close_session_and_remove_program": ToolOperationLevel.ADVANCED,
    "list_project_programs": ToolOperationLevel.STANDARD,
    "import_program": ToolOperationLevel.ADVANCED,
    "load_project_program": ToolOperationLevel.BASIC,
    # function_analysis
    "list_methods": ToolOperationLevel.BASIC,
    "list_functions": ToolOperationLevel.STANDARD,
    "list_classes": ToolOperationLevel.ADVANCED,
    "list_namespaces": ToolOperationLevel.ADVANCED,
    "search_functions_by_name": ToolOperationLevel.STANDARD,
    "decompile_function": ToolOperationLevel.BASIC,
    "decompile_function_by_address": ToolOperationLevel.STANDARD,
    "disassemble_function": ToolOperationLevel.STANDARD,
    "get_function_by_address": ToolOperationLevel.STANDARD,
    "get_function_xrefs": ToolOperationLevel.BASIC,
    "get_callee": ToolOperationLevel.STANDARD,
    # memory_data
    "list_segments": ToolOperationLevel.ADVANCED,
    "list_imports": ToolOperationLevel.BASIC,
    "list_exports": ToolOperationLevel.BASIC,
    "list_data_items": ToolOperationLevel.ADVANCED,
    "list_strings": ToolOperationLevel.BASIC,
    "get_xrefs_to": ToolOperationLevel.STANDARD,
    "get_xrefs_from": ToolOperationLevel.STANDARD,
    "get_data_by_label": ToolOperationLevel.STANDARD,
    "get_bytes": ToolOperationLevel.STANDARD,
    "search_bytes": ToolOperationLevel.STANDARD,
    # symbol_comment_edit
    "rename_function": ToolOperationLevel.BASIC,
    "rename_function_by_address": ToolOperationLevel.STANDARD,
    "rename_variable": ToolOperationLevel.BASIC,
    "rename_data": ToolOperationLevel.ADVANCED,
    "set_function_prototype": ToolOperationLevel.STANDARD,
    "set_local_variable_type": ToolOperationLevel.STANDARD,
    "set_global_data_type": ToolOperationLevel.ADVANCED,
    "set_bytes": ToolOperationLevel.ADVANCED,
    "set_decompiler_comment": ToolOperationLevel.STANDARD,
    "set_disassembly_comment": ToolOperationLevel.STANDARD,
    "add_bookmark": ToolOperationLevel.STANDARD,
    # datatype_ops
    "create_struct": ToolOperationLevel.STANDARD,
    "add_struct_members": ToolOperationLevel.STANDARD,
    "clear_struct": ToolOperationLevel.STANDARD,
    "remove_struct_members": ToolOperationLevel.STANDARD,
    "get_struct": ToolOperationLevel.STANDARD,
    "create_enum": ToolOperationLevel.ADVANCED,
    "add_enum_values": ToolOperationLevel.ADVANCED,
    "remove_enum_values": ToolOperationLevel.ADVANCED,
    "get_enum": ToolOperationLevel.ADVANCED,
    "create_class": ToolOperationLevel.ADVANCED,
    "add_class_members": ToolOperationLevel.ADVANCED,
    "remove_class_members": ToolOperationLevel.ADVANCED,
    # shared_sync
    "get_project_sync_status": ToolOperationLevel.BASIC,
    "get_version_history": ToolOperationLevel.STANDARD,
    "get_version_diff": ToolOperationLevel.ADVANCED,
    "checkout_project_program": ToolOperationLevel.BASIC,
    "add_project_program_to_version_control": ToolOperationLevel.STANDARD,
    "commit_project_program": ToolOperationLevel.BASIC,
    "pull_project_program": ToolOperationLevel.BASIC,
    "undo_checkout_project_program": ToolOperationLevel.STANDARD,
    "terminate_project_program_checkout": ToolOperationLevel.ADVANCED,
    "reload_project_program": ToolOperationLevel.ADVANCED,
}

_DEFAULT_PROFILE_CATEGORIES: frozenset[ToolCategoryTag] = frozenset(
    {
        ToolCategoryTag.CORE,
        ToolCategoryTag.FUNCTION_ANALYSIS,
        ToolCategoryTag.MEMORY_DATA,
        ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        ToolCategoryTag.DATATYPE_OPS,
    }
)

_ALL_CATEGORIES: frozenset[ToolCategoryTag] = frozenset(ToolCategoryTag)
_ALL_SAFETY_TAGS: frozenset[ToolSafetyTag] = frozenset(ToolSafetyTag)
_ALL_OPERATION_LEVELS: frozenset[ToolOperationLevel] = frozenset(ToolOperationLevel)

_PROFILE_SPECS: dict[ToolProfile, ToolProfileSpec] = {
    ToolProfile.DEFAULT: ToolProfileSpec(categories=_DEFAULT_PROFILE_CATEGORIES),
    ToolProfile.READONLY: ToolProfileSpec(
        categories=_DEFAULT_PROFILE_CATEGORIES,
        safety_tags=frozenset({ToolSafetyTag.SAFE_READONLY}),
    ),
    ToolProfile.FULL: ToolProfileSpec(
        categories=_ALL_CATEGORIES,
        safety_tags=_ALL_SAFETY_TAGS,
        operation_levels=_ALL_OPERATION_LEVELS,
    ),
}


def _build_output_model(tool_name: str) -> type[BaseModel]:
    model_name = f"{_pascal_case(tool_name)}Output"
    if tool_name in _DIRECT_OUTPUT_FIELDS:
        return create_typed_output_model(model_name, _DIRECT_OUTPUT_FIELDS[tool_name])
    if tool_name in _SCALAR_OUTPUT_TYPES:
        return create_scalar_output_model(model_name, _SCALAR_OUTPUT_TYPES[tool_name], allow_empty_list=True)
    if tool_name in _LIST_OUTPUT_TOOLS:
        return create_list_output_model(model_name, object)
    return create_map_output_model(model_name, object, allow_empty_list=True)


def _pascal_case(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def _build_input_model(tool_name: str, field_names: tuple[str, ...]) -> type[BaseModel]:
    model_name = f"{_pascal_case(tool_name)}Input"
    typed_fields_by_tool: dict[str, dict[str, tuple[type[Any], Any]]] = {
        "list_targets": {},
        "list_project_programs": {},
        "register_target": {
            "project_location": (str, ...),
            "project_name": (str | None, None),
        },
        "load_project_program": {
            "domain_path": (str, ...),
        },
        "import_program": {
            "binary_path": (str, ...),
        },
        "create_session": {
            "project_location": (str, ...),
            "domain_path": (str, ...),
            "project_name": (str | None, None),
        },
        "close_session": {},
        "close_session_and_remove_program": {},
        "get_project_sync_status": {
            "domain_path": (str | None, None),
        },
        "checkout_project_program": {
            "exclusive": (bool, False),
            "domain_path": (str | None, None),
        },
        "add_project_program_to_version_control": {
            "comment": (str, ...),
            "keep_checked_out": (bool, False),
            "domain_path": (str | None, None),
        },
        "commit_project_program": {
            "message": (str, ...),
            "keep_checked_out": (bool, False),
            "auto_checkout": (bool, True),
            "domain_path": (str | None, None),
        },
        "pull_project_program": {
            "on_local_changes": (str, "abort"),
            "domain_path": (str | None, None),
        },
        "undo_checkout_project_program": {
            "discard_local_changes": (bool, True),
            "domain_path": (str | None, None),
        },
        "terminate_project_program_checkout": {
            "checkout_id": (int, ...),
            "domain_path": (str | None, None),
        },
        "reload_project_program": {
            "domain_path": (str | None, None),
        },
        "get_version_history": {
            "limit": (int, 50),
            "domain_path": (str | None, None),
        },
        "get_version_diff": {
            "from_version": (int, ...),
            "to_version": (int, ...),
            "range_limit": (int, 200),
            "domain_path": (str | None, None),
        },
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
        category_tag=_TOOL_CATEGORY_BY_NAME[command_name],
        safety_tag=_TOOL_SAFETY_BY_NAME[command_name],
        operation_level=_TOOL_OPERATION_LEVEL_BY_NAME[command_name],
        executor_kind=ExecutorKind.CORE_COMMAND,
        command_or_method=command_name,
        input_model=_build_input_model(command_name, field_names),
        output_model=_build_output_model(command_name),
        public_signature=(*field_names, "target"),
        result_adapter=_RESULT_ADAPTERS_BY_SPEC.get(command_name),
        error_adapter=_ERROR_ADAPTERS_BY_SPEC.get(command_name),
    )

for spec_name, (method_name, field_names, include_target, static_kwargs) in _REGISTRY_METHOD_SPECS.items():
    signature_fields = ("target", *field_names) if include_target else field_names
    _TOOL_SPECS[spec_name] = ToolSpec(
        name=spec_name,
        category_tag=_TOOL_CATEGORY_BY_NAME[spec_name],
        safety_tag=_TOOL_SAFETY_BY_NAME[spec_name],
        operation_level=_TOOL_OPERATION_LEVEL_BY_NAME[spec_name],
        executor_kind=ExecutorKind.REGISTRY_METHOD,
        command_or_method=method_name,
        input_model=_build_input_model(spec_name, field_names),
        output_model=_build_output_model(spec_name),
        public_signature=signature_fields,
        include_target=include_target,
        static_kwargs=dict(static_kwargs),
        result_adapter=_RESULT_ADAPTERS_BY_SPEC.get(spec_name),
        error_adapter=_ERROR_ADAPTERS_BY_SPEC.get(spec_name),
    )

for spec_name, (method_name, field_names) in _SHARED_SYNC_METHOD_SPECS.items():
    _TOOL_SPECS[spec_name] = ToolSpec(
        name=spec_name,
        category_tag=_TOOL_CATEGORY_BY_NAME[spec_name],
        safety_tag=_TOOL_SAFETY_BY_NAME[spec_name],
        operation_level=_TOOL_OPERATION_LEVEL_BY_NAME[spec_name],
        executor_kind=ExecutorKind.SHARED_SYNC_METHOD,
        command_or_method=method_name,
        input_model=_build_input_model(spec_name, field_names),
        output_model=_build_output_model(spec_name),
        public_signature=("target", *field_names),
        result_adapter=_RESULT_ADAPTERS_BY_SPEC.get(spec_name),
        error_adapter=_ERROR_ADAPTERS_BY_SPEC.get(spec_name),
    )


def _coerce_enum_member(value: str | Enum, enum_cls: type[Enum], label: str):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_cls)
        raise ValueError(f"Unsupported {label}: {value!r} (expected one of: {allowed})") from exc


def _coerce_enum_set(
    values: Iterable[str | Enum] | None,
    *,
    enum_cls: type[Enum],
    label: str,
) -> set[Enum] | None:
    if values is None:
        return None
    return {_coerce_enum_member(value, enum_cls, label) for value in values}


def get_tool_spec(name: str) -> ToolSpec:
    try:
        return _TOOL_SPECS[name]
    except KeyError as exc:
        raise KeyError(f"Unsupported tool spec: {name}") from exc


def filter_tool_specs(
    *,
    specs: dict[str, ToolSpec] | None = None,
    profile: ToolProfile | str = ToolProfile.DEFAULT,
    allow_categories: Iterable[ToolCategoryTag | str] | None = None,
    add_categories: Iterable[ToolCategoryTag | str] | None = None,
    allow_safety: Iterable[ToolSafetyTag | str] | None = None,
    allow_operation_levels: Iterable[ToolOperationLevel | str] | None = None,
    enable_tools: Iterable[str] | None = None,
    disable_tools: Iterable[str] | None = None,
) -> dict[str, ToolSpec]:
    available_specs = _TOOL_SPECS if specs is None else specs
    profile_spec = _PROFILE_SPECS[_coerce_enum_member(profile, ToolProfile, "tool profile")]

    categories = set(profile_spec.categories)
    allow_category_set = _coerce_enum_set(
        allow_categories,
        enum_cls=ToolCategoryTag,
        label="category",
    )
    if allow_category_set is not None:
        categories = set(allow_category_set)
    add_category_set = _coerce_enum_set(
        add_categories,
        enum_cls=ToolCategoryTag,
        label="category",
    )
    if add_category_set is not None:
        categories.update(add_category_set)

    safety_tags = set(profile_spec.safety_tags) if profile_spec.safety_tags is not None else None
    requested_safety = _coerce_enum_set(
        allow_safety,
        enum_cls=ToolSafetyTag,
        label="safety tag",
    )
    if requested_safety is not None:
        safety_tags = requested_safety if safety_tags is None else safety_tags & requested_safety

    operation_levels = set(profile_spec.operation_levels) if profile_spec.operation_levels is not None else None
    requested_operation_levels = _coerce_enum_set(
        allow_operation_levels,
        enum_cls=ToolOperationLevel,
        label="operation level",
    )
    if requested_operation_levels is not None:
        operation_levels = (
            requested_operation_levels
            if operation_levels is None
            else operation_levels & requested_operation_levels
        )

    selected_names = {
        name
        for name, spec in available_specs.items()
        if spec.category_tag in categories
        and (safety_tags is None or spec.safety_tag in safety_tags)
        and (operation_levels is None or spec.operation_level in operation_levels)
    }

    enabled_names = set(enable_tools or ())
    disabled_names = set(disable_tools or ())

    selected_names.update(enabled_names)
    selected_names.difference_update(disabled_names)

    return {
        name: spec
        for name, spec in available_specs.items()
        if name in selected_names
    }
def get_all_tool_specs() -> dict[str, ToolSpec]:
    return dict(_TOOL_SPECS)


def get_public_tool_names() -> set[str]:
    return set(_TOOL_SPECS.keys())


__all__ = [
    "ExecutorKind",
    "ToolCategoryTag",
    "ToolOperationLevel",
    "ToolProfile",
    "ToolSafetyTag",
    "ToolSpec",
    "filter_tool_specs",
    "get_all_tool_specs",
    "get_public_tool_names",
    "get_tool_spec",
]
