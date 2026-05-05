"""Declarative tool specifications used by MCP wrappers and dispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Literal

from pydantic import BaseModel, field_validator, model_validator

from .tool_models import (
    ToolInputModel,
    create_list_output_model,
    create_map_output_model,
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


ToolFieldSpec = tuple[str, Any, Any]


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
    public_name_overrides: dict[str, str] = field(default_factory=dict)
    include_none_keys: frozenset[str] = field(default_factory=frozenset)
    omit_falsey_keys: frozenset[str] = field(default_factory=frozenset)
    description: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    checkout_required: bool = False


@dataclass(frozen=True)
class ToolProfileSpec:
    categories: frozenset[ToolCategoryTag]
    safety_tags: frozenset[ToolSafetyTag] | None = None
    operation_levels: frozenset[ToolOperationLevel] | None = None


_NO_FIELDS: tuple[ToolFieldSpec, ...] = ()
_OFFSET_LIMIT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("offset", int, 0),
    ("limit", int, 100),
)
_DOMAIN_PATH_FIELD: ToolFieldSpec = ("domain_path", str | None, None)
_CREATE_SESSION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("target", str, ...),
    ("project_location", str, ...),
    ("project_name", str | None, None),
    ("domain_path", str | None, None),
)
_CLOSE_SESSION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("closed", bool, ...),
    ("target", str, ...),
    ("remove_program", bool, ...),
)
_IMPORT_PROGRAM_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("binary_path", str, ...),
    ("import_mode", Literal["auto", "raw_binary"], "auto"),
    ("language_id", str | None, None),
    ("compiler_spec_id", str | None, None),
    ("base_address", str | None, None),
    ("file_offset", int | None, None),
    ("length", int | None, None),
    ("block_name", str | None, None),
    ("overlay", bool, False),
    ("entry_address", str | None, None),
    ("entry_offset", int | None, None),
    ("analyze_imported", bool | None, None),
)

_GET_PROJECT_SYNC_STATUS_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("target", str, ...),
    ("program", str, ...),
    ("is_versioned", bool, ...),
    ("is_checked_out", bool, ...),
    ("is_checked_out_exclusive", bool, ...),
    ("is_latest_version", bool | None, ...),
    ("modified_since_checkout", bool, ...),
    ("can_add_to_repository", bool, ...),
    ("can_checkout", bool, ...),
    ("can_checkin", bool, ...),
    ("can_merge", bool, ...),
    ("is_hijacked", bool, ...),
    ("version", int | None, ...),
    ("latest_version", int | None, ...),
    ("checkout_status", dict[str, object] | None, ...),
    ("checkouts", list[object], ...),
    ("shared_project_url", str | None, ...),
)

_GET_VERSION_HISTORY_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("target", str, ...),
    ("program", str, ...),
    ("current_version", int, ...),
    ("latest_version", int, ...),
    ("total_versions", int, ...),
    ("versions", list[object], ...),
)

_GET_VERSION_DIFF_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("target", str, ...),
    ("program", str, ...),
    ("from_version", int, ...),
    ("to_version", int, ...),
    ("total_diff_addresses", int, ...),
    ("total_diff_ranges", int, ...),
    ("diff_types", list[object], ...),
    ("ranges", list[object], ...),
    ("ranges_truncated", bool, ...),
    ("warnings", str | None, ...),
)

_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("checked_out", bool, ...),
    ("already_checked_out", bool, ...),
    ("exclusive", bool, ...),
)

_ADD_PROJECT_PROGRAM_TO_VERSION_CONTROL_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("reason", str | None, None),
    ("target", str, ...),
    ("program", str, ...),
    ("is_versioned", bool | None, None),
    ("version", int | None, None),
    ("latest_version", int | None, None),
    ("checked_out", bool | None, None),
    ("effective_keep_checked_out", bool | None, None),
)

_COMMIT_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("reason", str | None, None),
    ("target", str, ...),
    ("program", str, ...),
    ("required_action", str | None, None),
    ("can_add_to_repository", bool | None, None),
    ("message", str | None, None),
    ("new_version", int | None, None),
    ("version", int | None, None),
    ("latest_version", int | None, None),
    ("checked_out", bool | None, None),
    ("effective_keep_checked_out", bool | None, None),
    ("is_latest_version", bool | None, None),
    ("discarded_local_changes", bool | None, None),
    ("merged", bool | None, None),
)

_PULL_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("updated", bool, ...),
    ("merged", bool, ...),
    ("discarded_local_changes", bool, ...),
    ("followed_latest", bool, ...),
    ("version", int | None, ...),
    ("latest_version", int | None, ...),
    ("is_latest_version", bool | None, ...),
)

_UNDO_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("reason", str | None, None),
    ("target", str, ...),
    ("program", str, ...),
    ("checked_out", bool | None, None),
    ("version", int | None, None),
    ("is_latest_version", bool | None, None),
    ("kept_program", str | None, None),
)

_TERMINATE_PROJECT_PROGRAM_CHECKOUT_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("checkout_id", int, ...),
    ("active_checkouts", list[object], ...),
)

_DELETE_SHARED_PROJECT_FILE_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("domain_path", str, ...),
    ("deleted", bool, ...),
    ("content_type", str | None, ...),
    ("was_versioned", bool, ...),
    ("version", int | None, ...),
    ("latest_version", int | None, ...),
)

_RELOAD_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("reloaded", bool, ...),
)

class ImportProgramInput(ToolInputModel):
    binary_path: str
    import_mode: Literal["auto", "raw_binary"] = "auto"
    language_id: str | None = None
    compiler_spec_id: str | None = None
    base_address: str | None = None
    file_offset: int | None = None
    length: int | None = None
    block_name: str | None = None
    overlay: bool = False
    entry_address: str | None = None
    entry_offset: int | None = None
    analyze_imported: bool | None = None

    @field_validator("binary_path", "language_id", "compiler_spec_id", "block_name")
    @classmethod
    def _strip_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("base_address", "entry_address")
    @classmethod
    def _validate_address_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        try:
            int(text, 0)
        except ValueError as exc:
            raise ValueError("must be a valid integer address such as 0x401000") from exc
        return text

    @field_validator("file_offset", "entry_offset")
    @classmethod
    def _validate_non_negative(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("must be >= 0")
        return value

    @field_validator("length")
    @classmethod
    def _validate_positive_length(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("must be > 0")
        return value

    @model_validator(mode="after")
    def _validate_import_options(self) -> "ImportProgramInput":
        if self.import_mode == "raw_binary" and not self.language_id:
            raise ValueError("language_id is required when import_mode='raw_binary'")
        if self.entry_address is not None and self.entry_offset is not None:
            raise ValueError("entry_address and entry_offset cannot both be set")
        if self.analyze_imported is None:
            self.analyze_imported = self.import_mode == "raw_binary"
        return self


def _pascal_case(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def _typed_fields(fields: tuple[ToolFieldSpec, ...]) -> dict[str, tuple[Any, Any]]:
    return {name: (annotation, default) for name, annotation, default in fields}


def _build_input_model(tool_name: str, input_fields: tuple[ToolFieldSpec, ...]) -> type[BaseModel]:
    if tool_name == "import_program":
        return ImportProgramInput
    return create_typed_input_model(f"{_pascal_case(tool_name)}Input", _typed_fields(input_fields))


def _build_output_model(
    tool_name: str,
    *,
    list_output: bool = False,
    scalar_output_type: type[Any] | None = None,
    output_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
) -> type[BaseModel]:
    model_name = f"{_pascal_case(tool_name)}Output"
    if output_fields:
        return create_typed_output_model(model_name, _typed_fields(output_fields))
    if scalar_output_type is not None:
        return create_scalar_output_model(model_name, scalar_output_type, allow_empty_list=True)
    if list_output:
        return create_list_output_model(model_name, object)
    return create_map_output_model(model_name, object, allow_empty_list=True)


def _build_public_signature(
    executor_kind: ExecutorKind,
    *,
    include_target: bool,
    input_fields: tuple[ToolFieldSpec, ...],
) -> tuple[str, ...]:
    field_names = tuple(name for name, _, _ in input_fields)
    if executor_kind == ExecutorKind.CORE_COMMAND and include_target:
        return (*field_names, "target")
    if include_target:
        return ("target", *field_names)
    return field_names


def _tool(
    *,
    name: str,
    category_tag: ToolCategoryTag,
    safety_tag: ToolSafetyTag,
    operation_level: ToolOperationLevel,
    executor_kind: ExecutorKind,
    command_or_method: str,
    input_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    list_output: bool = False,
    scalar_output_type: type[Any] | None = None,
    output_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    include_target: bool = True,
    static_kwargs: dict[str, Any] | None = None,
    result_adapter: str | None = None,
    error_adapter: str | None = None,
    public_name_overrides: dict[str, str] | None = None,
    include_none_keys: Iterable[str] = (),
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    read_only_hint: bool | None = None,
    destructive_hint: bool | None = None,
    idempotent_hint: bool | None = None,
    checkout_required: bool = False,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        category_tag=category_tag,
        safety_tag=safety_tag,
        operation_level=operation_level,
        executor_kind=executor_kind,
        command_or_method=command_or_method,
        input_model=_build_input_model(name, input_fields),
        output_model=_build_output_model(
            name,
            list_output=list_output,
            scalar_output_type=scalar_output_type,
            output_fields=output_fields,
        ),
        public_signature=_build_public_signature(
            executor_kind,
            include_target=include_target,
            input_fields=input_fields,
        ),
        include_target=include_target,
        static_kwargs=dict(static_kwargs or {}),
        result_adapter=result_adapter,
        error_adapter=error_adapter,
        public_name_overrides=dict(public_name_overrides or {}),
        include_none_keys=frozenset(include_none_keys),
        omit_falsey_keys=frozenset(omit_falsey_keys),
        description=description,
        read_only_hint=read_only_hint,
        destructive_hint=destructive_hint,
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
    )


def _core_tool(
    name: str,
    *,
    category_tag: ToolCategoryTag,
    safety_tag: ToolSafetyTag,
    operation_level: ToolOperationLevel,
    input_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    list_output: bool = False,
    scalar_output_type: type[Any] | None = None,
    output_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    public_name_overrides: dict[str, str] | None = None,
    include_none_keys: Iterable[str] = (),
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    read_only_hint: bool | None = None,
    idempotent_hint: bool | None = None,
    checkout_required: bool = False,
) -> ToolSpec:
    return _tool(
        name=name,
        category_tag=category_tag,
        safety_tag=safety_tag,
        operation_level=operation_level,
        executor_kind=ExecutorKind.CORE_COMMAND,
        command_or_method=name,
        input_fields=input_fields,
        list_output=list_output,
        scalar_output_type=scalar_output_type,
        output_fields=output_fields,
        public_name_overrides=public_name_overrides,
        include_none_keys=include_none_keys,
        omit_falsey_keys=omit_falsey_keys,
        description=description,
        read_only_hint=read_only_hint,
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
    )


def _registry_tool(
    name: str,
    *,
    method_name: str,
    category_tag: ToolCategoryTag,
    safety_tag: ToolSafetyTag,
    operation_level: ToolOperationLevel,
    input_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    list_output: bool = False,
    scalar_output_type: type[Any] | None = None,
    output_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    include_target: bool = True,
    static_kwargs: dict[str, Any] | None = None,
    result_adapter: str | None = None,
    error_adapter: str | None = None,
    public_name_overrides: dict[str, str] | None = None,
    include_none_keys: Iterable[str] = (),
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    read_only_hint: bool | None = None,
    idempotent_hint: bool | None = None,
) -> ToolSpec:
    return _tool(
        name=name,
        category_tag=category_tag,
        safety_tag=safety_tag,
        operation_level=operation_level,
        executor_kind=ExecutorKind.REGISTRY_METHOD,
        command_or_method=method_name,
        input_fields=input_fields,
        list_output=list_output,
        scalar_output_type=scalar_output_type,
        output_fields=output_fields,
        include_target=include_target,
        static_kwargs=static_kwargs,
        result_adapter=result_adapter,
        error_adapter=error_adapter,
        public_name_overrides=public_name_overrides,
        include_none_keys=include_none_keys,
        omit_falsey_keys=omit_falsey_keys,
        description=description,
        read_only_hint=read_only_hint,
        idempotent_hint=idempotent_hint,
    )


def _shared_sync_tool(
    name: str,
    *,
    method_name: str,
    safety_tag: ToolSafetyTag,
    operation_level: ToolOperationLevel,
    input_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    output_fields: tuple[ToolFieldSpec, ...] = _NO_FIELDS,
    description: str | None = None,
    include_none_keys: Iterable[str] = (),
    read_only_hint: bool | None = None,
    destructive_hint: bool | None = None,
    idempotent_hint: bool | None = None,
) -> ToolSpec:
    return _tool(
        name=name,
        category_tag=ToolCategoryTag.SHARED_SYNC,
        safety_tag=safety_tag,
        operation_level=operation_level,
        executor_kind=ExecutorKind.SHARED_SYNC_METHOD,
        command_or_method=method_name,
        input_fields=input_fields,
        output_fields=output_fields,
        include_none_keys=include_none_keys,
        description=description,
        read_only_hint=read_only_hint,
        destructive_hint=destructive_hint,
        idempotent_hint=idempotent_hint,
    )


_TOOL_SPEC_LIST: tuple[ToolSpec, ...] = (
    # core
    _registry_tool(
        "list_targets",
        method_name="list_targets",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        include_target=False,
        list_output=True,
        description=(
            "List registered targets and their state, including project info and whether a program "
            "is loaded (domain_path). Call this before target-scoped operations."
        ),
        read_only_hint=True,
        idempotent_hint=True,
    ),
    _registry_tool(
        "create_session",
        method_name="create_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("project_location", str, ...),
            ("domain_path", str, ...),
            ("project_name", str | None, None),
        ),
        output_fields=_CREATE_SESSION_OUTPUT_FIELDS,
        result_adapter="status_target_ok",
        error_adapter="create_session_error",
        include_none_keys=("project_name",),
        description=(
            "Create a new target session by opening a program in a Ghidra project. "
            "This is non-idempotent and fails if the target already exists. "
            "If the target already exists, use load_project_program."
        ),
        read_only_hint=False,
        idempotent_hint=False,
    ),
    _registry_tool(
        "register_target",
        method_name="register_target",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("project_location", str, ...),
            ("project_name", str | None, None),
        ),
        include_none_keys=("project_name",),
        description=(
            "Register a target with project information only, without loading a program yet. "
            "Use load_project_program later to open a domain path."
        ),
        read_only_hint=False,
        idempotent_hint=False,
    ),
    _registry_tool(
        "close_session",
        method_name="close_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        output_fields=_CLOSE_SESSION_OUTPUT_FIELDS,
        result_adapter="status_target_ok",
        error_adapter="close_session_error",
    ),
    _registry_tool(
        "close_session_and_remove_program",
        method_name="close_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
        operation_level=ToolOperationLevel.ADVANCED,
        output_fields=_CLOSE_SESSION_OUTPUT_FIELDS,
        static_kwargs={"remove_program": True},
        result_adapter="status_target_ok",
        error_adapter="close_remove_error",
    ),
    _registry_tool(
        "list_project_programs",
        method_name="list_programs",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        list_output=True,
    ),
    _registry_tool(
        "import_program",
        method_name="import_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_IMPORT_PROGRAM_FIELDS,
        scalar_output_type=str,
        result_adapter="status_program_ok",
        description="Import a binary, raw binary, or Ghidra archive (.gzf) into the current target's project",
    ),
    _registry_tool(
        "load_project_program",
        method_name="load_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("domain_path", str, ...),),
        scalar_output_type=str,
        result_adapter="status_program_ok",
        description=(
            "Load or switch a program for an existing target by domain path. "
            "Use this for targets that already exist (including project-only targets) "
            "instead of create_session."
        ),
        read_only_hint=False,
        idempotent_hint=False,
    ),
    # function_analysis
    _core_tool(
        "list_methods",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_functions",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
        description=(
            "List all functions in the loaded program for the target session. "
            "Requires an initialized target with a loaded program; call list_targets first, "
            "then use create_session or load_project_program when needed."
        ),
        read_only_hint=True,
        idempotent_hint=True,
    ),
    _core_tool(
        "list_classes",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_namespaces",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "search_functions_by_name",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("query", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
    ),
    _core_tool(
        "decompile_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("name", str, ...),),
        scalar_output_type=str,
    ),
    _core_tool(
        "decompile_function_by_address",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        scalar_output_type=str,
    ),
    _core_tool(
        "disassemble_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        list_output=True,
    ),
    _core_tool(
        "get_function_by_address",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
    ),
    _core_tool(
        "get_function_xrefs",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("name", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
    ),
    _core_tool(
        "get_callee",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        list_output=True,
    ),
    # memory_data
    _core_tool(
        "list_segments",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_imports",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_exports",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_data_items",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
    ),
    _core_tool(
        "list_strings",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("offset", int, 0),
            ("limit", int, 2000),
            ("filter", str | None, None),
        ),
        list_output=True,
        omit_falsey_keys=("filter",),
    ),
    _core_tool(
        "get_xrefs_to",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
    ),
    _core_tool(
        "get_xrefs_from",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
    ),
    _core_tool(
        "get_data_by_label",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("label", str, ...),),
        list_output=True,
    ),
    _core_tool(
        "get_bytes",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("size", int, 16),
        ),
        scalar_output_type=str,
    ),
    _core_tool(
        "search_bytes",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("bytes", str, ...),
            *_OFFSET_LIMIT_FIELDS,
        ),
        list_output=True,
        public_name_overrides={"bytes": "pattern"},
    ),
    # symbol_comment_edit
    _core_tool(
        "rename_function",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("oldName", str, ...),
            ("newName", str, ...),
        ),
        public_name_overrides={"oldName": "old_name", "newName": "new_name"},
        checkout_required=True,
    ),
    _core_tool(
        "rename_function_by_address",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("function_address", str, ...),
            ("new_name", str, ...),
        ),
        checkout_required=True,
    ),
    _core_tool(
        "rename_variable",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("functionName", str, ...),
            ("oldName", str, ...),
            ("newName", str, ...),
        ),
        public_name_overrides={
            "functionName": "function_name",
            "oldName": "old_name",
            "newName": "new_name",
        },
        checkout_required=True,
    ),
    _core_tool(
        "rename_data",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("newName", str, ...),
        ),
        public_name_overrides={"newName": "new_name"},
        checkout_required=True,
    ),
    _core_tool(
        "set_function_prototype",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("function_address", str, ...),
            ("prototype", str, ...),
        ),
        checkout_required=True,
    ),
    _core_tool(
        "set_local_variable_type",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("function_address", str, ...),
            ("variable_name", str, ...),
            ("new_type", str, ...),
        ),
        checkout_required=True,
    ),
    _core_tool(
        "set_global_data_type",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("data_type", str, ...),
            ("length", int | None, None),
            ("clear_mode", str | None, None),
        ),
        omit_falsey_keys=("clear_mode",),
        checkout_required=True,
    ),
    _core_tool(
        "set_bytes",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.UNSAFE_BINARY_DESTRUCTIVE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("bytes", str, ...),
        ),
        public_name_overrides={"bytes": "bytes_hex"},
        checkout_required=True,
    ),
    _core_tool(
        "set_decompiler_comment",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("comment", str, ...),
        ),
        checkout_required=True,
    ),
    _core_tool(
        "set_disassembly_comment",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("comment", str, ...),
        ),
        checkout_required=True,
    ),
    _core_tool(
        "add_bookmark",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.SAFE_NONSEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("category", str, ...),
            ("comment", str, ...),
            ("type", str, ...),
            ("format", str, "json"),
        ),
        checkout_required=True,
    ),
    # datatype_ops
    _core_tool(
        "create_struct",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("size", int, 0),
            ("category", str | None, None),
            ("members", list[dict] | None, None),
        ),
        omit_falsey_keys=("category", "members"),
        checkout_required=True,
    ),
    _core_tool(
        "add_struct_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("struct_name", str, ...),
            ("members", list[dict], ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
    ),
    _core_tool(
        "clear_struct",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("struct_name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
    ),
    _core_tool(
        "remove_struct_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("struct_name", str, ...),
            ("members", list[str], ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
    ),
    _core_tool(
        "get_struct",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
    ),
    _core_tool(
        "create_enum",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("name", str, ...),
            ("size", int, 4),
            ("category", str | None, None),
            ("values", list[dict] | None, None),
        ),
        omit_falsey_keys=("category", "values"),
        checkout_required=True,
    ),
    _core_tool(
        "add_enum_values",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("enum_name", str, ...),
            ("values", list[dict], ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
    ),
    _core_tool(
        "remove_enum_values",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("enum_name", str, ...),
            ("values", list[str], ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
    ),
    _core_tool(
        "get_enum",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
    ),
    _core_tool(
        "create_class",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("name", str, ...),
            ("parent_namespace", str | None, None),
            ("members", list[dict] | None, None),
        ),
        omit_falsey_keys=("members", "parent_namespace"),
        checkout_required=True,
    ),
    _core_tool(
        "add_class_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("class_name", str, ...),
            ("members", list[dict], ...),
            ("parent_namespace", str | None, None),
        ),
        omit_falsey_keys=("parent_namespace",),
        checkout_required=True,
    ),
    _core_tool(
        "remove_class_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("class_name", str, ...),
            ("members", list[str], ...),
            ("parent_namespace", str | None, None),
        ),
        omit_falsey_keys=("parent_namespace",),
        checkout_required=True,
    ),
    # shared_sync
    _shared_sync_tool(
        "get_project_sync_status",
        method_name="get_project_sync_status",
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(_DOMAIN_PATH_FIELD,),
        output_fields=_GET_PROJECT_SYNC_STATUS_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Get shared-project version-control status for the target program",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "get_version_history",
        method_name="get_version_history",
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("limit", int, 50),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_GET_VERSION_HISTORY_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Get version history metadata for the target program in a shared project",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "get_version_diff",
        method_name="get_version_diff",
        safety_tag=ToolSafetyTag.SAFE_READONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("from_version", int, ...),
            ("to_version", int, ...),
            ("range_limit", int, 200),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_GET_VERSION_DIFF_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Get a summary of differences between two shared-project versions of the target program",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "checkout_project_program",
        method_name="checkout_project_program",
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("exclusive", bool, False),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Checkout the target program in a shared project",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "add_project_program_to_version_control",
        method_name="add_project_program_to_version_control",
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("comment", str, ...),
            ("keep_checked_out", bool, False),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_ADD_PROJECT_PROGRAM_TO_VERSION_CONTROL_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Add the target program to shared-project version control",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "commit_project_program",
        method_name="commit_project_program",
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("message", str, ...),
            ("keep_checked_out", bool, False),
            ("auto_checkout", bool, True),
            ("on_conflict", str, "abort"),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_COMMIT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description=(
            "Check-in changes of the target program to the shared project server; "
            "on_conflict controls stale checkout handling"
        ),
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "pull_project_program",
        method_name="pull_project_program",
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("on_local_changes", str, "abort"),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_PULL_PROJECT_PROGRAM_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Pull/merge latest remote changes for the target program",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "undo_checkout_project_program",
        method_name="undo_checkout_project_program",
        safety_tag=ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("discard_local_changes", bool, True),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_UNDO_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Undo checkout for the target program (optionally discard local changes)",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "terminate_project_program_checkout",
        method_name="terminate_project_program_checkout",
        safety_tag=ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("checkout_id", int, ...),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_TERMINATE_PROJECT_PROGRAM_CHECKOUT_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Terminate a stale checkout by checkout id for the target program",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "delete_shared_project_file",
        method_name="delete_shared_project_file",
        safety_tag=ToolSafetyTag.UNSAFE_NONBINARY_DESTRUCTIVE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("domain_path", str, ...),
            ("confirm", str, ...),
            ("expected_latest_version", int | None, None),
            ("allow_private", bool, False),
        ),
        output_fields=_DELETE_SHARED_PROJECT_FILE_OUTPUT_FIELDS,
        description="Delete a shared-project file after confirmation and checkout safety checks",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "reload_project_program",
        method_name="reload_project_program",
        safety_tag=ToolSafetyTag.UNSAFE_SEMANTIC_EDIT,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(_DOMAIN_PATH_FIELD,),
        output_fields=_RELOAD_PROJECT_PROGRAM_OUTPUT_FIELDS,
        include_none_keys=("domain_path",),
        description="Reload the target program by closing and reopening the current domain path",
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=True,
    ),
)

_TOOL_SPECS: dict[str, ToolSpec] = {spec.name: spec for spec in _TOOL_SPEC_LIST}

_DEFAULT_PROFILE_CATEGORIES = frozenset(
    {
        ToolCategoryTag.CORE,
        ToolCategoryTag.FUNCTION_ANALYSIS,
        ToolCategoryTag.MEMORY_DATA,
        ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        ToolCategoryTag.DATATYPE_OPS,
    }
)

_PROFILE_SPECS: dict[ToolProfile, ToolProfileSpec] = {
    ToolProfile.DEFAULT: ToolProfileSpec(categories=_DEFAULT_PROFILE_CATEGORIES),
    ToolProfile.READONLY: ToolProfileSpec(
        categories=_DEFAULT_PROFILE_CATEGORIES,
        safety_tags=frozenset({ToolSafetyTag.SAFE_READONLY}),
    ),
    ToolProfile.FULL: ToolProfileSpec(
        categories=frozenset(ToolCategoryTag),
        safety_tags=frozenset(ToolSafetyTag),
        operation_levels=frozenset(ToolOperationLevel),
    ),
}


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


def _resolve_profile_constraint(
    profile_values: frozenset[Enum] | None,
    requested_values: Iterable[str | Enum] | None,
    *,
    enum_cls: type[Enum],
    label: str,
) -> set[Enum] | None:
    resolved = set(profile_values) if profile_values is not None else None
    requested = _coerce_enum_set(requested_values, enum_cls=enum_cls, label=label)
    if requested is None:
        return resolved
    return requested if resolved is None else resolved & requested


def get_tool_spec(name: str) -> ToolSpec:
    try:
        return _TOOL_SPECS[name]
    except KeyError as exc:
        raise KeyError(f"Unsupported tool spec: {name}") from exc


def get_all_tool_specs() -> dict[str, ToolSpec]:
    return dict(_TOOL_SPECS)


def get_public_tool_names() -> set[str]:
    return set(_TOOL_SPECS)


def get_checkout_required_tool_names(specs: dict[str, ToolSpec] | None = None) -> set[str]:
    available_specs = _TOOL_SPECS if specs is None else specs
    return {
        spec.command_or_method
        for spec in available_specs.values()
        if spec.executor_kind == ExecutorKind.CORE_COMMAND and spec.checkout_required
    }


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
    allowed_categories = _coerce_enum_set(
        allow_categories,
        enum_cls=ToolCategoryTag,
        label="category",
    )
    if allowed_categories is not None:
        categories = set(allowed_categories)
    added_categories = _coerce_enum_set(
        add_categories,
        enum_cls=ToolCategoryTag,
        label="category",
    )
    if added_categories is not None:
        categories.update(added_categories)

    safety_tags = _resolve_profile_constraint(
        profile_spec.safety_tags,
        allow_safety,
        enum_cls=ToolSafetyTag,
        label="safety tag",
    )
    operation_levels = _resolve_profile_constraint(
        profile_spec.operation_levels,
        allow_operation_levels,
        enum_cls=ToolOperationLevel,
        label="operation level",
    )

    selected_names = {
        name
        for name, spec in available_specs.items()
        if spec.category_tag in categories
        and (safety_tags is None or spec.safety_tag in safety_tags)
        and (operation_levels is None or spec.operation_level in operation_levels)
    }

    selected_names.update(enable_tools or ())
    selected_names.difference_update(disable_tools or ())

    return {name: spec for name, spec in available_specs.items() if name in selected_names}


__all__ = [
    "ExecutorKind",
    "ToolCategoryTag",
    "ToolOperationLevel",
    "ToolProfile",
    "ToolSafetyTag",
    "ToolSpec",
    "filter_tool_specs",
    "get_all_tool_specs",
    "get_checkout_required_tool_names",
    "get_public_tool_names",
    "get_tool_spec",
]
