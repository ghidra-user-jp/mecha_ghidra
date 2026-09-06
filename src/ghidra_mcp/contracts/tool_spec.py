"""Declarative tool specifications used by MCP wrappers and dispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any, Iterable, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

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
    BSIM = "bsim"
    FUNCTION_ANALYSIS = "function_analysis"
    MEMORY_DATA = "memory_data"
    SYMBOL_COMMENT_EDIT = "symbol_comment_edit"
    DATATYPE_OPS = "datatype_ops"
    SHARED_SYNC = "shared_sync"


class ToolSafetyTag(str, Enum):
    READ_ONLY = "read_only"
    WRITE = "write"
    DESTRUCTIVE_WRITE = "destructive_write"


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
    empty_list_policy: str = "normalize"
    include_target: bool = True
    static_kwargs: dict[str, Any] = field(default_factory=dict)
    result_adapter: str | None = None
    error_adapter: str | None = None
    public_name_overrides: dict[str, str] = field(default_factory=dict)
    omit_falsey_keys: frozenset[str] = field(default_factory=frozenset)
    description: str | None = None
    short_description: str | None = None
    idempotent_hint: bool | None = None
    checkout_required: bool = False


@dataclass(frozen=True)
class ToolProfileSpec:
    categories: frozenset[ToolCategoryTag]
    safety_tags: frozenset[ToolSafetyTag] | None = None
    operation_levels: frozenset[ToolOperationLevel] | None = None


_NO_FIELDS: tuple[ToolFieldSpec, ...] = ()
_PAGE_OFFSET = Annotated[int, Field(ge=0, le=1_000_000)]
_PAGE_LIMIT = Annotated[int, Field(ge=1, le=10_000)]
_RANGE_LIMIT = Annotated[int, Field(ge=0, le=10_000)]
# Bounds below mirror the runtime checks so clients learn the limits from the
# schema instead of from a failed call.
_BYTE_COUNT = Annotated[int, Field(ge=1, le=1_048_576)]
_POSITIVE_INT = Annotated[int, Field(ge=1)]
_NON_NEGATIVE_INT = Annotated[int, Field(ge=0)]
_VERSION_NUMBER = Annotated[int, Field(ge=1)]
_UNIT_INTERVAL = Annotated[float, Field(ge=0.0, le=1.0)]
_BSIM_MATCHES_PER_FUNCTION = Annotated[int, Field(ge=1, le=1_000)]
_BSIM_MAX_RESULTS = Annotated[int, Field(ge=1, le=10_000)]
_BSIM_MAX_APPLY_FUNCTIONS = Annotated[int, Field(ge=1, le=10_000)]
_BSIM_MIN_FUNCTION_SIZE = Annotated[int, Field(ge=0, le=1_000_000)]
_DETAILS_LIMIT = Annotated[int, Field(ge=0, le=200)]
ConflictAction = Literal["abort", "discard"]
# Ghidra listing/decompiler comment slots (CodeUnit.*_COMMENT).
CommentKind = Literal["pre", "eol", "post", "plate", "repeatable"]
ExportFormat = Literal["gzf", "binary"]
_UNDO_STEPS = Annotated[int, Field(ge=1, le=100)]
_ENUM_SIZE = Annotated[int, Field(ge=1, le=8)]
# commit_project_program can also park the local edits in a .keep copy.
CommitConflictAction = Literal["abort", "discard", "keep"]
ClearDataMode = Literal[
    "CHECK_FOR_SPACE",
    "CLEAR_SINGLE_DATA",
    "CLEAR_ALL_UNDEFINED_CONFLICT_DATA",
    "CLEAR_ALL_DEFAULT_CONFLICT_DATA",
    "CLEAR_ALL_CONFLICT_DATA",
]
_OFFSET_LIMIT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("offset", _PAGE_OFFSET, 0),
    ("limit", _PAGE_LIMIT, 100),
)
_DOMAIN_PATH_FIELD: ToolFieldSpec = ("domain_path", str | None, None)
_STATUS_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
)
_LOAD_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    # True when the target already held this program and it was reopened in place.
    ("reloaded", bool, False),
    # Set when a past repository version was opened; such a session is read-only.
    ("version", int | None, None),
    ("read_only", bool, False),
)
_SAVE_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("saved", bool, ...),
)
_CREATE_SESSION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("project_location", str, ...),
    ("project_name", str | None, None),
    ("domain_path", str | None, None),
)
_CLOSE_SESSION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
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
    ("from_version", _VERSION_NUMBER, ...),
    ("to_version", _VERSION_NUMBER, ...),
    ("total_diff_addresses", int, ...),
    ("total_diff_ranges", int, ...),
    ("diff_types", list[object], ...),
    ("ranges", list[object], ...),
    ("ranges_truncated", bool, ...),
    # Populated only with include_details=true: Ghidra's Diff description per range start.
    ("details", list[object], ...),
    ("details_truncated", bool, ...),
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
    ("committed", bool | None, None),
    ("conflict_discarded", bool | None, None),
    ("conflict_kept", bool | None, None),
    ("kept_program", str | None, None),
)

_PULL_PROJECT_PROGRAM_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("updated", bool, ...),
    ("merged", bool, ...),
    ("discarded_local_changes", bool, ...),
    ("discarded_hijacked_file", bool | None, None),
    ("followed_latest", bool, ...),
    ("reloaded", bool, ...),
    # Following the latest version drops a stale checkout; the runtime reports
    # whether the program is still checked out so callers know to re-checkout.
    ("checked_out", bool, ...),
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
    ("checkout_id", _NON_NEGATIVE_INT, ...),
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
    ("atomic_version_guard", bool, ...),
)

_BSIM_URL_FIELD: ToolFieldSpec = ("bsim_url", str | None, None)
_BSIM_QUERY_FIELDS: tuple[ToolFieldSpec, ...] = (
    _BSIM_URL_FIELD,
    ("similarity_threshold", _UNIT_INTERVAL, 0.7),
    ("significance_threshold", _UNIT_INTERVAL, 0.0),
    ("matches_per_function", _BSIM_MATCHES_PER_FUNCTION, 10),
    ("max_results", _BSIM_MAX_RESULTS, 500),
    # The query program is usually in the database too; its own records match
    # every function perfectly and would bury the useful results.
    ("exclude_self", bool, True),
    ("min_function_size", _BSIM_MIN_FUNCTION_SIZE, 0),
)
_BSIM_FUNCTION_SELECTOR_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("address", str | None, None),
    ("function_name", str | None, None),
    ("addresses", list[str] | None, None),
    ("function_names", list[str] | None, None),
)
_BSIM_LOAD_MATCH_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("target", str, ...),
    ("program", str, ...),
    ("matched_function_address", str | None, None),
    ("matched_function_name", str | None, None),
    ("executable_md5", str | None, None),
    ("matched_ref_version", int, 1),
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
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    short_description: str | None = None,
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
        include_target=include_target,
        static_kwargs=dict(static_kwargs or {}),
        result_adapter=result_adapter,
        error_adapter=error_adapter,
        public_name_overrides=dict(public_name_overrides or {}),
        omit_falsey_keys=frozenset(omit_falsey_keys),
        description=description,
        short_description=short_description,
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
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    short_description: str | None = None,
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
        omit_falsey_keys=omit_falsey_keys,
        description=description,
        short_description=short_description,
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
    omit_falsey_keys: Iterable[str] = (),
    description: str | None = None,
    short_description: str | None = None,
    idempotent_hint: bool | None = None,
    checkout_required: bool = False,
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
        omit_falsey_keys=omit_falsey_keys,
        description=description,
        short_description=short_description,
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
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
    short_description: str | None = None,
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
        description=description,
        short_description=short_description,
        idempotent_hint=idempotent_hint,
    )


_TOOL_SPEC_LIST: tuple[ToolSpec, ...] = (
    # core
    _registry_tool(
        "list_targets",
        method_name="list_targets",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        include_target=False,
        list_output=True,
        description=(
            "List registered targets and their state, including project info and whether a program "
            "is loaded (domain_path). Call this before target-scoped operations."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "create_project",
        method_name="create_project",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("project_location", str, ...),
            ("project_name", str | None, None),
            ("overwrite", bool, False),
        ),
        include_target=False,
        description=(
            "Create an empty local Ghidra project. Refuses to overwrite an existing .gpr/.rep unless overwrite=true."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "create_session",
        method_name="create_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("project_location", str, ...),
            ("domain_path", str, ...),
            ("project_name", str | None, None),
        ),
        output_fields=_CREATE_SESSION_OUTPUT_FIELDS,
        result_adapter="status_target_ok",
        error_adapter="create_session_error",
        description=(
            "Create a new target session by opening a program in a Ghidra project. "
            "This is non-idempotent and fails if the target already exists. "
            "If the target already exists, use load_project_program."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "register_target",
        method_name="register_target",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("project_location", str, ...),
            ("project_name", str | None, None),
        ),
        description=(
            "Register a target with project information only, without loading a program yet. "
            "Use load_project_program later to open a domain path."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "close_session",
        method_name="close_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        output_fields=_CLOSE_SESSION_OUTPUT_FIELDS,
        result_adapter="status_target_ok",
        error_adapter="close_session_error",
        description=(
            "Close a target's program session. Unsaved changes are saved to the project first unless the program is unchanged."
        ),
    ),
    _registry_tool(
        "close_session_and_remove_program",
        method_name="close_session",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        output_fields=_CLOSE_SESSION_OUTPUT_FIELDS,
        static_kwargs={"remove_program": True},
        result_adapter="status_target_ok",
        error_adapter="close_remove_error",
        description=(
            "Close a target's session and delete the program from the project. Refuses versioned shared-project "
            "programs; use delete_shared_project_file (shared_sync) for those after closing the target."
        ),
    ),
    _registry_tool(
        "list_project_programs",
        method_name="list_programs",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        list_output=True,
        description=(
            "List the programs in the target's project with their domain paths and shared-project sync summary."
        ),
    ),
    _registry_tool(
        "import_program",
        method_name="import_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_IMPORT_PROGRAM_FIELDS,
        output_fields=_STATUS_PROGRAM_OUTPUT_FIELDS,
        result_adapter="status_program_ok",
        description=(
            "Import a binary, Ghidra archive (.gzf), or raw binary / shellcode into the current "
            "target's project. Raw imports support BinaryLoader options such as language_id, "
            "base_address, entry bootstrap, and automatic analysis."
        ),
    ),
    _registry_tool(
        "load_project_program",
        method_name="load_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("domain_path", str, ...),
            ("version", _VERSION_NUMBER | None, None),
        ),
        output_fields=_LOAD_PROJECT_PROGRAM_OUTPUT_FIELDS,
        result_adapter="status_program_ok",
        description=(
            "Load or switch a program for an existing target by domain path. "
            "Use this for targets that already exist (including project-only targets) instead of create_session. "
            "Loading the program the target already holds reopens it in place (reloaded=true), saving unsaved edits "
            "first. Pass version=N on a shared-project program to open that past repository version read-only "
            "(read_only=true): read tools work, mutating tools fail with READ_ONLY_PROGRAM."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "save_project_program",
        method_name="save_project_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(_DOMAIN_PATH_FIELD,),
        output_fields=_SAVE_PROJECT_PROGRAM_OUTPUT_FIELDS,
        description=(
            "Persist the currently loaded program for a target into its Ghidra project. "
            "Use this after mutating tools such as rename_function when changes "
            "must remain visible after reopening the project."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "get_program_info",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        description=(
            "Describe the loaded program: name, domain path, executable path/format/md5/sha256, language and "
            "compiler, endianness, image base and address range, memory size and block count, function and symbol "
            "counts, entry points, whether auto-analysis ran, unsaved changes, and undo/redo availability."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "undo_program_change",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("count", _UNDO_STEPS, 1),),
        checkout_required=True,
        description=(
            "Undo the most recent count transactions on the loaded program (each mutating tool call is one "
            "transaction). Returns the undone transaction names and what remains; status is noop when there is "
            "nothing to undo. Undo history is per session and is lost when the program is reloaded."
        ),
        idempotent_hint=False,
    ),
    _core_tool(
        "redo_program_change",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("count", _UNDO_STEPS, 1),),
        checkout_required=True,
        description="Redo up to count transactions undone by undo_program_change.",
        idempotent_hint=False,
    ),
    _registry_tool(
        "export_program",
        method_name="export_program",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("output_path", str, ...),
            ("format", ExportFormat, "gzf"),
            ("overwrite", bool, False),
        ),
        description=(
            "Write the loaded program to output_path as a Ghidra .gzf archive (format='gzf', the saved state "
            "including analysis) or as the raw bytes of its initialized memory (format='binary'). Refuses to "
            "replace an existing file unless overwrite=true; --allowed-export-root can restrict where files go. "
            "Save with save_project_program first so a .gzf includes recent edits."
        ),
        idempotent_hint=False,
    ),
    # bsim
    _registry_tool(
        "get_bsim_database_status",
        method_name="get_bsim_database_status",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(_BSIM_URL_FIELD,),
        include_target=False,
        description=(
            "Get BSim database metadata: executable count, configured executable categories, function tags, "
            "and backend/server details."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_add_executable_category",
        method_name="bsim_add_executable_category",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("category", str, ...),
            _BSIM_URL_FIELD,
        ),
        include_target=False,
        description="Add a user-defined executable metadata category to the BSim database.",
        idempotent_hint=True,
    ),
    _registry_tool(
        "list_bsim_executables",
        method_name="list_bsim_executables",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            _BSIM_URL_FIELD,
            ("name", str | None, None),
            ("md5", str | None, None),
            ("arch", str | None, None),
            ("compiler", str | None, None),
            ("limit", _PAGE_LIMIT, 100),
        ),
        include_target=False,
        omit_falsey_keys=("name", "md5", "arch", "compiler"),
        description="List BSim executable records with optional filters.",
        idempotent_hint=True,
    ),
    _registry_tool(
        "get_bsim_executable",
        method_name="get_bsim_executable",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            _BSIM_URL_FIELD,
            ("md5", str | None, None),
            ("name", str | None, None),
        ),
        include_target=False,
        omit_falsey_keys=("md5", "name"),
        description="Get one BSim executable record by md5 or executable name.",
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_update_executable_metadata",
        method_name="bsim_update_executable_metadata",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("categories", dict[str, object], ...),
            _BSIM_URL_FIELD,
            ("md5", str | None, None),
            ("name", str | None, None),
        ),
        include_target=False,
        omit_falsey_keys=("md5", "name"),
        description=(
            "Update executable metadata categories on an existing BSim executable record "
            "looked up by md5 or executable name."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_query_target",
        method_name="bsim_query_target",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=_BSIM_QUERY_FIELDS,
        description=(
            "Compare every function in the loaded target program against the BSim database and "
            "return matches with matched_ref values usable by bsim_load_matched_executable. "
            "Matches against the program's own database record are dropped unless exclude_self=false; "
            "min_function_size skips functions whose body is smaller than that many bytes."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_query_function",
        method_name="bsim_query_function",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            _BSIM_URL_FIELD,
            *_BSIM_FUNCTION_SELECTOR_FIELDS,
            ("similarity_threshold", _UNIT_INTERVAL, 0.7),
            ("significance_threshold", _UNIT_INTERVAL, 0.0),
            ("matches_per_function", _BSIM_MATCHES_PER_FUNCTION, 10),
            ("max_results", _BSIM_MAX_RESULTS, 100),
            ("exclude_self", bool, True),
        ),
        omit_falsey_keys=("address", "function_name", "addresses", "function_names"),
        description=(
            "Compare one or more functions in the loaded target program against the BSim database. "
            "Select them by address/function_name or, in one round trip, by the addresses/function_names "
            "lists (up to 1000 functions). Every selector must resolve or the call fails with BSIM_FUNCTION_NOT_FOUND."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_load_matched_executable",
        method_name="bsim_load_matched_executable",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("matched_ref", dict[str, object], ...),
            ("target", str | None, None),
        ),
        output_fields=_BSIM_LOAD_MATCH_OUTPUT_FIELDS,
        include_target=False,
        description=(
            "Load the executable referenced by a BSim matched_ref into a reusable target. "
            "If that executable is already loaded, returns the existing target instead of reloading it. "
            "A matched_ref that points at a Ghidra Server (ghidra://host/repo) is opened through a local cache "
            "project created under --bsim-remote-cache-dir; without that flag it fails with "
            "BSIM_REMOTE_PROJECT_LOAD_UNSUPPORTED."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_register_target",
        method_name="bsim_register_target",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            _BSIM_URL_FIELD,
            ("categories", dict[str, object] | None, None),
        ),
        omit_falsey_keys=("categories",),
        description=(
            "Generate signatures for the loaded target program and insert them into the BSim database. "
            "Optional categories ({category: value}) are stored in Program Information first, so the record is "
            "created with that metadata; category names must already exist in the database "
            "(bsim_add_executable_category) and, on a shared project, storing them requires a checkout. "
            "inserted_executables counts the program plus one stub record per library its call graph references "
            "(inserted_library_executables); executable_count is the database total excluding libraries. "
            "Re-registering an already ingested program fails with BSIM_ALREADY_REGISTERED."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "bsim_apply_matches",
        method_name="bsim_apply_matches",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            _BSIM_URL_FIELD,
            ("similarity_threshold", _UNIT_INTERVAL, 0.9),
            ("significance_threshold", _UNIT_INTERVAL, 0.0),
            ("matches_per_function", _BSIM_MATCHES_PER_FUNCTION, 5),
            ("max_functions", _BSIM_MAX_APPLY_FUNCTIONS, 500),
            ("only_default_names", bool, True),
            ("exclude_self", bool, True),
            ("min_function_size", _BSIM_MIN_FUNCTION_SIZE, 0),
            ("dry_run", bool, False),
            ("addresses", list[str] | None, None),
            ("function_names", list[str] | None, None),
        ),
        omit_falsey_keys=("addresses", "function_names"),
        description=(
            "Query the BSim database for the loaded program's functions and rename each one after its best match, "
            "all in one transaction. By default only functions that still carry a Ghidra default name (FUN_...) "
            "are renamed, matches whose own name is a default name are ignored, and a function whose top matches "
            "disagree on the name is skipped as ambiguous. Restrict the scope with addresses/function_names; "
            "dry_run=true returns the planned renames without changing the program. Requires a checkout on shared "
            "projects; call save_project_program afterwards to persist."
        ),
        idempotent_hint=False,
        checkout_required=True,
    ),
    _registry_tool(
        "bsim_update_target_signatures",
        method_name="bsim_update_target_signatures",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(_BSIM_URL_FIELD,),
        description=(
            "Push the loaded program's current function names and metadata back to its existing BSim records "
            "(Ghidra's generateupdates + commitupdates in one step). Feature vectors are not regenerated. "
            "Fails with BSIM_EXECUTABLE_NOT_FOUND when the program was never registered."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "bsim_delete_executable",
        method_name="bsim_delete_executable",
        category_tag=ToolCategoryTag.BSIM,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("confirm", str, ...),
            _BSIM_URL_FIELD,
            ("md5", str | None, None),
            ("name", str | None, None),
        ),
        include_target=False,
        omit_falsey_keys=("md5", "name"),
        description=(
            "Delete one executable and all of its function records from the BSim database, looked up by md5 or "
            "exact executable name. confirm must repeat the md5 (or the name when md5 is omitted). Use it before "
            "re-registering a program whose analysis changed."
        ),
        idempotent_hint=False,
    ),
    # function_analysis
    _core_tool(
        "list_functions",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            *_OFFSET_LIMIT_FIELDS,
            ("filter", str | None, None),
            ("only_default_names", bool, False),
        ),
        list_output=True,
        omit_falsey_keys=("filter", "only_default_names"),
        description=(
            "List functions of the loaded program with name, entry, body size, and is_thunk (paginated). "
            "filter is a case-insensitive name substring; only_default_names=true keeps only functions "
            "Ghidra named itself (FUN_...), i.e. the ones still waiting for a real name. "
            "Requires an initialized target with a loaded program; call list_targets first."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "list_namespaces",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(*_OFFSET_LIMIT_FIELDS, ("classes_only", bool, False)),
        list_output=True,
        omit_falsey_keys=("classes_only",),
        description=(
            "List namespaces of the loaded program as {name, is_class} (paginated); classes_only=true returns "
            "only class namespaces."
        ),
    ),
    _core_tool(
        "decompile_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("address", str | None, None),
            ("name", str | None, None),
        ),
        omit_falsey_keys=("address", "name"),
        scalar_output_type=str,
        description=(
            "Return C-like pseudocode for a function by address or name (address wins if both are set). Large output is compacted to a result_id."
        ),
    ),
    _core_tool(
        "disassemble_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        list_output=True,
        description=(
            "Return every instruction of the function containing the address as address, mnemonic, operands, and comment."
        ),
    ),
    _core_tool(
        "disassemble_range",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("start_address", str, ...),
            ("end_address", str | None, None),
            ("length", _POSITIVE_INT | None, None),
            ("limit", _PAGE_LIMIT, 200),
        ),
        list_output=True,
        description=(
            "Return instructions between start_address and end_address, or start_address plus length bytes, up to limit instructions."
        ),
    ),
    _core_tool(
        "create_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("name", str | None, None),
        ),
        checkout_required=True,
        description=(
            "Create a function at an address, disassembling it first when needed. Returns the existing function if one starts there."
        ),
    ),
    _core_tool(
        "delete_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(("address", str, ...),),
        checkout_required=True,
        description=(
            "Delete the function at or containing the address. The instructions stay; only the function definition is removed."
        ),
    ),
    _core_tool(
        "analyze_program",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("force", bool, False),),
        omit_falsey_keys=("force",),
        checkout_required=True,
        description=(
            "Run Ghidra auto-analysis if the program has not been analyzed yet; force=true runs it again on an "
            "already analyzed program. Can take minutes on large binaries."
        ),
    ),
    _core_tool(
        "get_function",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str | None, None),
            ("name", str | None, None),
        ),
        description=(
            "Describe a function by address or name (address wins if both are set): signature, return type, "
            "calling convention, parameters and local variables with types and storage, body range and size, "
            "thunk target, namespace, name source, and plate comment."
        ),
    ),
    _core_tool(
        "get_function_xrefs",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("address", str | None, None),
            ("name", str | None, None),
            *_OFFSET_LIMIT_FIELDS,
        ),
        list_output=True,
        omit_falsey_keys=("address", "name"),
        description=(
            "List the references to a function's entry point (its callers) as from address, from_function, and "
            "reference type, looked up by address or name (paginated). Outgoing calls come from get_callee."
        ),
    ),
    _core_tool(
        "get_callee",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        list_output=True,
        description=(
            "List the functions called from the function containing the address as {name, entry, is_external}; "
            "thunks resolve to their thunked target."
        ),
    ),
    # memory_data
    _core_tool(
        "list_segments",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
        description=("List memory blocks with start, end, length, and read/write/execute permissions (paginated)."),
    ),
    _core_tool(
        "list_imports",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
        description=(
            "List imported (external) symbols of the loaded program as {name, library, full_name, address} (paginated)."
        ),
    ),
    _core_tool(
        "list_exports",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
        description=("List exported symbols and external entry points as {name, address} (paginated)."),
    ),
    _core_tool(
        "list_data_items",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=_OFFSET_LIMIT_FIELDS,
        list_output=True,
        description=("List defined data items with address, data type, label, length, and value (paginated)."),
    ),
    _core_tool(
        "list_strings",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("offset", _PAGE_OFFSET, 0),
            ("limit", _PAGE_LIMIT, 2000),
            ("filter", str | None, None),
        ),
        list_output=True,
        omit_falsey_keys=("filter",),
        description=(
            "List defined strings with addresses, optionally filtered by a case-insensitive substring "
            "(paginated, default limit 2000)."
        ),
    ),
    _core_tool(
        "get_xrefs_to",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
        description=("List references to an address with the referencing address and reference type (paginated)."),
    ),
    _core_tool(
        "get_xrefs_from",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...), *_OFFSET_LIMIT_FIELDS),
        list_output=True,
        description=("List references made from an address (paginated)."),
    ),
    _core_tool(
        "get_data_by_label",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("label", str, ...),),
        list_output=True,
        description=("Return defined data items whose symbol matches the label, with their value representation."),
    ),
    _core_tool(
        "list_data_types",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("offset", _PAGE_OFFSET, 0),
            ("limit", _PAGE_LIMIT, 100),
            ("filter", str | None, None),
            ("category", str | None, None),
        ),
        list_output=True,
        omit_falsey_keys=("filter", "category"),
        description=(
            "List data types in the program's data type manager, optionally filtered by name substring or category path (paginated)."
        ),
    ),
    _core_tool(
        "get_bytes",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("size", _BYTE_COUNT, 16),
        ),
        scalar_output_type=str,
        description=("Return a hex dump of size bytes starting at address (1 to 1,048,576 bytes)."),
    ),
    _core_tool(
        "search_bytes",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("bytes", str, ...),
            *_OFFSET_LIMIT_FIELDS,
        ),
        list_output=True,
        public_name_overrides={"bytes": "pattern"},
        description=(
            "Find occurrences of a hex byte pattern in memory and return their addresses (paginated). "
            "Use ?? for a wildcard byte, e.g. '48 8b ?? 24'."
        ),
    ),
    # symbol_comment_edit
    _core_tool(
        "rename_function",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("newName", str, ...),
            ("address", str | None, None),
            ("oldName", str | None, None),
        ),
        public_name_overrides={
            "oldName": "old_name",
            "newName": "new_name",
        },
        checkout_required=True,
        description=("Rename a function found by address or old_name (address wins if both are set)."),
    ),
    _core_tool(
        "rename_variable",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("oldName", str, ...),
            ("newName", str, ...),
            ("functionAddress", str | None, None),
            ("functionName", str | None, None),
        ),
        public_name_overrides={
            "functionAddress": "function_address",
            "functionName": "function_name",
            "oldName": "old_name",
            "newName": "new_name",
        },
        omit_falsey_keys=("functionAddress", "functionName"),
        checkout_required=True,
        description=(
            "Rename a local variable or parameter of the function given by function_address or function_name "
            "(address wins). Decompiler-level symbols are renamed first; database variables are the fallback."
        ),
    ),
    _core_tool(
        "rename_data",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("newName", str, ...),
        ),
        public_name_overrides={"newName": "new_name"},
        checkout_required=True,
        description=("Rename the primary data symbol at an address. Function entry points must use rename_function."),
    ),
    _core_tool(
        "set_function_prototype",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("prototype", str, ...),
            ("function_address", str | None, None),
            ("function_name", str | None, None),
        ),
        omit_falsey_keys=("function_address", "function_name"),
        checkout_required=True,
        description=(
            "Apply a C prototype string to the function given by function_address or function_name (address wins), "
            "replacing its signature."
        ),
    ),
    _core_tool(
        "set_local_variable_type",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("variable_name", str, ...),
            ("new_type", str, ...),
            ("function_address", str | None, None),
            ("function_name", str | None, None),
        ),
        omit_falsey_keys=("function_address", "function_name"),
        checkout_required=True,
        description=(
            "Set the data type of a local variable or parameter by name in the function given by function_address "
            "or function_name (address wins)."
        ),
    ),
    _core_tool(
        "set_global_data_type",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("data_type", str, ...),
            ("length", int | None, None),
            ("clear_mode", ClearDataMode | None, None),
        ),
        omit_falsey_keys=("clear_mode",),
        checkout_required=True,
        description=(
            "Apply a data type at an address; clear_mode controls how conflicting existing data is cleared (default CHECK_FOR_SPACE)."
        ),
    ),
    _core_tool(
        "set_bytes",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("address", str, ...),
            ("bytes", str, ...),
        ),
        public_name_overrides={"bytes": "bytes_hex"},
        checkout_required=True,
        description=(
            "Overwrite memory at address with the given hex bytes (up to 1 MiB). This changes the program image."
        ),
    ),
    _core_tool(
        "set_comment",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("comment", str, ...),
            ("kind", CommentKind, ...),
        ),
        checkout_required=True,
        description=(
            "Set a comment at an address. kind selects the slot: 'pre' (above the line; this is what the "
            "decompiler shows), 'eol' (end of line in the listing), 'post', 'plate' (function header block), or "
            "'repeatable'. An empty comment clears that slot."
        ),
    ),
    _core_tool(
        "get_comments",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("address", str, ...),),
        description="Return the pre, eol, post, plate, and repeatable comments at an address (null when unset).",
        idempotent_hint=True,
    ),
    _core_tool(
        "search_symbols",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("query", str, ...),
            ("type", str | None, None),
            *_OFFSET_LIMIT_FIELDS,
        ),
        list_output=True,
        omit_falsey_keys=("type",),
        description=(
            "Search all symbols (functions, labels, data, namespaces, classes, ...) by name, case-insensitively; "
            "query may use * and ? globs, otherwise it matches as a substring. type filters by symbol kind such as "
            "Function, Label, Class, Namespace, Parameter, or LocalVar. Returns name, address, type, namespace, "
            "source, and whether the symbol is primary (paginated)."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "create_label",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("name", str, ...),
            ("make_primary", bool, True),
        ),
        checkout_required=True,
        description=(
            "Create a user-defined label at an address, even where no symbol exists yet; rename_data only renames "
            "existing symbols. make_primary=false keeps an existing primary label in place."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "add_bookmark",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("address", str, ...),
            ("category", str, ...),
            ("comment", str, ...),
            ("type", str, ...),
        ),
        checkout_required=True,
        description=("Add a bookmark of the given type and category at an address."),
    ),
    _core_tool(
        "list_bookmarks",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("offset", _PAGE_OFFSET, 0),
            ("limit", _PAGE_LIMIT, 100),
            ("address", str | None, None),
            ("type", str | None, None),
            ("category", str | None, None),
        ),
        list_output=True,
        omit_falsey_keys=("address", "type", "category"),
        description=("List bookmarks, optionally filtered by address, type, and category (paginated)."),
    ),
    _core_tool(
        "delete_bookmark",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("id", _NON_NEGATIVE_INT | None, None),
            ("address", str | None, None),
            ("category", str | None, None),
            ("comment", str | None, None),
            ("type", str | None, None),
        ),
        omit_falsey_keys=("address", "category", "comment", "type"),
        checkout_required=True,
        description=("Delete bookmarks by id, or by address plus type and category (optionally matching comment)."),
    ),
    # datatype_ops
    _core_tool(
        "create_struct",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("size", _NON_NEGATIVE_INT, 0),
            ("category", str | None, None),
            ("members", list[dict] | None, None),
        ),
        omit_falsey_keys=("category", "members"),
        checkout_required=True,
        description=("Create a structure data type; members is a list of {name, type, comment?, offset?} objects."),
    ),
    _core_tool(
        "add_struct_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("struct_name", str, ...),
            ("members", list[dict], ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
        description=("Append or place members ({name, type, comment?, offset?}) in an existing structure."),
    ),
    _core_tool(
        "delete_data_type",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
        description=(
            "Delete a data type (structure, union, enum, typedef, ...) from the program's data type manager, "
            "found by name and optionally category."
        ),
    ),
    _core_tool(
        "remove_struct_members",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("struct_name", str, ...),
            ("members", list[str | dict] | None, None),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category", "members"),
        checkout_required=True,
        description=(
            "Remove members from a structure; members accepts names or {name} objects, and omitting it removes "
            "every member while keeping the type."
        ),
    ),
    _core_tool(
        "get_struct",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        description=("Return a structure's members with offsets, lengths, types, and comments."),
    ),
    _core_tool(
        "rename_data_type",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("new_name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
        description=("Rename a data type found by name (optionally within a category)."),
    ),
    _core_tool(
        "create_enum",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("values", dict[str, object] | None, None),
            ("size", _ENUM_SIZE, 4),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("values", "category"),
        checkout_required=True,
        description=(
            "Create an enum data type of size 1, 2, 4, or 8 bytes; values maps each name to an integer (or to "
            "{value, comment}); hex strings such as '0x10' are accepted."
        ),
        idempotent_hint=False,
    ),
    _core_tool(
        "set_enum_values",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("name", str, ...),
            ("values", dict[str, object] | None, None),
            ("remove", list[str] | None, None),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("values", "remove", "category"),
        checkout_required=True,
        description=(
            "Add or replace named values on an existing enum and/or remove names listed in remove; at least one of "
            "values or remove is required."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "parse_c_declarations",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("source", str, ...),),
        checkout_required=True,
        description=(
            "Parse C declarations (structs, unions, enums, typedefs, function prototypes) with Ghidra's C parser "
            "and add the resulting data types to the program. Returns the names created per kind; a syntax error "
            "fails with C_PARSE_FAILED and adds nothing."
        ),
        idempotent_hint=True,
    ),
    _core_tool(
        "get_enum",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("name", str, ...),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        description=("Return an enum's values, comments, and size."),
    ),
    # shared_sync
    _shared_sync_tool(
        "get_project_sync_status",
        method_name="get_project_sync_status",
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(_DOMAIN_PATH_FIELD,),
        output_fields=_GET_PROJECT_SYNC_STATUS_OUTPUT_FIELDS,
        description="Get shared-project version-control status for the target program",
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "get_version_history",
        method_name="get_version_history",
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("limit", _PAGE_LIMIT, 50),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_GET_VERSION_HISTORY_OUTPUT_FIELDS,
        description="Get version history metadata for the target program in a shared project",
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "get_version_diff",
        method_name="get_version_diff",
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("from_version", _VERSION_NUMBER, ...),
            ("to_version", _VERSION_NUMBER, ...),
            ("range_limit", _RANGE_LIMIT, 200),
            ("include_details", bool, False),
            ("details_limit", _DETAILS_LIMIT, 20),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_GET_VERSION_DIFF_OUTPUT_FIELDS,
        description=(
            "Get a summary of differences between two shared-project versions of the target program: counts, "
            "difference types, and address ranges. include_details=true adds Ghidra's Diff description (symbols, "
            "comments, code units, functions) at the start of the first details_limit ranges."
        ),
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "checkout_project_program",
        method_name="checkout_project_program",
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("exclusive", bool | None, None),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        description=(
            "Checkout the target program in a shared project. exclusive omitted uses the server default "
            "(--shared-sync-exclusive-checkout); an exclusive checkout blocks other users' checkouts so no merge "
            "can become necessary."
        ),
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "add_project_program_to_version_control",
        method_name="add_project_program_to_version_control",
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("comment", str, ...),
            ("keep_checked_out", bool, False),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_ADD_PROJECT_PROGRAM_TO_VERSION_CONTROL_OUTPUT_FIELDS,
        description="Add the target program to shared-project version control",
        idempotent_hint=True,
    ),
    _shared_sync_tool(
        "commit_project_program",
        method_name="commit_project_program",
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("message", str, ...),
            ("keep_checked_out", bool, False),
            ("auto_checkout", bool, True),
            ("on_conflict", CommitConflictAction, "abort"),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_COMMIT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        description=(
            "Check-in changes of the target program to the shared project server. When the checkout is stale "
            "(someone else committed first) on_conflict decides: 'abort' fails with MERGE_REQUIRED, 'keep' parks the "
            "local edits in a <name>.keep copy (kept_program) and follows the latest version, 'discard' drops them."
        ),
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "pull_project_program",
        method_name="pull_project_program",
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("on_local_changes", ConflictAction, "abort"),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_PULL_PROJECT_PROGRAM_OUTPUT_FIELDS,
        description=(
            "Follow the latest repository version of the target program. A stale checkout is dropped "
            "and the program is reopened at the latest version, so checked_out is false afterwards and a new "
            "checkout is required before mutating; on_local_changes controls whether local edits are discarded"
        ),
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "undo_checkout_project_program",
        method_name="undo_checkout_project_program",
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("discard_local_changes", bool, True),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_UNDO_CHECKOUT_PROJECT_PROGRAM_OUTPUT_FIELDS,
        description="Undo checkout for the target program (optionally discard local changes)",
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "terminate_project_program_checkout",
        method_name="terminate_project_program_checkout",
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("checkout_id", _NON_NEGATIVE_INT, ...),
            _DOMAIN_PATH_FIELD,
        ),
        output_fields=_TERMINATE_PROJECT_PROGRAM_CHECKOUT_OUTPUT_FIELDS,
        description="Terminate a stale checkout by checkout id for the target program",
        idempotent_hint=False,
    ),
    _shared_sync_tool(
        "delete_shared_project_file",
        method_name="delete_shared_project_file",
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        input_fields=(
            ("domain_path", str, ...),
            ("confirm", str, ...),
            ("expected_latest_version", _VERSION_NUMBER | None, None),
            ("allow_private", bool, False),
            ("allow_non_atomic_versioned_delete", bool, False),
        ),
        output_fields=_DELETE_SHARED_PROJECT_FILE_OUTPUT_FIELDS,
        description=(
            "Delete a project file that no target has loaded, after confirmation and checkout safety checks; "
            "versioned deletion requires an explicit non-atomic-risk acknowledgement. For the program a target "
            "currently holds use close_session_and_remove_program instead (private programs only)."
        ),
        idempotent_hint=False,
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
        safety_tags=frozenset({ToolSafetyTag.READ_ONLY}),
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
    # Checkout enforcement keys on the core command name. CORE_COMMAND tools expose it
    # directly as command_or_method; REGISTRY_METHOD tools that wrap a core command (e.g.
    # bsim_apply_matches) use a method_name identical to that core command, so they
    # contribute the same name here.
    return {
        spec.command_or_method
        for spec in available_specs.values()
        if spec.checkout_required and spec.executor_kind in (ExecutorKind.CORE_COMMAND, ExecutorKind.REGISTRY_METHOD)
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
    "CommentKind",
    "ExportFormat",
    "CommitConflictAction",
    "ConflictAction",
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
