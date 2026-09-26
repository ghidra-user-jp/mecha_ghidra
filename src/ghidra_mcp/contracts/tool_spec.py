"""Declarative tool specifications used by MCP wrappers and dispatcher."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any, Iterable, Literal

from pydantic import AfterValidator, BaseModel, Field, field_validator, model_validator

from ghidra_mcp.domain.identifiers import canonical_uuid

from .batch_models import batch_input_model
from .edit_models import Edits
from .tool_descriptions import SHORT_TOOL_DESCRIPTIONS
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
    SCRIPTS = "scripts"


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
    # Presentation pipeline variant. ``None`` is the generic value/compaction
    # path; ``"batch"`` selects the batch manifest envelope, the per-item output
    # validation and the child-tool enablement check in the presentation layer.
    # ``"operation"`` marks a background-job tool: its bounded job record is
    # returned as-is (never replaced by a stored-result reference), the MCP
    # binding may wait for the job, and get_operation must stay published.
    presenter: str | None = None

    @property
    def writes(self) -> bool:
        """Whether a call may change something, so its failure says what it left behind (``output_state``)."""
        return self.safety_tag != ToolSafetyTag.READ_ONLY

    @property
    def deferrable(self) -> bool:
        """Whether a call still running after the deferral wait replies with a job record instead.

        Job tools already reply with records. list_targets reads registry state
        only and always answers at once.
        """
        return self.presenter != "operation" and self.name != "list_targets"

    @property
    def reports_source(self) -> bool:
        """Whether a result names the program state it came from (``source``: target, program, revision).

        A core command reads or changes one target's program under its locks;
        the revision is the one ``expected_revision`` takes.
        """
        # batch_read names the program and revision in its one JSON block already.
        return self.executor_kind == ExecutorKind.CORE_COMMAND and self.include_target and self.presenter != "batch"

    @property
    def replays_requests(self) -> bool:
        """Whether a resend with the same ``request_id`` gets the first call's reply instead of running again.

        Job tools keep their own request records; see GhidraMCPServer for the rest.
        """
        return self.presenter != "operation" and "request_id" in self.input_model.model_fields


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
_BSIM_SIGNIFICANCE = Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
_BSIM_MATCHES_PER_FUNCTION = Annotated[int, Field(ge=1, le=1_000)]
_BSIM_MAX_RESULTS = Annotated[int, Field(ge=1, le=10_000)]
_BSIM_MAX_APPLY_FUNCTIONS = Annotated[int, Field(ge=1, le=10_000)]
_BSIM_MIN_FUNCTION_SIZE = Annotated[int, Field(ge=0, le=1_000_000)]
_DETAILS_LIMIT = Annotated[int, Field(ge=0, le=200)]
ConflictAction = Literal["abort", "discard"]
# Ghidra listing/decompiler comment slots (CommentType).
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
    # Loading never analyzes; false means analyze_program should run first.
    # null: the program was reopened but its flag could not be read.
    ("is_analyzed", bool | None, ...),
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
    # null: the program opened but its flag could not be read (get_program_info reports it).
    ("is_analyzed", bool | None, ...),
)
_CLOSE_SESSION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("status", str, ...),
    ("closed", bool, ...),
    ("target", str, ...),
    ("remove_program", bool, ...),
    ("discard_changes", bool, False),
)
_SCRIPT_TIMEOUT_SECONDS = Annotated[int, Field(ge=1, le=3_600)]
ScriptRuntimeName = Literal["Java", "Jython", "PyGhidra"]
ScriptOrigin = Literal["operator", "bundled"]
# Server-side wait of the background-job tools. The cap stays well below common
# client call budgets (60 s is a frequent default) so a waiting call never times out.
OPERATION_WAIT_DEFAULT_SECONDS = 20
OPERATION_WAIT_MAX_SECONDS = 50
# A tool call still running after this many seconds replies deferred=true with
# a job record and goes on (presentation.deferred_calls): well inside that
# 60-second budget, and above the default lock wait.
DEFER_AFTER_SECONDS = 40.0
# The background-job tools, and the tools that read and cancel their records.
JOB_TOOLS = ("import_program", "analyze_program", "run_script")
OPERATION_CONTROL_TOOLS = frozenset({"get_operation", "cancel_operation"})
_OPERATION_WAIT_DESCRIPTION = (
    "Response wait budget in seconds, including startup and admission. "
    "0 skips waiting for completion (admission still has a 40-second deadline). "
    "Replies early when the job succeeds or fails."
)
_OPERATION_STATE = Literal["queued", "running", "succeeded", "failed"]
_OPERATION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("operation_id", str, ...),
    # import_program, analyze_program or run_script for a queued job; any
    # other tool's name for a call that outlived its reply.
    ("kind", str, ...),
    ("request_id", str | None, ...),
    ("server_instance_id", str, ...),
    ("target", str, ...),
    ("state", _OPERATION_STATE, ...),
    ("phase", Literal["queued", "waiting_for_lock", "executing"], ...),
    ("poll_after_ms", _NON_NEGATIVE_INT, ...),
    ("created_at", str, ...),
    ("updated_at", str, ...),
    ("started_at", str | None, ...),
    ("finished_at", str | None, ...),
    # What the tool returned: any JSON value, or a stored-result reference when large.
    ("result", object, ...),
    # For a deferred program tool: the program state its result came from, as its reply names it.
    ("source", dict[str, object] | None, None),
    ("operation_error", dict[str, object] | None, ...),
    # Present (true) only when the server dropped a large result to bound its memory.
    ("result_discarded", bool, False),
)
# What a job-submitting tool returns: the record, and whether it repeats an earlier request.
_SUBMIT_OPERATION_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    *_OPERATION_OUTPUT_FIELDS,
    ("replayed", bool, ...),
)
_REQUEST_ID_DESCRIPTION = (
    "Optional client UUID for this job. Resending it with the same arguments returns the same job, "
    "and get_operation can look the job up by it if this reply is lost."
)


def _canonical_request_id(value: str | None) -> str | None:
    return None if value is None else canonical_uuid(value)


# The request_id and the server-side wait every background-job tool takes.
_JOB_REQUEST_ID = Annotated[
    str | None, AfterValidator(_canonical_request_id), Field(description=_REQUEST_ID_DESCRIPTION)
]
_JOB_WAIT_SECONDS = Annotated[int, Field(ge=0, le=OPERATION_WAIT_MAX_SECONDS, description=_OPERATION_WAIT_DESCRIPTION)]


# A write that must not apply twice when its reply is lost and the call is sent
# again.  Every program write has it (see _core_tool), so its text is short.
_CALL_REQUEST_ID_FIELD: ToolFieldSpec = (
    "request_id",
    Annotated[
        str | None,
        AfterValidator(_canonical_request_id),
        Field(
            description=(
                "Optional client UUID. Resending it with the same arguments returns the first reply instead of "
                "applying the write again."
            )
        ),
    ],
    None,
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
    ("significance_threshold", _BSIM_SIGNIFICANCE, 0.0),
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
    request_id: _JOB_REQUEST_ID = None
    wait_seconds: _JOB_WAIT_SECONDS = OPERATION_WAIT_DEFAULT_SECONDS
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
    analyze_imported: bool | None = Field(
        default=True,
        description=(
            "Run Ghidra auto-analysis inside the job (null means true). false leaves the program unanalyzed; "
            "loading does not analyze it, so run analyze_program later."
        ),
    )

    @field_validator("analyze_imported")
    @classmethod
    def _analysis_by_default(cls, value: bool | None) -> bool:
        # One spelling per request, so a resend with null matches the job it repeats.
        return True if value is None else value

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
            number = int(text, 0)
        except ValueError as exc:
            raise ValueError("must be a valid integer address such as 0x401000") from exc
        # One spelling per address, so a resend written as 0x08000000 or
        # 134217728 matches the job it repeats.
        return hex(number)

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
        return self


class AnalyzeProgramInput(ToolInputModel):
    force: bool = Field(default=False, description="Analyze again even when the program is already analyzed.")
    request_id: _JOB_REQUEST_ID = None
    wait_seconds: _JOB_WAIT_SECONDS = OPERATION_WAIT_DEFAULT_SECONDS


class RunScriptInput(ToolInputModel):
    script_id: str | None = None
    source: str | None = None
    runtime: ScriptRuntimeName | None = None
    script_name: str | None = None
    args: list[str] | None = None
    timeout_seconds: _SCRIPT_TIMEOUT_SECONDS | None = None
    expected_revision: str | None = None
    request_id: _JOB_REQUEST_ID = None
    wait_seconds: _JOB_WAIT_SECONDS = OPERATION_WAIT_DEFAULT_SECONDS


class CancelOperationInput(ToolInputModel):
    operation_id: str

    @field_validator("operation_id")
    @classmethod
    def _validate_operation_id(cls, value: str) -> str:
        return canonical_uuid(value)


class GetOperationInput(ToolInputModel):
    operation_id: str | None = None
    request_id: str | None = None
    wait_seconds: _JOB_WAIT_SECONDS = OPERATION_WAIT_DEFAULT_SECONDS

    @field_validator("operation_id", "request_id")
    @classmethod
    def _validate_uuid(cls, value: str | None) -> str | None:
        return None if value is None else canonical_uuid(value)

    @model_validator(mode="after")
    def _one_identifier(self) -> "GetOperationInput":
        if (self.operation_id is None) == (self.request_id is None):
            raise ValueError("Supply exactly one of operation_id or request_id")
        return self


def _pascal_case(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def _typed_fields(fields: tuple[ToolFieldSpec, ...]) -> dict[str, tuple[Any, Any]]:
    return {name: (annotation, default) for name, annotation, default in fields}


def _build_input_model(tool_name: str, input_fields: tuple[ToolFieldSpec, ...]) -> type[BaseModel]:
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
    input_model: type[BaseModel] | None = None,
    presenter: str | None = None,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        category_tag=category_tag,
        safety_tag=safety_tag,
        operation_level=operation_level,
        executor_kind=executor_kind,
        command_or_method=command_or_method,
        # A model of its own (a job's, with its validators) instead of one from input_fields.
        input_model=input_model or _build_input_model(name, input_fields),
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
        short_description=short_description or SHORT_TOOL_DESCRIPTIONS.get(name),
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
        presenter=presenter,
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
    input_model: type[BaseModel] | None = None,
    presenter: str | None = None,
) -> ToolSpec:
    if safety_tag != ToolSafetyTag.READ_ONLY and all(field[0] != "request_id" for field in input_fields):
        # Every program write can be resent after a lost reply without applying twice.
        input_fields = (*input_fields, _CALL_REQUEST_ID_FIELD)
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
        short_description=short_description or SHORT_TOOL_DESCRIPTIONS.get(name),
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
        input_model=input_model,
        presenter=presenter,
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
    input_model: type[BaseModel] | None = None,
    presenter: str | None = None,
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
        short_description=short_description or SHORT_TOOL_DESCRIPTIONS.get(name),
        idempotent_hint=idempotent_hint,
        checkout_required=checkout_required,
        input_model=input_model,
        presenter=presenter,
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
        short_description=short_description or SHORT_TOOL_DESCRIPTIONS.get(name),
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
            "Create an empty local Ghidra project. Refuses to overwrite an existing .gpr/.rep unless overwrite=true. "
            "Needs exclusive use of the server: while other operations such as a background import run, it returns "
            "a retryable LOCK_TIMEOUT after the lock timeout instead of holding them up."
        ),
        idempotent_hint=False,
    ),
    _registry_tool(
        "open_program",
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
            "Open an existing Ghidra program in a new target session. Opening never runs auto-analysis: when "
            "is_analyzed is false, run analyze_program before listing functions or decompiling. "
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
        input_fields=(("discard_changes", bool, False),),
        output_fields=_CLOSE_SESSION_OUTPUT_FIELDS,
        result_adapter="status_target_ok",
        error_adapter="close_session_error",
        description=(
            "Close a target's program session. Unsaved changes are saved to the project first unless the program is "
            "unchanged. discard_changes=true closes WITHOUT saving; it is also the recovery path after a script run "
            "left the program unverifiable (TARGET_EXECUTION_INVALID): close with discard_changes, then reload."
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
        output_fields=_SUBMIT_OPERATION_OUTPUT_FIELDS,
        description=(
            "Import a binary, Ghidra archive (.gzf), or raw binary as a background job and return the job "
            "record. The server waits up to wait_seconds for the job; while state is queued or running, call "
            "get_operation with operation_id. On success pass result.program to load_project_program. "
            "Resending the same arguments while the job runs returns the same job. A failure reports "
            "operation_error.details.output_state: absent (nothing was written; fix the cause and import "
            "again), created (the program exists; load it) or uncertain (inspect the project first). "
            "Keep the input file unchanged until the job finishes. The job also runs Ghidra auto-analysis "
            "unless analyze_imported=false. Raw imports support language_id, base_address and entry bootstrap."
        ),
        input_model=ImportProgramInput,
        presenter="operation",
    ),
    _registry_tool(
        "get_operation",
        method_name="get_operation",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        include_target=False,
        output_fields=_OPERATION_OUTPUT_FIELDS,
        description=(
            "Read a job by operation_id, or by the request_id given when it was submitted, without taking "
            "Ghidra locks: an import, analysis or script job, a write sent with a request_id, or any tool call "
            f"that replied deferred=true because it was still running after {DEFER_AFTER_SECONDS:g} seconds. "
            "Waits up to wait_seconds for it to finish, so "
            "call it again at once while state is queued or running. succeeded includes result, exactly what "
            "the tool returns (for an import, result.program is the project path; a deferred program tool's "
            "record also has source); failed includes "
            "operation_error. Job records live in server memory only: OPERATION_NOT_FOUND after a restart "
            "does not mean the job never ran, so inspect the project before submitting it again."
        ),
        input_model=GetOperationInput,
        presenter="operation",
    ),
    _registry_tool(
        "cancel_operation",
        method_name="cancel_operation",
        category_tag=ToolCategoryTag.CORE,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        include_target=False,
        output_fields=_OPERATION_OUTPUT_FIELDS,
        description=(
            "Cancel a queued or running import, analysis or script job and return its record. A job that has "
            "not started changing the program ends at once (OPERATION_CANCELLED, output_state=absent). A "
            "running one stops at its next cancellation check and rolls back its transaction; poll "
            "get_operation until it ends. A script that never checks its monitor cannot be stopped. Finished "
            "jobs and the records of tool calls (deferred, or sent with a request_id) cannot be cancelled "
            "(VALIDATION_ERROR)."
        ),
        input_model=CancelOperationInput,
        presenter="operation",
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
            "Use this for targets that already exist (including project-only targets) instead of open_program. "
            "Loading the program the target already holds reopens it in place (reloaded=true), saving unsaved edits "
            "first. Pass version=N on a shared-project program to open that past repository version read-only "
            "(read_only=true): read tools work, mutating tools fail with READ_ONLY_PROGRAM. Loading never runs "
            "auto-analysis: when is_analyzed is false, run analyze_program before listing functions or decompiling."
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
            "Use this after mutating tools such as apply_edits when changes "
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
            "Write the loaded program to output_path as a Ghidra .gzf archive of its current state, including "
            "unsaved edits and analysis results (format='gzf'), or as the raw bytes of its initialized memory "
            "(format='binary'). Refuses to replace an existing file unless overwrite=true; --allowed-export-root "
            "can restrict where files go. Exporting does not save the project: the changes stay unsaved until "
            "save_project_program."
        ),
        idempotent_hint=False,
    ),
    # scripts (inline execution needs no root; --script-root adds catalog entries)
    _registry_tool(
        "list_scripts",
        method_name="list_scripts",
        category_tag=ToolCategoryTag.SCRIPTS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        include_target=False,
        input_fields=(
            ("filter", str | None, None),
            ("runtime", ScriptRuntimeName | None, None),
            ("category", str | None, None),
            ("origin", ScriptOrigin | None, None),
            ("include_bundled", bool, False),
            *_OFFSET_LIMIT_FIELDS,
        ),
        description=(
            "List the Ghidra scripts the operator made executable (script_id = '<root>:<relative path>'). Each item "
            "reports runtime (Java/Jython/PyGhidra), category, description and whether it can run now. "
            "include_bundled=true also lists Ghidra's bundled scripts when the operator allowed them. Nothing is "
            "compiled or executed by listing."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "get_script_info",
        method_name="get_script_info",
        category_tag=ToolCategoryTag.SCRIPTS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        include_target=False,
        input_fields=(("script_id", str, ...), ("include_source", bool, False)),
        description=(
            "Describe one catalog script: runtime, header metadata and (include_source=true) its source text, "
            "so the arguments it expects can be read before run_script."
        ),
        idempotent_hint=True,
    ),
    _registry_tool(
        "run_script",
        method_name="run_script",
        category_tag=ToolCategoryTag.SCRIPTS,
        safety_tag=ToolSafetyTag.DESTRUCTIVE_WRITE,
        operation_level=ToolOperationLevel.ADVANCED,
        output_fields=_SUBMIT_OPERATION_OUTPUT_FIELDS,
        checkout_required=True,
        description=(
            "Run a Ghidra script against the loaded program, like the Script Manager does, as a background job "
            "and return the job record. The server waits up to wait_seconds; while state is queued or running, "
            "call get_operation with operation_id. Pass `source` with the script text (Java: 'public class X "
            "extends GhidraScript'; Python: start with '# @runtime PyGhidra' or '# @runtime Jython', or pass "
            "`runtime`), or `script_id` for a catalog script (list_scripts). `args` are the script's positional "
            "string arguments. The run is wrapped in a transaction: on success result.transaction_outcome is "
            "committed or unchanged; on an exception, timeout or cancel_operation the changes roll back. "
            "timeout_seconds (default 300, max 3600) and cancellation reach the script through its monitor, so "
            "a loop that never checks monitor.checkCancelled() cannot be interrupted. result or "
            "operation_error.details carry stdout, stderr and, for Java, compiler diagnostics, so a failing "
            "script can be corrected and re-run. output_state covers program changes only, not files or "
            "network effects. Resending the same arguments while the job is pending returns the same job."
        ),
        idempotent_hint=False,
        input_model=RunScriptInput,
        presenter="operation",
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
            "Signatures cover the functions analysis found: loading never analyzes, so run analyze_program first "
            "when the program is not analyzed. Optional categories ({category: value}) are stored in Program Information first, so the record is "
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
            ("significance_threshold", _BSIM_SIGNIFICANCE, 0.0),
            ("matches_per_function", _BSIM_MATCHES_PER_FUNCTION, 5),
            ("max_functions", _BSIM_MAX_APPLY_FUNCTIONS, 500),
            ("only_default_names", bool, True),
            ("exclude_self", bool, True),
            ("min_function_size", _BSIM_MIN_FUNCTION_SIZE, 0),
            ("dry_run", bool, False),
            ("addresses", list[str] | None, None),
            ("function_names", list[str] | None, None),
            _CALL_REQUEST_ID_FIELD,
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
            "Return C-like pseudocode for a function by address or name (address wins if both are set). The first "
            "line is a comment with the function's full name and entry address. Large output is compacted to a "
            "result_id."
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
    _registry_tool(
        "analyze_program",
        method_name="analyze_program",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        output_fields=_SUBMIT_OPERATION_OUTPUT_FIELDS,
        # The job runs the analyze_program core command, so checkout and quarantine checks apply to it.
        checkout_required=True,
        description=(
            "Run Ghidra auto-analysis on the target's program as a background job and return the job record. "
            "The server waits up to wait_seconds for the job; while state is queued or running, call "
            "get_operation with operation_id. An analyzed program is left as is (result.analyzed=false) "
            "unless force=true. Loading never analyzes, so run this when load_project_program or open_program "
            "reports is_analyzed=false. The analysis stays unsaved until save_project_program. While the job "
            "runs, other calls on its project fail with LOCK_TIMEOUT naming details.operation_id. "
            "Takes minutes on large binaries."
        ),
        input_model=AnalyzeProgramInput,
        presenter="operation",
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
            ("clear_all", bool, False),
            ("category", str | None, None),
        ),
        omit_falsey_keys=("category",),
        checkout_required=True,
        description=(
            "Remove members from a structure; members accepts names or {name} objects. "
            "An empty list changes nothing; clear_all=true explicitly removes every member."
        ),
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
_CURSOR_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("limit", _PAGE_LIMIT, 100),
    ("cursor", Annotated[str, Field(max_length=1024)] | None, None),
)
_PAGE_OUTPUT_FIELDS: tuple[ToolFieldSpec, ...] = (
    ("program", str | None, ...),
    ("revision", str, ...),
    ("items", list[dict], ...),
    ("has_more", bool, ...),
    ("next_cursor", str | None, ...),
)
_CONSOLIDATED_SPECS = (
    _core_tool(
        "get_xrefs",
        category_tag=ToolCategoryTag.MEMORY_DATA,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(("address", str, ...), ("direction", Literal["to", "from"], "to"), *_CURSOR_FIELDS),
        output_fields=_PAGE_OUTPUT_FIELDS,
        description="Get references to/from an address, including both endpoints and their functions. Follow next_cursor with unchanged query arguments; editing or reloading invalidates it.",
    ),
    _core_tool(
        "get_call_edges",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("address", str | None, None),
            ("name", str | None, None),
            ("direction", Literal["in", "out"], "out"),
            ("include_tail_calls", bool, True),
            ("include_unresolved", bool, True),
            *_CURSOR_FIELDS,
        ),
        output_fields=_PAGE_OUTPUT_FIELDS,
        description="Get incoming/outgoing call edges for a function selected by address or unique name. Includes call sites, tail calls, thunk transfers and unresolved outgoing calls; excludes data references. Follow next_cursor; a semantic thunk without an instruction reference has call_site=null.",
    ),
    _core_tool(
        "disassemble",
        category_tag=ToolCategoryTag.FUNCTION_ANALYSIS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.BASIC,
        input_fields=(
            ("address", str | None, None),
            ("name", str | None, None),
            ("start_address", str | None, None),
            ("end_address", str | None, None),
            ("length", _POSITIVE_INT | None, None),
            *_CURSOR_FIELDS,
        ),
        output_fields=_PAGE_OUTPUT_FIELDS,
        description="Read existing instructions for a function (address/name) OR range (start_address and exactly one of end_address/length). These selectors are mutually exclusive. Follow next_cursor to continue; this does not create instructions.",
    ),
    _core_tool(
        "get_data_type",
        category_tag=ToolCategoryTag.DATATYPE_OPS,
        safety_tag=ToolSafetyTag.READ_ONLY,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(("path", str, ...), ("include_members", bool, True)),
        description="Describe a data type by full path (preferred) or unique name. Includes struct/union members, enum values or typedef base type; include_members=false returns metadata only.",
    ),
    _core_tool(
        "apply_edits",
        category_tag=ToolCategoryTag.SYMBOL_COMMENT_EDIT,
        safety_tag=ToolSafetyTag.WRITE,
        operation_level=ToolOperationLevel.STANDARD,
        input_fields=(
            ("edits", Edits, ...),
            ("atomic", bool, True),
            ("dry_run", bool, False),
            ("expected_revision", Annotated[str, Field(max_length=128)] | None, None),
        ),
        checkout_required=True,
        description="Apply 1-100 ordered function/data/variable renames, prototypes, types or comments to one target. rename_function requires new_name and/or namespace_path: omitted/null fields keep the current value, an empty namespace_path means Global; create_namespace=true creates missing parents. Namespace-only edits preserve the name and its source. atomic=true rolls everything back on any failure; false retains successful items. dry_run executes then rolls back. Inspect status and each result; results include before/after state. expected_revision (source.revision of the reply the edits are based on, or get_program_info's revision) rejects stale edits; request_id makes a resend return the first reply instead of applying again. Requires a writable program and checkout even for dry_run.",
    ),
)

_TOOL_SPECS: dict[str, ToolSpec] = {spec.name: spec for spec in (*_TOOL_SPEC_LIST, *_CONSOLIDATED_SPECS)}
_TOOL_SPECS["bsim_query"] = _registry_tool(
    "bsim_query",
    method_name="bsim_query",
    category_tag=ToolCategoryTag.BSIM,
    safety_tag=ToolSafetyTag.READ_ONLY,
    operation_level=ToolOperationLevel.STANDARD,
    input_fields=(
        ("scope", Literal["program", "functions"], ...),
        ("bsim_url", str | None, None),
        ("addresses", list[str] | None, None),
        ("function_names", list[str] | None, None),
        ("similarity_threshold", _UNIT_INTERVAL, 0.7),
        ("significance_threshold", _BSIM_SIGNIFICANCE, 0.0),
        ("matches_per_function", _BSIM_MATCHES_PER_FUNCTION, 10),
        ("max_results", _BSIM_MAX_RESULTS, 500),
        ("exclude_self", bool, True),
        ("min_function_size", _BSIM_MIN_FUNCTION_SIZE, 0),
    ),
    description="Search BSim for the loaded program or selected functions. scope=functions requires addresses/function_names (up to 1,000 combined); scope=program excludes selectors. min_function_size applies only to program scope. Results retain query provenance and matched_ref for bsim_load_matched_executable.",
)

_TOOL_SPECS["batch_read"] = _core_tool(
    "batch_read",
    category_tag=ToolCategoryTag.CORE,
    safety_tag=ToolSafetyTag.READ_ONLY,
    operation_level=ToolOperationLevel.STANDARD,
    input_fields=(),
    output_fields=(
        ("program", str | None, ...),
        ("revision", str, ...),
        ("status", Literal["ok", "partial", "error"], ...),
        ("succeeded_count", int, ...),
        ("failed_count", int, ...),
        ("not_run_count", int, ...),
        ("items", list[dict], ...),
    ),
    description=(
        "Read 1-20 independent requests on one target under one lock. Supported tools: get_function, "
        "get_comments, get_data_type, get_xrefs, get_call_edges, decompile_function, disassemble; "
        "each must also be enabled individually. "
        "Use unique short ids and each tool's usual arguments without target. Optional fields select top-level "
        "data keys, or row keys for paged tools (page metadata is preserved); no fields for C strings. "
        "All inputs are validated first; "
        "item query failures continue, revision changes fail the entire batch. Inspect status and all item statuses. "
        "Page limits total at most 2000 rows; at most 5 decompiles, with batch-only item_timeout_seconds "
        "(default 15, 1-60). timeout_seconds (default 10, max 60) starts after locking; heavy reads "
        "cooperatively stop within the remaining time. This is not a hard interrupt. Retained payloads "
        "are limited to 8 MiB; unstarted items report time_budget_exhausted or result_budget_exhausted. "
        "max_output_chars bounds response JSON text "
        "(not the MCP envelope). Large batches use one result_id: read_result(mode='json', path='/items', "
        "offset_items=N) retrieves item N. read_result(mode='text', path='/items/N/data') and search_result "
        "with the same path retrieve/search decoded C text. Inline mode rejects oversized responses."
    ),
    input_model=batch_input_model(_TOOL_SPECS),
    presenter="batch",
)

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
    disabled = set(disable_tools or ())
    selected_names.difference_update(disabled)

    # Background-job tools are useless without the read-only lookup, so a tag
    # filter that keeps them keeps get_operation too. Only an explicit
    # --disable-tool get_operation conflicts with them.
    selected = {name: spec for name, spec in available_specs.items() if name in selected_names}
    if _operation_tools_without_lookup(selected) and "get_operation" in available_specs:
        if "get_operation" in disabled:
            raise ValueError(_operation_lookup_message(selected))
        selected_names.add("get_operation")
    # Their replies point to cancel_operation as well; it stays out only when disabled.
    if _job_tools(selected) and "cancel_operation" in available_specs and "cancel_operation" not in disabled:
        selected_names.add("cancel_operation")
    if "get_operation" not in selected_names:
        # Cancelling is only useful to a client that can read the job record.
        selected_names.discard("cancel_operation")

    return {name: spec for name, spec in available_specs.items() if name in selected_names}


def _job_tools(specs: Mapping[str, ToolSpec]) -> list[str]:
    # The job-record tools follow get_operation instead of requiring it.
    return sorted(
        name for name, spec in specs.items() if spec.presenter == "operation" and name not in OPERATION_CONTROL_TOOLS
    )


def _operation_tools_without_lookup(specs: Mapping[str, ToolSpec]) -> list[str]:
    return [] if "get_operation" in specs else _job_tools(specs)


def _operation_lookup_message(specs: Mapping[str, ToolSpec]) -> str:
    tools = _operation_tools_without_lookup(specs)
    names = ", ".join(tools)
    verb = "reports" if len(tools) == 1 else "report"
    return f"{names} {verb} jobs through get_operation: keep get_operation enabled or also disable {names}"


def validate_tool_selection(specs: Mapping[str, ToolSpec]) -> None:
    """Reject a published tool set whose background-job tools lack get_operation."""
    if _operation_tools_without_lookup(specs):
        raise ValueError(_operation_lookup_message(specs))


__all__ = [
    "CommentKind",
    "ScriptOrigin",
    "ScriptRuntimeName",
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
    "validate_tool_selection",
    "DEFER_AFTER_SECONDS",
    "JOB_TOOLS",
    "OPERATION_CONTROL_TOOLS",
]
