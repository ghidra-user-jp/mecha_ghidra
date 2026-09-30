"""Thin facade for headless handlers with backward-compatible public entrypoints."""

from __future__ import absolute_import, print_function

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import CategoryPath, DataUtilities, EnumDataType, StructureDataType
from ghidra.program.model.listing import CommentType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

from ghidra_headless.handlers.commands.query_support import program_metadata
from ghidra_headless.handlers.core_command_registry import (
    COMMAND_NAMES,
    COMMAND_PROFILE,
    COMMAND_TO_IMPL,
)
from ghidra_headless.handlers.core_helpers import (
    _analyze_program,
    _build_signature_parser,
    _collect,
    _component_length,
    _decode_hex_bytes,
    _decompile_function_object,
    _decompile_high_function,
    _describe_data_type,
    _describe_enum,
    _describe_struct,
    _dt_manager,
    _find_data_type_by_name,
    _find_function_by_name,
    _get_address,
    _get_enum_datatype,
    _get_struct_datatype,
    _hexdump,
    _is_exported_symbol,
    _iter_items,
    _iter_namespaces,
    _json_safe,
    _parse_clear_data_mode,
    _parse_data_type,
    _requires_full_param_commit,
    _safe_call,
    _to_int,
    _txn,
)
from ghidra_headless.handlers.core_runtime import (
    _THREAD_STATE,
    _ensure_context_for_key,
    begin_command,
    bind_project,
    clear_contexts,
    current_task_monitor,
    describe_state,
    ensure_context,
    execution_state,
    initialize,
    remove_context,
)
from ghidra_headless.session.transactions import UNCHANGED, recorded_transactions


def _execute_nested_command(command, params, *, budget=None):
    # Bounded edit/read handlers validate commands before entering this path;
    # the outer core call already holds the target/project locks.
    if budget is not None:
        return SUPPORTED_COMMANDS[command](params, budget=budget)
    return SUPPORTED_COMMANDS[command](params)


_PROFILE_DEPENDENCIES = {
    "execute_read": _execute_nested_command,
    "execute_edit": _execute_nested_command,
    "ensure_context": ensure_context,
    "to_int": _to_int,
    "collect": _collect,
    "iter_namespaces": _iter_namespaces,
    "safe_call": _safe_call,
    "find_function_by_name": _find_function_by_name,
    "decompile_function_object": _decompile_function_object,
    "analyze_program_impl": _analyze_program,
    "current_task_monitor": current_task_monitor,
    "begin_command": begin_command,
    "get_address": _get_address,
    "txn": _txn,
    "source_type": SourceType,
    "iter_items": _iter_items,
    "is_exported_symbol": _is_exported_symbol,
    "decompile_high_function": _decompile_high_function,
    "requires_full_param_commit": _requires_full_param_commit,
    "high_function_db_util": HighFunctionDBUtil,
    "comment_types": CommentType,
    "build_signature_parser": _build_signature_parser,
    "apply_function_signature_cmd": ApplyFunctionSignatureCmd,
    "parse_data_type": _parse_data_type,
    "dt_manager": _dt_manager,
    "find_data_type_by_name": _find_data_type_by_name,
    "describe_data_type": _describe_data_type,
    "category_path": CategoryPath,
    "structure_data_type": StructureDataType,
    "enum_data_type": EnumDataType,
    "component_length": _component_length,
    "describe_struct": _describe_struct,
    "get_struct_datatype": _get_struct_datatype,
    "hexdump": _hexdump,
    "decode_hex_bytes": _decode_hex_bytes,
    "get_enum_datatype": _get_enum_datatype,
    "describe_enum": _describe_enum,
    "parse_clear_data_mode": _parse_clear_data_mode,
    "data_utilities": DataUtilities,
    "task_monitor": TaskMonitor,
    "current_key": lambda: getattr(_THREAD_STATE, "current_key", None),
}


def _build_profile_kwargs(profile):
    kwargs = {}
    for keyword in profile:
        if keyword == "context":
            kwargs[keyword] = ensure_context()
            continue
        try:
            kwargs[keyword] = _PROFILE_DEPENDENCIES[keyword]
        except KeyError:
            raise RuntimeError("Unknown dependency profile key: %s" % keyword)
    return kwargs


def _make_handler(command):
    impl = COMMAND_TO_IMPL[command]
    profile = COMMAND_PROFILE[command]

    def _handler(params, *, budget=None):
        kwargs = _build_profile_kwargs(profile)
        if budget is not None:
            kwargs["budget"] = budget
        return impl(params or {}, **kwargs)

    _handler.__name__ = command
    _handler.__doc__ = "Generated core handler for %s" % command
    return _handler


SUPPORTED_COMMANDS = {command: _make_handler(command) for command in COMMAND_NAMES}

if tuple(SUPPORTED_COMMANDS.keys()) != COMMAND_NAMES:
    raise RuntimeError("SUPPORTED_COMMANDS and COMMAND_NAMES order/membership mismatch")


def execute(command, params, key="default", *, task_monitor=None, on_begin=None, record_transactions=False):
    """Run ``command`` against the context for ``key``.

    ``task_monitor`` lets a background job cancel the command; handlers that
    can be cancelled receive it through the ``current_task_monitor`` profile key.
    ``on_begin`` is the job's hook for the moment the command starts changing
    the program, which the handler signals through ``begin_command``.
    ``record_transactions`` notes the transactions the command starts, for
    ``transaction_outcome``; the runtime asks for it for program writes.
    """
    # A command refused below changed nothing, and produced no result.
    _THREAD_STATE.transaction_outcome = UNCHANGED
    _THREAD_STATE.transaction_record = None
    _THREAD_STATE.command_source = None
    handler = SUPPORTED_COMMANDS.get(command)
    if handler is None:
        raise KeyError("Unsupported command: %s" % command)
    context = _ensure_context_for_key(key)
    previous = getattr(_THREAD_STATE, "current_key", None)
    previous_monitor = getattr(_THREAD_STATE, "task_monitor", None)
    previous_begin = getattr(_THREAD_STATE, "on_begin", None)
    _THREAD_STATE.current_key = key
    _THREAD_STATE.task_monitor = task_monitor
    _THREAD_STATE.on_begin = on_begin
    try:
        if record_transactions:
            with recorded_transactions(context.program) as record:
                # Read only if the command fails: the outcome costs Java calls.
                _THREAD_STATE.transaction_record = record
                result = _json_safe(handler(params or {}))
        else:
            _THREAD_STATE.transaction_outcome = None
            result = _json_safe(handler(params or {}))
        # Read while the runtime still holds the target's locks, so no other
        # command can come between the result and the revision it names.
        _THREAD_STATE.command_source = _source_of(context)
        return result
    finally:
        _THREAD_STATE.task_monitor = previous_monitor
        _THREAD_STATE.on_begin = previous_begin
        if previous is None:
            if hasattr(_THREAD_STATE, "current_key"):
                delattr(_THREAD_STATE, "current_key")
        else:
            _THREAD_STATE.current_key = previous


def _source_of(context):
    try:
        return program_metadata(context)
    except Exception:
        return None


def command_source():
    """The program and revision the last command ``execute`` ran on this thread left, or None.

    ``{"program": domain path, "revision": ...}``, taken right after the
    command; the revision is the one ``expected_revision`` compares against.
    None when the command failed.
    """
    return getattr(_THREAD_STATE, "command_source", None)


def transaction_outcome():
    """How the transactions of the last command ``execute`` ran on this thread ended.

    ``unchanged``, ``committed``, ``rolled_back`` or ``unknown`` (see
    ``ghidra_headless.session.transactions``); None before any command, and
    for a command run without ``record_transactions``.  The runtime reads it
    when a write fails, to say what the failure left behind.
    """
    record = getattr(_THREAD_STATE, "transaction_record", None)
    if record is not None:
        _THREAD_STATE.transaction_outcome = record.outcome()
        _THREAD_STATE.transaction_record = None
    return getattr(_THREAD_STATE, "transaction_outcome", None)


def begins_itself(command):
    """Whether ``command`` marks the moment it starts changing the program (``begin_command``) itself."""
    return "begin_command" in COMMAND_PROFILE.get(command, ())


HANDLERS = {
    "initialize": initialize,
    "execute": execute,
    "transaction_outcome": transaction_outcome,
    "begins_itself": begins_itself,
    "command_source": command_source,
    "describe_state": describe_state,
    "execution_state": execution_state,
    "bind_project": bind_project,
    "remove_context": remove_context,
    "clear_contexts": clear_contexts,
}


__all__ = [
    "SUPPORTED_COMMANDS",
    "initialize",
    "remove_context",
    "clear_contexts",
    "execute",
    "transaction_outcome",
    "begins_itself",
    "command_source",
    "describe_state",
    "execution_state",
    "bind_project",
    "HANDLERS",
]
