"""Thin facade for headless handlers with backward-compatible public entrypoints."""

from __future__ import absolute_import, print_function

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import CategoryPath, DataUtilities, EnumDataType, StructureDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

from ghidra_headless.handlers.core_command_registry import (
    COMMAND_DEP_KEYS,
    COMMAND_NAMES,
    COMMAND_PROFILE,
    COMMAND_TO_IMPL,
)
from ghidra_headless.handlers.core_helpers import (
    _apply_members_to_struct,
    _analyze_program,
    _build_class_category_path,
    _build_signature_parser,
    _collect,
    _component_length,
    _decode_hex_bytes,
    _decompile_function_object,
    _decompile_high_function,
    _describe_enum,
    _describe_data_type,
    _describe_struct,
    _dt_manager,
    _find_data_type_by_name,
    _ensure_class_struct,
    _find_function_by_name,
    _find_ghidra_class,
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
    _resolve_namespace,
    _safe_call,
    _to_int,
    _to_int_auto,
    _txn,
)
from ghidra_headless.handlers.core_runtime import (
    _THREAD_STATE,
    _ensure_context_for_key,
    clear_contexts,
    describe_state,
    ensure_context,
    initialize,
    remove_context,
)

_PROFILE_DEPENDENCIES = {
    "ensure_context": ensure_context,
    "to_int": _to_int,
    "collect": _collect,
    "iter_namespaces": _iter_namespaces,
    "safe_call": _safe_call,
    "find_function_by_name": _find_function_by_name,
    "decompile_function_object": _decompile_function_object,
    "analyze_program_impl": _analyze_program,
    "get_address": _get_address,
    "txn": _txn,
    "source_type": SourceType,
    "iter_items": _iter_items,
    "is_exported_symbol": _is_exported_symbol,
    "decompile_high_function": _decompile_high_function,
    "requires_full_param_commit": _requires_full_param_commit,
    "high_function_db_util": HighFunctionDBUtil,
    "code_unit": CodeUnit,
    "build_signature_parser": _build_signature_parser,
    "apply_function_signature_cmd": ApplyFunctionSignatureCmd,
    "parse_data_type": _parse_data_type,
    "dt_manager": _dt_manager,
    "find_data_type_by_name": _find_data_type_by_name,
    "describe_data_type": _describe_data_type,
    "category_path": CategoryPath,
    "structure_data_type": StructureDataType,
    "component_length": _component_length,
    "describe_struct": _describe_struct,
    "get_struct_datatype": _get_struct_datatype,
    "hexdump": _hexdump,
    "decode_hex_bytes": _decode_hex_bytes,
    "enum_data_type": EnumDataType,
    "to_int_auto": _to_int_auto,
    "get_enum_datatype": _get_enum_datatype,
    "describe_enum": _describe_enum,
    "parse_clear_data_mode": _parse_clear_data_mode,
    "data_utilities": DataUtilities,
    "resolve_namespace": _resolve_namespace,
    "find_ghidra_class": _find_ghidra_class,
    "build_class_category_path": _build_class_category_path,
    "apply_members_to_struct": _apply_members_to_struct,
    "ensure_class_struct": _ensure_class_struct,
    "task_monitor": TaskMonitor,
}


def _touch_params(command, params):
    for key in COMMAND_DEP_KEYS.get(command, ()):
        params.get(key)


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

    def _handler(params):
        normalized_params = params or {}
        _touch_params(command, normalized_params)
        return impl(normalized_params, **_build_profile_kwargs(profile))

    _handler.__name__ = command
    _handler.__doc__ = "Generated core handler for %s" % command
    return _handler


SUPPORTED_COMMANDS = {command: _make_handler(command) for command in COMMAND_NAMES}

if tuple(SUPPORTED_COMMANDS.keys()) != COMMAND_NAMES:
    raise RuntimeError("SUPPORTED_COMMANDS and COMMAND_NAMES order/membership mismatch")


def execute(command, params, key="default"):
    handler = SUPPORTED_COMMANDS.get(command)
    if handler is None:
        raise KeyError("Unsupported command: %s" % command)
    _ensure_context_for_key(key)
    previous = getattr(_THREAD_STATE, "current_key", None)
    _THREAD_STATE.current_key = key
    try:
        return _json_safe(handler(params or {}))
    finally:
        if previous is None:
            if hasattr(_THREAD_STATE, "current_key"):
                delattr(_THREAD_STATE, "current_key")
        else:
            _THREAD_STATE.current_key = previous


HANDLERS = {
    "initialize": initialize,
    "execute": execute,
    "describe_state": describe_state,
    "remove_context": remove_context,
    "clear_contexts": clear_contexts,
}


__all__ = [
    "SUPPORTED_COMMANDS",
    "initialize",
    "remove_context",
    "clear_contexts",
    "execute",
    "describe_state",
    "HANDLERS",
]
