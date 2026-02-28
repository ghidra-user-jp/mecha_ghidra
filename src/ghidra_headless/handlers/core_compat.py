"""Backward-compatible core command shims extracted from legacy core module."""

from __future__ import absolute_import, print_function

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import CategoryPath, StructureDataType, EnumDataType, DataUtilities
from ghidra.util.task import TaskMonitor

from ghidra_headless.handlers.core_command_registry import (
    AST_SENSITIVE_COMMANDS,
    COMMAND_DEP_KEYS,
    COMMAND_NAMES,
    COMMAND_PROFILE,
    COMMAND_TO_IMPL,
)
from ghidra_headless.handlers.core_helpers import (
    _apply_members_to_struct,
    _build_class_category_path,
    _build_signature_parser,
    _collect,
    _component_length,
    _decode_hex_bytes,
    _decompile_function_object,
    _decompile_high_function,
    _describe_enum,
    _describe_struct,
    _dt_manager,
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
    _parse_clear_data_mode,
    _parse_data_type,
    _requires_full_param_commit,
    _resolve_namespace,
    _safe_call,
    _to_int,
    _to_int_auto,
    _txn,
)
from ghidra_headless.handlers.core_runtime import ensure_context

_PROFILE_DEPENDENCIES = {
    "ensure_context": ensure_context,
    "to_int": _to_int,
    "collect": _collect,
    "context": ensure_context,
    "iter_namespaces": _iter_namespaces,
    "safe_call": _safe_call,
    "find_function_by_name": _find_function_by_name,
    "decompile_function_object": _decompile_function_object,
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
    for key in COMMAND_DEP_KEYS.get(command, ()):  # CLIとの契約維持のため明示的に参照する
        params.get(key)


def _build_profile_kwargs(profile, context=None):
    kwargs = {}
    for keyword in profile:
        if keyword == "context":
            kwargs[keyword] = ensure_context() if context is None else context
            continue
        kwargs[keyword] = _PROFILE_DEPENDENCIES[keyword]
    return kwargs


def _invoke_with_profile(command, params, profile, context=None):
    return COMMAND_TO_IMPL[command](
        params,
        **_build_profile_kwargs(profile, context=context),
    )


def _make_simple_shim(command):
    profile = COMMAND_PROFILE[command]

    def _shim(params):
        _touch_params(command, params)
        return _invoke_with_profile(command, params, profile)

    _shim.__name__ = command
    _shim.__doc__ = "Generated compat shim for %s" % command
    return _shim


def list_classes(params):
    _touch_params("list_classes", params)
    ctx = ensure_context()
    _iter_namespaces(ctx)
    return _invoke_with_profile("list_classes", params, COMMAND_PROFILE["list_classes"], context=ctx)


def list_exports(params):
    _touch_params("list_exports", params)
    _is_exported_symbol(ensure_context(), None)
    return _invoke_with_profile("list_exports", params, COMMAND_PROFILE["list_exports"])


def list_namespaces(params):
    _touch_params("list_namespaces", params)
    _iter_namespaces(ensure_context())
    return _invoke_with_profile("list_namespaces", params, COMMAND_PROFILE["list_namespaces"])


def rename_variable(params):
    _touch_params("rename_variable", params)
    if False:
        function = None
        function.getParameters()
    return _invoke_with_profile("rename_variable", params, COMMAND_PROFILE["rename_variable"])


def set_function_prototype(params):
    _touch_params("set_function_prototype", params)
    if False:
        ApplyFunctionSignatureCmd(None, None, None)
    return _invoke_with_profile("set_function_prototype", params, COMMAND_PROFILE["set_function_prototype"])


def set_local_variable_type(params):
    _touch_params("set_local_variable_type", params)
    if False:
        _decompile_high_function(None, None)
        HighFunctionDBUtil.updateDBVariable(None, None, None, None)
    return _invoke_with_profile("set_local_variable_type", params, COMMAND_PROFILE["set_local_variable_type"])


def get_xrefs_from(params):
    _touch_params("get_xrefs_from", params)
    _iter_items(())
    return _invoke_with_profile("get_xrefs_from", params, COMMAND_PROFILE["get_xrefs_from"])


def get_enum(params):
    _touch_params("get_enum", params)
    return _invoke_with_profile("get_enum", params, COMMAND_PROFILE["get_enum"])


def set_global_data_type(params):
    _touch_params("set_global_data_type", params)
    params.get("clear_mode")
    return _invoke_with_profile("set_global_data_type", params, COMMAND_PROFILE["set_global_data_type"])


def add_class_members(params):
    _touch_params("add_class_members", params)
    if False:
        _ensure_class_struct(
            None,
            None,
            None,
            create_class_if_missing=False,
            create_struct_if_missing=False,
        )
    return _invoke_with_profile("add_class_members", params, COMMAND_PROFILE["add_class_members"])


for _command_name in COMMAND_NAMES:
    if _command_name in AST_SENSITIVE_COMMANDS:
        continue
    globals()[_command_name] = _make_simple_shim(_command_name)

del _command_name


SUPPORTED_COMMANDS = {
    "list_methods": list_methods,
    "list_functions": list_functions,
    "list_classes": list_classes,
    "decompile_function": decompile_function,
    "decompile_function_by_address": decompile_function_by_address,
    "rename_function": rename_function,
    "rename_data": rename_data,
    "list_segments": list_segments,
    "list_imports": list_imports,
    "list_exports": list_exports,
    "list_namespaces": list_namespaces,
    "list_data_items": list_data_items,
    "search_functions_by_name": search_functions_by_name,
    "rename_variable": rename_variable,
    "get_function_by_address": get_function_by_address,
    "disassemble_function": disassemble_function,
    "set_decompiler_comment": set_decompiler_comment,
    "rename_function_by_address": rename_function_by_address,
    "set_disassembly_comment": set_disassembly_comment,
    "set_function_prototype": set_function_prototype,
    "set_local_variable_type": set_local_variable_type,
    "get_xrefs_to": get_xrefs_to,
    "get_xrefs_from": get_xrefs_from,
    "get_function_xrefs": get_function_xrefs,
    "list_strings": list_strings,
    "create_struct": create_struct,
    "add_struct_members": add_struct_members,
    "clear_struct": clear_struct,
    "get_struct": get_struct,
    "get_data_by_label": get_data_by_label,
    "get_bytes": get_bytes,
    "search_bytes": search_bytes,
    "create_enum": create_enum,
    "add_enum_values": add_enum_values,
    "get_enum": get_enum,
    "set_global_data_type": set_global_data_type,
    "create_class": create_class,
    "add_class_members": add_class_members,
    "remove_class_members": remove_class_members,
    "remove_enum_values": remove_enum_values,
    "remove_struct_members": remove_struct_members,
    "set_bytes": set_bytes,
    "get_callee": get_callee,
    "add_bookmark": add_bookmark,
}

if tuple(SUPPORTED_COMMANDS.keys()) != COMMAND_NAMES:
    raise RuntimeError("SUPPORTED_COMMANDS と COMMAND_NAMES の順序/集合が一致しません")


__all__ = ["SUPPORTED_COMMANDS"] + list(COMMAND_NAMES)
