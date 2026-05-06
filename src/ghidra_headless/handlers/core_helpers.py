"""Core helper functions extracted from legacy core handler."""

from __future__ import absolute_import, print_function

import os
from numbers import Integral

import jpype

from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath,
    StructureDataType,
    DataUtilities,
    VoidDataType,
    CharDataType,
    UnsignedCharDataType,
    ShortDataType,
    UnsignedShortDataType,
    IntegerDataType,
    UnsignedIntegerDataType,
    LongLongDataType,
    UnsignedLongLongDataType,
    FloatDataType,
    DoubleDataType,
    BooleanDataType,
    StringDataType,
    UnicodeDataType,
)
from ghidra_mcp.ghidra_installation import validate_linux_arm64_decompiler_install

_GHIDRA_PROGRAM_UTILITIES = None
_GHIDRA_SCRIPT_UTIL = None

def _to_int(value, default):
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _to_int_auto(value):
    if value is None:
        raise ValueError("Numeric value is required")
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _txn(ctx, description, func):
    _ensure_checkout_for_versioned_program(ctx)
    tx_id = ctx.program.startTransaction(description)
    success = False
    try:
        result = func()
        success = True
        return result
    finally:
        ctx.program.endTransaction(tx_id, success)


def _safe_call(obj, name, *args):
    method = getattr(obj, name, None)
    if method is None:
        return None
    try:
        return method(*args)
    except Exception:
        return None


def _required_domain_file_call(domain_file, name):
    method = getattr(domain_file, name, None)
    if method is None:
        raise RuntimeError("SYNC_STATUS_UNAVAILABLE: DomainFile.%s is unavailable" % name)
    try:
        return method()
    except Exception as exc:
        raise RuntimeError("SYNC_STATUS_UNAVAILABLE: failed to call DomainFile.%s: %s" % (name, exc)) from exc


def _iter_items(items):
    if items is None:
        return

    has_next = getattr(items, "hasNext", None)
    next_item = getattr(items, "next", None)
    if callable(has_next) and callable(next_item):
        while bool(has_next()):
            yield next_item()
        return

    iterator_fn = getattr(items, "iterator", None)
    if callable(iterator_fn):
        iterator = _safe_call(items, "iterator")
        if iterator is not None:
            for item in _iter_items(iterator):
                yield item
            return

    try:
        for item in items:
            yield item
        return
    except Exception:
        pass

    if callable(next_item):
        while True:
            try:
                yield next_item()
            except Exception:
                break


def _json_safe(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]

    has_next = getattr(value, "hasNext", None)
    next_item = getattr(value, "next", None)
    if callable(has_next) and callable(next_item):
        return [_json_safe(v) for v in _iter_items(value)]

    iterator_fn = getattr(value, "iterator", None)
    if callable(iterator_fn):
        return [_json_safe(v) for v in _iter_items(value)]

    return str(value)


def _namespace_key(namespace):
    namespace_id = _safe_call(namespace, "getID")
    if namespace_id is not None:
        return "id:%s" % namespace_id
    full_name = _safe_call(namespace, "getName", True)
    if full_name:
        return "name:%s" % full_name
    return "repr:%s" % namespace


def _iter_symbol_table_symbols(symbol_table):
    probes = [
        ("getAllSymbols", (True,)),
        ("getAllSymbols", ()),
        ("getSymbolIterator", (True,)),
        ("getSymbolIterator", ()),
    ]
    for method_name, args in probes:
        symbols = _safe_call(symbol_table, method_name, *args)
        if symbols is None:
            continue
        for symbol in _iter_items(symbols):
            yield symbol
        return


def _iter_namespaces(ctx):
    manager = getattr(ctx, "namespace_manager", None)
    if manager is not None:
        for args in ((True,), ()):
            namespaces = _safe_call(manager, "getNamespaces", *args)
            if namespaces is None:
                continue
            for namespace in _iter_items(namespaces):
                yield namespace
            return

    seen = set()
    for symbol in _iter_symbol_table_symbols(ctx.symbol_table):
        parent = _safe_call(symbol, "getParentNamespace")
        if parent is not None and not bool(_safe_call(parent, "isGlobal")):
            key = _namespace_key(parent)
            if key not in seen:
                seen.add(key)
                yield parent

        symbol_type = _safe_call(symbol, "getSymbolType")
        if symbol_type is None or str(symbol_type).upper() != "CLASS":
            continue
        class_namespace = _safe_call(symbol, "getObject")
        if class_namespace is None or bool(_safe_call(class_namespace, "isGlobal")):
            continue
        class_key = _namespace_key(class_namespace)
        if class_key in seen:
            continue
        seen.add(class_key)
        yield class_namespace


def _is_exported_symbol(ctx, symbol):
    if symbol is None:
        return False

    exported = _safe_call(symbol, "isExported")
    if exported is not None:
        return bool(exported)

    exported = _safe_call(symbol, "isExternalEntryPoint")
    if exported is not None:
        return bool(exported)

    address = _safe_call(symbol, "getAddress")
    if address is not None:
        exported = _safe_call(ctx.symbol_table, "isExternalEntryPoint", address)
        if exported is not None:
            return bool(exported)
    return False


def _ensure_checkout_for_versioned_program(ctx):
    program = getattr(ctx, "program", None)
    if program is None:
        return
    try:
        domain_file = program.getDomainFile()
    except Exception as exc:
        raise RuntimeError("SYNC_STATUS_UNAVAILABLE: failed to resolve DomainFile: %s" % exc)
    if domain_file is None:
        return

    is_versioned = _required_domain_file_call(domain_file, "isVersioned")
    if not bool(is_versioned):
        return
    is_checked_out = _required_domain_file_call(domain_file, "isCheckedOut")
    if bool(is_checked_out):
        return
    raise RuntimeError(
        "CHECKOUT_REQUIRED: checkout is required for mutating operations on shared projects. "
        "Run checkout_project_program first"
    )


def _find_function_by_name(ctx, name):
    iterator = ctx.function_manager.getFunctions(True)
    first_match = None
    while iterator.hasNext():
        function = iterator.next()
        if function.getName() != name:
            continue
        if first_match is None:
            first_match = function
        body = function.getBody()
        if body is not None and not body.isEmpty():
            return function
    return first_match


def _get_address(ctx, address_text):
    if not address_text:
        raise ValueError("address is empty")
    address = ctx.address_factory.getAddress(address_text)
    if address is None:
        raise ValueError("Invalid address: %s" % address_text)
    return address


def _collect(iterator, offset, limit, to_value):
    if limit <= 0:
        return []
    if offset < 0:
        offset = 0
    result = []
    idx = 0
    for item in _iter_items(iterator):
        if idx >= offset:
            result.append(to_value(item))
            if len(result) >= limit:
                break
        idx += 1
    return result


def _dt_manager(ctx):
    return ctx.program.getDataTypeManager()


def _find_data_type_by_name(dtm, type_name):
    if not type_name:
        return None

    query = str(type_name).strip()
    if not query:
        return None
    query_lower = query.lower()
    query_compact = query_lower.replace(" ", "")
    candidate = None

    iterator = _safe_call(dtm, "getAllDataTypes")
    if iterator is not None:
        while iterator.hasNext():
            data_type = iterator.next()
            names = [
                _safe_call(data_type, "getName"),
                _safe_call(data_type, "getDisplayName"),
                _safe_call(data_type, "getPathName"),
                _safe_call(data_type, "getName", True),
            ]
            for name in names:
                if not name:
                    continue
                text = str(name)
                text_lower = text.lower()
                if text == query:
                    return data_type
                if text_lower == query_lower and candidate is None:
                    candidate = data_type
                if text_lower.replace(" ", "") == query_compact and candidate is None:
                    candidate = data_type
                if text.endswith("/" + query) and candidate is None:
                    candidate = data_type
                if text_lower.endswith("/" + query_lower) and candidate is None:
                    candidate = data_type

    if candidate is not None:
        return candidate

    for probe in (query, "/" + query):
        resolved = _safe_call(dtm, "getDataType", probe)
        if resolved is not None:
            return resolved

    return None


def _parse_clear_data_mode(clear_mode_text):
    clear_data_mode = DataUtilities.ClearDataMode
    mapping = {
        "CHECK_FOR_SPACE": clear_data_mode.CHECK_FOR_SPACE,
        "CLEAR_SINGLE_DATA": clear_data_mode.CLEAR_SINGLE_DATA,
        "CLEAR_ALL_UNDEFINED_CONFLICT_DATA": clear_data_mode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
        "CLEAR_ALL_DEFAULT_CONFLICT_DATA": clear_data_mode.CLEAR_ALL_DEFAULT_CONFLICT_DATA,
        "CLEAR_ALL_CONFLICT_DATA": clear_data_mode.CLEAR_ALL_CONFLICT_DATA,
    }
    if not clear_mode_text:
        return mapping["CHECK_FOR_SPACE"]
    normalized = str(clear_mode_text).strip().upper()
    mode = mapping.get(normalized)
    if mode is None:
        allowed = ", ".join(sorted(mapping.keys()))
        raise ValueError("Invalid clear_mode: %s (allowed: %s)" % (clear_mode_text, allowed))
    return mode


def _parse_data_type(ctx, type_str):
    if not type_str:
        raise ValueError("data_type is required")

    dtm = _dt_manager(ctx)
    text = type_str.strip()
    for needle in ("\t", "\n", "\r"):
        text = text.replace(needle, " ")
    text = " ".join(text.split())
    text = " ".join([token for token in text.split(" ") if token.lower() not in {"const", "volatile"}])

    pointer_depth = 0
    while text.endswith("*"):
        pointer_depth += 1
        text = text[:-1].strip()

    builtin = {
        "void": VoidDataType.dataType,
        "char": CharDataType.dataType,
        "signed char": CharDataType.dataType,
        "uchar": UnsignedCharDataType.dataType,
        "unsigned char": UnsignedCharDataType.dataType,
        "short": ShortDataType.dataType,
        "unsigned short": UnsignedShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "unsigned": UnsignedIntegerDataType.dataType,
        "unsigned int": UnsignedIntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "long long": LongLongDataType.dataType,
        "unsigned long long": UnsignedLongLongDataType.dataType,
        "ull": UnsignedLongLongDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "bool": BooleanDataType.dataType,
        "boolean": BooleanDataType.dataType,
        "string": StringDataType.dataType,
        "unicode": UnicodeDataType.dataType,
    }

    pointer_alias = {
        "pvoid": "void",
        "lpvoid": "void",
        "lpcstr": "char",
        "pcstr": "char",
        "lpstr": "char",
        "lpwstr": "unicode",
        "lpcwstr": "unicode",
        "pwstr": "unicode",
    }

    lowered = text.lower()
    dt = None
    if lowered in builtin:
        dt = builtin[lowered]
    elif lowered in pointer_alias:
        dt = builtin[pointer_alias[lowered]]
        pointer_depth += 1
    else:
        dt = _find_data_type_by_name(dtm, text)
    if dt is None:
        raise ValueError("unknown data type: %s" % type_str)

    for _ in range(pointer_depth):
        dt = dtm.getPointer(dt)
    return dt


def _new_java_byte_buffer(size):
    try:
        return jpype.JArray(jpype.JByte)(size)
    except Exception:
        return bytearray(size)


def _hexdump(memory, start_address, size):
    buffer = _new_java_byte_buffer(size)
    read = memory.getBytes(start_address, buffer)
    if read < 0:
        raise RuntimeError("Failed to read memory")
    lines = []
    base = start_address
    for idx in range(0, read, 16):
        chunk = [int(buffer[i]) & 0xFF for i in range(idx, min(idx + 16, read))]
        hex_part = " ".join(["%02X" % b for b in chunk])
        lines.append("%s  %s" % (base.add(idx), hex_part))
    return "\n".join(lines)


def _ghidra_program_utilities():
    global _GHIDRA_PROGRAM_UTILITIES
    if _GHIDRA_PROGRAM_UTILITIES is None:
        from ghidra.program.util import GhidraProgramUtilities
        _GHIDRA_PROGRAM_UTILITIES = GhidraProgramUtilities
    return _GHIDRA_PROGRAM_UTILITIES


def _ghidra_script_util():
    global _GHIDRA_SCRIPT_UTIL
    if _GHIDRA_SCRIPT_UTIL is None:
        from ghidra.app.script import GhidraScriptUtil
        _GHIDRA_SCRIPT_UTIL = GhidraScriptUtil
    return _GHIDRA_SCRIPT_UTIL


def _analyze_program_if_needed(ctx):
    utilities = _ghidra_program_utilities()
    if not utilities.shouldAskToAnalyze(ctx.program):
        return False
    script_util = _ghidra_script_util()
    script_util.acquireBundleHostReference()
    try:
        ctx.flat_api.analyzeAll(ctx.program)
        utilities.markProgramAnalyzed(ctx.program)
    finally:
        script_util.releaseBundleHostReference()
    return True


def _decompile_function_object(ctx, function):
    def _run_decompile():
        interface = DecompInterface()
        try:
            if not interface.openProgram(ctx.program):
                ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
                try:
                    validate_linux_arm64_decompiler_install(ghidra_install_dir)
                except RuntimeError as exc:
                    raise RuntimeError(str(exc))
                raise RuntimeError("Failed to initialize decompiler")
            results = interface.decompileFunction(function, 120, ctx.monitor())
            if results is None:
                raise RuntimeError("Decompilation failed")
            decompiled = results.getDecompiledFunction()
            if decompiled is not None:
                return decompiled.getC()
            detail = (results.getErrorMessage() or "").strip()
            if detail:
                raise RuntimeError("Decompilation result is empty: %s" % detail)
            raise RuntimeError("Decompilation result is empty")
        finally:
            interface.dispose()

    return _run_decompile()


def _decompile_high_function(ctx, function):
    def _run_decompile():
        interface = DecompInterface()
        try:
            if not interface.openProgram(ctx.program):
                ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
                try:
                    validate_linux_arm64_decompiler_install(ghidra_install_dir)
                except RuntimeError as exc:
                    raise RuntimeError(str(exc))
                raise RuntimeError("Failed to initialize decompiler")
            results = interface.decompileFunction(function, 120, ctx.monitor())
            if results is None:
                raise RuntimeError("Decompilation failed")
            if not results.decompileCompleted():
                detail = (results.getErrorMessage() or "").strip()
                if detail:
                    raise RuntimeError("Decompilation failed: %s" % detail)
                raise RuntimeError("Decompilation failed")
            high_function = results.getHighFunction()
            if high_function is None:
                raise RuntimeError("Failed to obtain high-level function info")
            return high_function
        finally:
            interface.dispose()

    try:
        return _run_decompile()
    except RuntimeError:
        _ensure_checkout_for_versioned_program(ctx)
        analyzed = False
        try:
            analyzed = _analyze_program_if_needed(ctx)
        except Exception:
            analyzed = False
        if not analyzed:
            raise
        return _run_decompile()


def _requires_full_param_commit(high_symbol, high_function):
    try:
        if high_symbol is not None and not bool(high_symbol.isParameter()):
            return False
        function = high_function.getFunction()
        params = function.getParameters()
        local_symbol_map = high_function.getLocalSymbolMap()
        num_params = int(local_symbol_map.getNumParams())
        if num_params != len(params):
            return True
        for index in range(num_params):
            param_symbol = local_symbol_map.getParamSymbol(index)
            if param_symbol is None:
                return True
            if int(param_symbol.getCategoryIndex()) != index:
                return True
            storage = param_symbol.getStorage()
            if storage is None:
                return True
            if int(storage.compareTo(params[index].getVariableStorage())) != 0:
                return True
        return False
    except Exception:
        return True


def _build_signature_parser(ctx):
    data_type_manager = ctx.program.getDataTypeManager()
    try:
        return FunctionSignatureParser(data_type_manager, None)
    except TypeError:
        # Some environments only provide the single-argument signature.
        return FunctionSignatureParser(data_type_manager)


def _decode_hex_bytes(hex_string):
    cleaned = "".join(hex_string.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("Invalid bytes length")
    try:
        return bytearray.fromhex(cleaned)
    except Exception:
        raise ValueError("bytes must be hexadecimal")


def _get_struct_datatype(ctx, name, category):
    dtm = _dt_manager(ctx)
    cp = CategoryPath(category) if category else CategoryPath("/")
    return dtm.getDataType(cp, name)


def _resolve_namespace(ctx, namespace_path):
    global_namespace = ctx.program.getGlobalNamespace()
    if not namespace_path:
        return global_namespace

    normalized = str(namespace_path).replace("/", "::")
    parts = [part for part in normalized.split("::") if part]
    current = global_namespace
    for part in parts:
        found = ctx.symbol_table.getNamespace(part, current)
        if found is None:
            return None
        current = found
    return current


def _find_ghidra_class(ctx, class_name, parent_namespace):
    symbols = ctx.symbol_table.getSymbols(class_name, parent_namespace)
    for symbol in _iter_items(symbols):
        symbol_type = _safe_call(symbol, "getSymbolType")
        if symbol_type is None or str(symbol_type).upper() != "CLASS":
            continue
        class_namespace = _safe_call(symbol, "getObject")
        if class_namespace is not None:
            return class_namespace
    return None


def _build_class_category_path(class_namespace):
    parts = []
    current = class_namespace
    while current is not None and not bool(current.isGlobal()):
        parts.insert(0, current.getName())
        current = current.getParentNamespace()
    if not parts:
        return "/classes"
    return "/classes/" + "/".join(parts)


def _ensure_class_struct(
    ctx,
    class_name,
    parent_namespace,
    create_class_if_missing=False,
    create_struct_if_missing=False,
):
    parent = _resolve_namespace(ctx, parent_namespace)
    if parent is None:
        raise LookupError("Parent namespace not found: %s" % parent_namespace)

    class_namespace = _find_ghidra_class(ctx, class_name, parent)
    if class_namespace is None:
        if not create_class_if_missing:
            raise LookupError("Class not found: %s" % class_name)
        class_namespace = ctx.symbol_table.createClass(parent, class_name, SourceType.USER_DEFINED)

    category = _build_class_category_path(class_namespace)
    struct = _get_struct_datatype(ctx, class_name, category)
    if struct is None:
        if not create_struct_if_missing:
            raise LookupError("Class struct not found: %s" % class_name)
        struct = StructureDataType(CategoryPath(category), class_name, 0)
        struct = _dt_manager(ctx).addDataType(struct, None)
    return class_namespace, struct


def _apply_members_to_struct(ctx, struct, members):
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("Each members entry must be an object")
        data_type = _parse_data_type(ctx, member.get("type"))
        field_name = member.get("name", "")
        comment = member.get("comment", "")
        offset = member.get("offset")
        length = _component_length(data_type)
        if offset is not None:
            struct.replaceAtOffset(int(offset), data_type, length, field_name, comment)
        else:
            struct.add(data_type, length, field_name, comment)


def _get_enum_datatype(ctx, name, category):
    dtm = _dt_manager(ctx)
    cp = CategoryPath(category) if category else CategoryPath("/")
    return dtm.getDataType(cp, name)


def _describe_struct(struct_dt):
    members = []
    for component in struct_dt.getComponents():
        members.append({
            "offset": component.getOffset(),
            "length": component.getLength(),
            "name": component.getFieldName() or "",
            "type": component.getDataType().getDisplayName(),
            "comment": component.getComment() or "",
        })
    category = struct_dt.getCategoryPath()
    return {
        "name": struct_dt.getName(),
        "category": category.getPath() if category else "/",
        "length": struct_dt.getLength(),
        "members": members,
    }


def _describe_enum(enum_dt):
    values = []
    for name in enum_dt.getNames():
        values.append({
            "name": name,
            "value": int(enum_dt.getValue(name)),
            "comment": enum_dt.getComment(name) or "",
        })
    category = enum_dt.getCategoryPath()
    return {
        "name": enum_dt.getName(),
        "category": category.getPath() if category else "/",
        "size": enum_dt.getLength(),
        "count": enum_dt.getCount(),
        "values": values,
        "isSigned": bool(enum_dt.isSigned()),
    }


def _component_length(data_type):
    length = data_type.getLength()
    return length if length > 0 else 1

__all__ = [
    "_to_int",
    "_to_int_auto",
    "_txn",
    "_safe_call",
    "_iter_items",
    "_json_safe",
    "_namespace_key",
    "_iter_symbol_table_symbols",
    "_iter_namespaces",
    "_is_exported_symbol",
    "_ensure_checkout_for_versioned_program",
    "_find_function_by_name",
    "_get_address",
    "_collect",
    "_dt_manager",
    "_find_data_type_by_name",
    "_parse_clear_data_mode",
    "_parse_data_type",
    "_new_java_byte_buffer",
    "_hexdump",
    "_ghidra_program_utilities",
    "_ghidra_script_util",
    "_analyze_program_if_needed",
    "_decompile_function_object",
    "_decompile_high_function",
    "_requires_full_param_commit",
    "_build_signature_parser",
    "_decode_hex_bytes",
    "_get_struct_datatype",
    "_resolve_namespace",
    "_find_ghidra_class",
    "_build_class_category_path",
    "_ensure_class_struct",
    "_apply_members_to_struct",
    "_get_enum_datatype",
    "_describe_struct",
    "_describe_enum",
    "_component_length",
]
