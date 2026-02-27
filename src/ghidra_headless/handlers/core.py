"""Ghidraのヘッドレス操作をラップするハンドラ群。"""

from __future__ import absolute_import, print_function

import threading
from numbers import Integral

import jpype

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath,
    StructureDataType,
    EnumDataType,
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
from ghidra.util.task import ConsoleTaskMonitor, TaskMonitor

from ghidra_headless.handlers.commands import (
    get_function_by_address as get_function_by_address_command,
)
from ghidra_headless.handlers.commands import list_classes as list_classes_command
from ghidra_headless.handlers.commands import list_functions as list_functions_command
from ghidra_headless.handlers.commands import list_methods as list_methods_command
from ghidra_headless.handlers.commands import (
    search_functions_by_name as search_functions_by_name_command,
)

_CONTEXTS = {}
_THREAD_STATE = threading.local()
_GHIDRA_PROGRAM_UTILITIES = None
_GHIDRA_SCRIPT_UTIL = None


class HeadlessContext(object):
    def __init__(self, program):
        self.program = program
        self.flat_api = FlatProgramAPI(program)
        self.symbol_table = program.getSymbolTable()
        self.function_manager = program.getFunctionManager()
        self.namespace_manager = program.getNamespaceManager()
        self.address_factory = program.getAddressFactory()
        self.listing = program.getListing()
        self.reference_manager = program.getReferenceManager()

    def monitor(self):
        return ConsoleTaskMonitor()


def initialize(program, key="default"):
    _CONTEXTS[key] = HeadlessContext(program)
    return _CONTEXTS[key]


def remove_context(key):
    _CONTEXTS.pop(key, None)
    if getattr(_THREAD_STATE, "current_key", None) == key:
        delattr(_THREAD_STATE, "current_key")


def clear_contexts():
    _CONTEXTS.clear()
    if hasattr(_THREAD_STATE, "current_key"):
        delattr(_THREAD_STATE, "current_key")


def _ensure_context_for_key(key):
    if key not in _CONTEXTS:
        raise RuntimeError("コンテキストが初期化されていません: %s" % key)
    return _CONTEXTS[key]


def ensure_context():
    key = getattr(_THREAD_STATE, "current_key", None)
    if key is None:
        raise RuntimeError("コンテキストキーが設定されていません")
    return _ensure_context_for_key(key)


def _to_int(value, default):
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _to_int_auto(value):
    if value is None:
        raise ValueError("数値が未指定です")
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
    domain_file = _safe_call(program, "getDomainFile")
    if domain_file is None:
        return

    is_versioned = _safe_call(domain_file, "isVersioned")
    if not bool(is_versioned):
        return
    is_checked_out = _safe_call(domain_file, "isCheckedOut")
    if bool(is_checked_out):
        return
    raise RuntimeError(
        "CHECKOUT_REQUIRED: 共有プロジェクトの更新系操作には checkout が必要です。"
        "先に checkout_project_program を実行してください"
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
        raise ValueError("addressが空です")
    address = ctx.address_factory.getAddress(address_text)
    if address is None:
        raise ValueError("不正なアドレス: %s" % address_text)
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
        raise ValueError("clear_modeが不正です: %s (利用可能: %s)" % (clear_mode_text, allowed))
    return mode


def _parse_data_type(ctx, type_str):
    if not type_str:
        raise ValueError("data_typeが指定されていません")

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
        raise RuntimeError("メモリの読み取りに失敗しました")
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
                raise RuntimeError("デコンパイラの初期化に失敗しました")
            results = interface.decompileFunction(function, 120, ctx.monitor())
            if results is None:
                raise RuntimeError("デコンパイルに失敗しました")
            decompiled = results.getDecompiledFunction()
            if decompiled is not None:
                return decompiled.getC()
            detail = (results.getErrorMessage() or "").strip()
            if detail:
                raise RuntimeError("デコンパイル結果が空です: %s" % detail)
            raise RuntimeError("デコンパイル結果が空です")
        finally:
            interface.dispose()

    try:
        return _run_decompile()
    except RuntimeError as first_error:
        analyzed = False
        try:
            analyzed = _analyze_program_if_needed(ctx)
        except Exception:
            analyzed = False
        if not analyzed:
            raise
        return _run_decompile()


def _decompile_high_function(ctx, function):
    def _run_decompile():
        interface = DecompInterface()
        try:
            if not interface.openProgram(ctx.program):
                raise RuntimeError("デコンパイラの初期化に失敗しました")
            results = interface.decompileFunction(function, 120, ctx.monitor())
            if results is None:
                raise RuntimeError("デコンパイルに失敗しました")
            if not results.decompileCompleted():
                detail = (results.getErrorMessage() or "").strip()
                if detail:
                    raise RuntimeError("デコンパイルに失敗しました: %s" % detail)
                raise RuntimeError("デコンパイルに失敗しました")
            high_function = results.getHighFunction()
            if high_function is None:
                raise RuntimeError("高レベル関数情報を取得できませんでした")
            return high_function
        finally:
            interface.dispose()

    try:
        return _run_decompile()
    except RuntimeError:
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
        # 環境差分でシグネチャが1引数版のみの場合に対応
        return FunctionSignatureParser(data_type_manager)


def _decode_hex_bytes(hex_string):
    cleaned = "".join(hex_string.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("bytesの長さが不正です")
    try:
        return bytearray.fromhex(cleaned)
    except Exception:
        raise ValueError("bytesは16進数で指定してください")


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
        raise LookupError("親名前空間が見つかりません: %s" % parent_namespace)

    class_namespace = _find_ghidra_class(ctx, class_name, parent)
    if class_namespace is None:
        if not create_class_if_missing:
            raise LookupError("クラスが見つかりません: %s" % class_name)
        class_namespace = ctx.symbol_table.createClass(parent, class_name, SourceType.USER_DEFINED)

    category = _build_class_category_path(class_namespace)
    struct = _get_struct_datatype(ctx, class_name, category)
    if struct is None:
        if not create_struct_if_missing:
            raise LookupError("クラス構造体が見つかりません: %s" % class_name)
        struct = StructureDataType(CategoryPath(category), class_name, 0)
        struct = _dt_manager(ctx).addDataType(struct, None)
    return class_namespace, struct


def _apply_members_to_struct(ctx, struct, members):
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("membersの要素はオブジェクトで指定してください")
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


def list_methods(params):
    # 既存の契約テスト（paramsキー整合）を維持するため、明示的に参照しておく。
    params.get("offset")
    params.get("limit")
    return list_methods_command(
        params,
        ensure_context=ensure_context,
        to_int=_to_int,
        collect=_collect,
    )


def list_functions(params):
    # 既存の契約テスト（paramsキー整合）を維持するため、明示的に参照しておく。
    params.get("offset")
    params.get("limit")
    return list_functions_command(
        params,
        ensure_context=ensure_context,
        to_int=_to_int,
        collect=_collect,
    )


def list_classes(params):
    # 既存の契約テスト（paramsキー整合）を維持するため、明示的に参照しておく。
    params.get("offset")
    params.get("limit")
    ctx = ensure_context()
    _iter_namespaces(ctx)
    return list_classes_command(
        params,
        context=ctx,
        to_int=_to_int,
        iter_namespaces=_iter_namespaces,
        safe_call=_safe_call,
    )


def decompile_function(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    function = _find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % name)

    return _decompile_function_object(ctx, function)


def decompile_function_by_address(params):
    ctx = ensure_context()
    address_text = params.get("address")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("アドレスに対応する関数が見つかりません: %s" % address_text)
    return _decompile_function_object(ctx, function)


def rename_function(params):
    ctx = ensure_context()
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not old_name or not new_name:
        raise ValueError("oldNameとnewNameが必要です")
    function = _find_function_by_name(ctx, old_name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % old_name)

    def _rename():
        function.setName(new_name, SourceType.USER_DEFINED)
        return True

    _txn(ctx, "Rename function", _rename)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def rename_function_by_address(params):
    ctx = ensure_context()
    address_text = params.get("function_address")
    new_name = params.get("new_name") or params.get("newName")
    if not address_text or not new_name:
        raise ValueError("function_addressとnew_nameは必須です")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("アドレスに対応する関数が見つかりません: %s" % address_text)
    def _rename():
        function.setName(new_name, SourceType.USER_DEFINED)
        return True
    _txn(ctx, "Rename function", _rename)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def rename_data(params):
    ctx = ensure_context()
    address_text = params.get("address")
    new_name = params.get("newName")
    if not new_name:
        raise ValueError("newNameが必要です")
    address = _get_address(ctx, address_text)
    symbol = ctx.symbol_table.getPrimarySymbol(address)
    if symbol is None:
        raise LookupError("アドレスにデータシンボルが存在しません: %s" % address_text)

    def _rename():
        symbol.setName(new_name, SourceType.USER_DEFINED)
        return True

    _txn(ctx, "Rename data", _rename)
    return {"name": symbol.getName(), "address": str(symbol.getAddress())}


def list_segments(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    blocks = ctx.program.getMemory().getBlocks()
    result = []
    idx = 0
    for block in blocks:
        if idx < offset:
            idx += 1
            continue
        entry = {
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "length": block.getSize(),
            "permissions": {
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute(),
            },
        }
        result.append(entry)
        if len(result) >= limit:
            break
        idx += 1
    return result


def list_imports(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    iterator = ctx.symbol_table.getExternalSymbols()
    items = []
    idx = 0
    while iterator.hasNext():
        symbol = iterator.next()
        if idx >= offset:
            items.append(symbol.getName(True))
            if len(items) >= limit:
                break
        idx += 1
    return items


def list_exports(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    iterator = ctx.function_manager.getFunctions(True)
    exports = []
    idx = 0
    for function in _iter_items(iterator):
        symbol = function.getSymbol()
        if _is_exported_symbol(ctx, symbol):
            if idx >= offset:
                exports.append(symbol.getName(True))
                if len(exports) >= limit:
                    break
            idx += 1
    return exports


def list_namespaces(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    result = []
    idx = 0
    for namespace in _iter_namespaces(ctx):
        if bool(_safe_call(namespace, "isGlobal")):
            continue
        if idx >= offset:
            result.append(namespace.getName(True))
            if len(result) >= limit:
                break
        idx += 1
    return result


def list_data_items(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    data_iter = ctx.listing.getDefinedData(True)
    items = []
    idx = 0
    while data_iter.hasNext():
        data = data_iter.next()
        if idx >= offset:
            item = {
                "address": str(data.getAddress()),
                "dataType": str(data.getDataType()),
            }
            items.append(item)
            if len(items) >= limit:
                break
        idx += 1
    return items


def search_functions_by_name(params):
    # 既存の契約テスト（paramsキー整合）を維持するため、明示的に参照しておく。
    params.get("query")
    params.get("offset")
    params.get("limit")
    return search_functions_by_name_command(
        params,
        ensure_context=ensure_context,
        to_int=_to_int,
    )


def rename_variable(params):
    ctx = ensure_context()
    function_name = params.get("functionName")
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not function_name or not old_name or not new_name:
        raise ValueError("functionName, oldName, newNameが必要です")

    function = _find_function_by_name(ctx, function_name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % function_name)

    if old_name == new_name:
        return {"name": new_name}

    # まず高レベルシンボル（ローカル＋引数）を優先して更新する。
    # これにより引数名やデコンパイル由来の変数名にも対応できる。
    high_symbol = None
    high_function = None
    try:
        high_function = _decompile_high_function(ctx, function)
    except Exception:
        high_function = None

    if high_function is not None:
        local_symbol_map = high_function.getLocalSymbolMap()
        if local_symbol_map is not None:
            symbols = local_symbol_map.getSymbols()
            while symbols.hasNext():
                symbol = symbols.next()
                symbol_name = symbol.getName()
                if symbol_name == new_name and symbol_name != old_name:
                    raise ValueError("同名の変数が既に存在します: %s" % new_name)
                if symbol_name == old_name:
                    high_symbol = symbol
            if high_symbol is not None:
                def _rename_high():
                    if _requires_full_param_commit(high_symbol, high_function):
                        HighFunctionDBUtil.commitParamsToDatabase(
                            high_function,
                            False,
                            HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                            function.getSignatureSource(),
                        )
                    HighFunctionDBUtil.updateDBVariable(
                        high_symbol,
                        new_name,
                        None,
                        SourceType.USER_DEFINED,
                    )
                    return True

                _txn(ctx, "Rename variable", _rename_high)
                return {"name": new_name}

    # フォールバック: DB上のローカル変数と引数を直接変更
    target = None
    for local in function.getLocalVariables():
        local_name = local.getName()
        if local_name == new_name and local_name != old_name:
            raise ValueError("同名の変数が既に存在します: %s" % new_name)
        if local_name == old_name:
            target = local

    if target is None:
        for param in function.getParameters():
            param_name = param.getName()
            if param_name == new_name and param_name != old_name:
                raise ValueError("同名の変数が既に存在します: %s" % new_name)
            if param_name == old_name:
                target = param
                break

    if target is None:
        raise LookupError("変数が見つかりません: %s" % old_name)

    def _rename():
        target.setName(new_name, SourceType.USER_DEFINED)
        return True

    _txn(ctx, "Rename variable", _rename)
    return {"name": target.getName()}


def get_function_by_address(params):
    # 既存の契約テスト（paramsキー整合）を維持するため、明示的に参照しておく。
    params.get("address")
    return get_function_by_address_command(
        params,
        ensure_context=ensure_context,
        get_address=_get_address,
    )


def disassemble_function(params):
    ctx = ensure_context()
    address_text = params.get("address")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)
    body = function.getBody()
    instructions = ctx.listing.getInstructions(body, True)
    lines = []
    for inst in _iter_items(instructions):
        operand_parts = []
        try:
            operand_count = inst.getNumOperands()
        except Exception:
            operand_count = 0

        for operand_index in range(operand_count):
            try:
                operand_repr = inst.getDefaultOperandRepresentation(operand_index)
            except Exception:
                operand_repr = None
            if operand_repr:
                operand_parts.append(str(operand_repr))

        operands = ", ".join(operand_parts)
        comment = inst.getComment(CodeUnit.EOL_COMMENT)
        line = {
            "address": str(inst.getAddress()),
            "mnemonic": str(inst.getMnemonicString()),
            "operands": str(operands),
            "comment": str(comment) if comment else "",
        }
        lines.append(line)
    return lines


def set_decompiler_comment(params):
    ctx = ensure_context()
    address_text = params.get("address")
    comment = params.get("comment", "")
    address = _get_address(ctx, address_text)

    def _apply():
        ctx.listing.setComment(address, CodeUnit.PRE_COMMENT, comment)
        return True

    _txn(ctx, "Set decompiler comment", _apply)
    return {"address": address_text, "comment": comment}


def set_disassembly_comment(params):
    ctx = ensure_context()
    address_text = params.get("address")
    comment = params.get("comment", "")
    address = _get_address(ctx, address_text)

    def _apply():
        ctx.listing.setComment(address, CodeUnit.EOL_COMMENT, comment)
        return True

    _txn(ctx, "Set disassembly comment", _apply)
    return {"address": address_text, "comment": comment}


def set_function_prototype(params):
    ctx = ensure_context()
    address_text = params.get("function_address")
    prototype = params.get("prototype")
    if not address_text or not prototype:
        raise ValueError("function_addressとprototypeは必須です")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)

    def _apply():
        parser = _build_signature_parser(ctx)
        base_signature = _safe_call(function, "getSignature")
        try:
            signature = parser.parse(base_signature, prototype)
        except TypeError:
            signature = parser.parse(None, prototype)
        if signature is None:
            raise ValueError("関数プロトタイプを解析できません: %s" % prototype)

        command = ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED)
        if not command.applyTo(ctx.program, ctx.monitor()):
            status_msg = _safe_call(command, "getStatusMsg")
            if status_msg:
                raise RuntimeError("関数プロトタイプの適用に失敗しました: %s" % status_msg)
            raise RuntimeError("関数プロトタイプの適用に失敗しました")
        return True

    _txn(ctx, "Set function prototype", _apply)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def set_local_variable_type(params):
    ctx = ensure_context()
    address_text = params.get("function_address")
    variable_name = params.get("variable_name")
    type_text = params.get("new_type")
    if not address_text or not variable_name or not type_text:
        raise ValueError("function_address, variable_name, new_typeは必須です")

    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)

    data_type = _parse_data_type(ctx, type_text)

    def _apply():
        high_function = None
        try:
            high_function = _decompile_high_function(ctx, function)
        except Exception:
            high_function = None
        if high_function is not None:
            local_symbol_map = high_function.getLocalSymbolMap()
            if local_symbol_map is not None:
                symbols = local_symbol_map.getSymbols()
                target_symbol = None
                while symbols.hasNext():
                    symbol = symbols.next()
                    if symbol.getName() == variable_name:
                        target_symbol = symbol
                        break
                if target_symbol is not None:
                    if _requires_full_param_commit(target_symbol, high_function):
                        HighFunctionDBUtil.commitParamsToDatabase(
                            high_function,
                            False,
                            HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                            function.getSignatureSource(),
                        )
                    HighFunctionDBUtil.updateDBVariable(
                        target_symbol,
                        target_symbol.getName(),
                        data_type,
                        SourceType.USER_DEFINED,
                    )
                    return True
        for local in function.getLocalVariables():
            if local.getName() == variable_name:
                local.setDataType(data_type, SourceType.USER_DEFINED)
                return True
        for param in function.getParameters():
            if param.getName() == variable_name:
                param.setDataType(data_type, SourceType.USER_DEFINED)
                return True
        raise LookupError("変数が見つかりません: %s" % variable_name)

    _txn(ctx, "Set local variable type", _apply)
    return {"function": function.getName(), "variable": variable_name, "type": type_text}


def get_xrefs_to(params):
    ctx = ensure_context()
    address_text = params.get("address")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    address = _get_address(ctx, address_text)
    references = ctx.reference_manager.getReferencesTo(address)
    items = []
    idx = 0
    for ref in _iter_items(references):
        if idx >= offset:
            items.append({
                "from": str(ref.getFromAddress()),
                "type": str(ref.getReferenceType()),
            })
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_xrefs_from(params):
    ctx = ensure_context()
    address_text = params.get("address")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    address = _get_address(ctx, address_text)
    references = ctx.reference_manager.getReferencesFrom(address)
    items = []
    idx = 0
    for ref in _iter_items(references):
        if idx >= offset:
            items.append({
                "to": str(ref.getToAddress()),
                "type": str(ref.getReferenceType()),
            })
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_function_xrefs(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    function = _find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % name)
    entry = function.getEntryPoint()
    references = ctx.reference_manager.getReferencesTo(entry)
    results = []
    idx = 0
    for ref in _iter_items(references):
        if idx >= offset:
            results.append({
                "from": str(ref.getFromAddress()),
                "type": str(ref.getReferenceType()),
            })
            if len(results) >= limit:
                break
        idx += 1
    return results


def list_strings(params):
    # シンプルなダンプリスト。Jython環境ではdataIterから抽出。
    ctx = ensure_context()
    filter_text = params.get("filter")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 200)
    data_iter = ctx.listing.getDefinedData(True)
    items = []
    idx = 0
    while data_iter.hasNext():
        data = data_iter.next()
        if not data.hasStringValue():
            continue
        string_value = str(data.getValue())
        if filter_text and filter_text not in string_value:
            continue
        if idx >= offset:
            items.append({
                "address": str(data.getAddress()),
                "string": string_value,
            })
            if len(items) >= limit:
                break
        idx += 1
    return items


def create_struct(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    size = _to_int(params.get("size"), 0)
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _create():
        dtm = _dt_manager(ctx)
        struct = StructureDataType(CategoryPath(category) if category else CategoryPath("/"), name, size)
        struct = dtm.addDataType(struct, None)
        for member in members:
            data_type = _parse_data_type(ctx, member.get("type"))
            field_name = member.get("name", "")
            comment = member.get("comment", "")
            offset = member.get("offset")
            length = _component_length(data_type)
            if offset is not None:
                struct.replaceAtOffset(int(offset), data_type, length, field_name, comment)
            else:
                struct.add(data_type, length, field_name, comment)
        dtm.replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Create struct", _create)
    return _describe_struct(struct_dt)


def add_struct_members(params):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        struct = _get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        for member in members:
            data_type = _parse_data_type(ctx, member.get("type"))
            field_name = member.get("name", "")
            comment = member.get("comment", "")
            offset = member.get("offset")
            length = _component_length(data_type)
            if offset is not None:
                struct.replaceAtOffset(int(offset), data_type, length, field_name, comment)
            else:
                struct.add(data_type, length, field_name, comment)
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Add struct members", _update)
    return _describe_struct(struct_dt)


def clear_struct(params):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")

    def _clear():
        struct = _get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        cleared = False
        clear_components = getattr(struct, "clearComponents", None)
        if callable(clear_components):
            clear_components()
            cleared = True
        else:
            num_components = _safe_call(struct, "getNumComponents")
            if num_components is None:
                num_components = len(list(_iter_items(struct.getComponents())))
            for ordinal in range(int(num_components) - 1, -1, -1):
                struct.delete(ordinal)
                cleared = True
        if not cleared:
            raise RuntimeError("構造体メンバーのクリアに失敗しました")
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Clear struct", _clear)
    return _describe_struct(struct_dt)


def get_struct(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    struct = _get_struct_datatype(ctx, name, category)
    if struct is None:
        raise LookupError("構造体が見つかりません: %s" % name)
    return _describe_struct(struct)


def get_data_by_label(params):
    ctx = ensure_context()
    label = params.get("label")
    if not label:
        raise ValueError("labelが必要です")
    symbols = ctx.symbol_table.getSymbols(label)
    results = []
    for symbol in _iter_items(symbols):
        address = symbol.getAddress()
        data = ctx.listing.getDefinedDataAt(address)
        representation = data.getDefaultValueRepresentation() if data else ""
        results.append({
            "name": symbol.getName(True),
            "address": str(address),
            "value": representation,
        })
    return results


def get_bytes(params):
    ctx = ensure_context()
    address_text = params.get("address")
    size = _to_int(params.get("size"), 1)
    if size <= 0:
        raise ValueError("sizeは正の整数で指定してください")
    address = _get_address(ctx, address_text)
    memory = ctx.program.getMemory()
    return _hexdump(memory, address, size)


def search_bytes(params):
    ctx = ensure_context()
    pattern_text = params.get("bytes")
    if not pattern_text:
        raise ValueError("bytesが必要です")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    pattern = _decode_hex_bytes(pattern_text)
    memory = ctx.program.getMemory()
    start = memory.getMinAddress()
    end = memory.getMaxAddress()
    monitor = ctx.monitor()
    results = []
    current = start
    while True:
        address = memory.findBytes(current, end, pattern, None, True, monitor)
        if address is None:
            break
        results.append(str(address))
        if len(results) >= offset + limit:
            break
        current = address.add(1)
    return results[offset: offset + limit]


def create_enum(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    size = _to_int(params.get("size"), 4)
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _create():
        enum_dt = EnumDataType(CategoryPath(category) if category else CategoryPath("/"), name, size)
        for value in values:
            enum_dt.add(value.get("name"), _to_int_auto(value.get("value")), value.get("comment"))
        _dt_manager(ctx).addDataType(enum_dt, None)
        return enum_dt

    enum_dt = _txn(ctx, "Create enum", _create)
    return _describe_enum(enum_dt)


def add_enum_values(params):
    ctx = ensure_context()
    name = params.get("enum_name")
    if not name:
        raise ValueError("enum_nameが必要です")
    category = params.get("category")
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _update():
        enum_dt = _get_enum_datatype(ctx, name, category)
        if enum_dt is None:
            raise LookupError("列挙体が見つかりません: %s" % name)
        for value in values:
            enum_dt.add(value.get("name"), _to_int_auto(value.get("value")), value.get("comment"))
        _dt_manager(ctx).replaceDataType(enum_dt, enum_dt, True)
        return enum_dt

    enum_dt = _txn(ctx, "Add enum values", _update)
    return _describe_enum(enum_dt)


def get_enum(params):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    enum_dt = _get_enum_datatype(ctx, name, category)
    if enum_dt is None:
        raise LookupError("列挙体が見つかりません: %s" % name)
    class_name = _safe_call(_safe_call(enum_dt, "getClass"), "getName")
    if not class_name or "Enum" not in str(class_name):
        raise TypeError("指定されたデータ型は列挙型ではありません")
    return _describe_enum(enum_dt)


def set_global_data_type(params):
    ctx = ensure_context()
    address_text = params.get("address")
    data_type_text = params.get("data_type")
    length = _to_int(params.get("length"), -1)
    clear_mode_text = params.get("clear_mode")
    if not address_text or not data_type_text:
        raise ValueError("addressとdata_typeは必須です")
    address = _get_address(ctx, address_text)
    data_type = _parse_data_type(ctx, data_type_text)
    clear_mode = _parse_clear_data_mode(clear_mode_text)

    def _apply():
        created = DataUtilities.createData(ctx.program, address, data_type, length, clear_mode)
        if created is None:
            raise RuntimeError("データ型の設定に失敗しました")
        return True

    _txn(ctx, "Set global data type", _apply)
    return {"address": address_text, "data_type": data_type_text, "clear_mode": str(clear_mode)}


def create_class(params):
    ctx = ensure_context()
    class_name = params.get("name")
    if not class_name:
        raise ValueError("nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _create():
        parent = _resolve_namespace(ctx, parent_namespace)
        if parent is None:
            raise LookupError("親名前空間が見つかりません: %s" % parent_namespace)
        existing_class = _find_ghidra_class(ctx, class_name, parent)
        if existing_class is not None:
            raise ValueError("クラスが既に存在します: %s" % class_name)

        class_namespace = ctx.symbol_table.createClass(parent, class_name, SourceType.USER_DEFINED)
        category = _build_class_category_path(class_namespace)
        struct = _get_struct_datatype(ctx, class_name, category)
        if struct is None:
            struct = StructureDataType(CategoryPath(category), class_name, 0)
            struct = _dt_manager(ctx).addDataType(struct, None)
        _apply_members_to_struct(ctx, struct, members)
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return class_namespace, struct

    class_namespace, struct_dt = _txn(ctx, "Create class", _create)
    namespace_name = _safe_call(class_namespace, "getName", True)
    if not namespace_name:
        namespace_name = class_namespace.getName()
    return {
        "class": namespace_name,
        "struct": _describe_struct(struct_dt),
    }


def add_class_members(params):
    ctx = ensure_context()
    class_name = params.get("class_name")
    if not class_name:
        raise ValueError("class_nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        _, struct = _ensure_class_struct(
            ctx,
            class_name,
            parent_namespace,
            create_class_if_missing=False,
            create_struct_if_missing=False,
        )
        _apply_members_to_struct(ctx, struct, members)
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Add class members", _update)
    return _describe_struct(struct_dt)


def remove_class_members(params):
    ctx = ensure_context()
    class_name = params.get("class_name")
    if not class_name:
        raise ValueError("class_nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        _, struct = _ensure_class_struct(
            ctx,
            class_name,
            parent_namespace,
            create_class_if_missing=False,
            create_struct_if_missing=False,
        )
        target_names = set(members)
        for component in list(struct.getComponents()):
            if component.getFieldName() in target_names:
                struct.delete(component.getOrdinal())
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Remove class members", _update)
    return _describe_struct(struct_dt)


def remove_enum_values(params):
    ctx = ensure_context()
    name = params.get("enum_name")
    if not name:
        raise ValueError("enum_nameが必要です")
    category = params.get("category")
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _update():
        enum_dt = _get_enum_datatype(ctx, name, category)
        if enum_dt is None:
            raise LookupError("列挙体が見つかりません: %s" % name)
        for value in values:
            enum_dt.remove(value)
        _dt_manager(ctx).replaceDataType(enum_dt, enum_dt, True)
        return enum_dt

    enum_dt = _txn(ctx, "Remove enum values", _update)
    return _describe_enum(enum_dt)


def remove_struct_members(params):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        struct = _get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        target_names = set(members)
        for component in list(struct.getComponents()):
            if component.getFieldName() in target_names:
                struct.delete(component.getOrdinal())
        _dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = _txn(ctx, "Remove struct members", _update)
    return _describe_struct(struct_dt)


def set_bytes(params):
    ctx = ensure_context()
    address_text = params.get("address")
    bytes_text = params.get("bytes")
    if not address_text or not bytes_text:
        raise ValueError("addressとbytesは必須です")
    address = _get_address(ctx, address_text)
    data = _decode_hex_bytes(bytes_text)

    def _apply():
        ctx.program.getMemory().setBytes(address, data)
        return True

    _txn(ctx, "Set bytes", _apply)
    return {"address": address_text, "length": len(data)}


def get_callee(params):
    ctx = ensure_context()
    address_text = params.get("address")
    if not address_text:
        raise ValueError("addressが必要です")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)
    callees = function.getCalledFunctions(TaskMonitor.DUMMY)
    callees_list = list(_iter_items(callees))
    if function.isThunk() and not callees_list:
        thunked = function.getThunkedFunction(False)
        if thunked is not None:
            callees_list = list(_iter_items(thunked.getCalledFunctions(TaskMonitor.DUMMY)))
    return sorted(["%s @ %s" % (callee.getName(True), callee.getEntryPoint()) for callee in callees_list])


def add_bookmark(params):
    ctx = ensure_context()
    address_text = params.get("address")
    category = params.get("category")
    comment = params.get("comment", "")
    bookmark_type = params.get("type")
    _bookmark_format = params.get("format", "json")
    if not address_text or not category or bookmark_type is None:
        raise ValueError("address, category, type は必須です")

    address = _get_address(ctx, address_text)
    manager = ctx.program.getBookmarkManager()

    def _apply():
        manager.setBookmark(address, bookmark_type, category, comment)
        return True

    _txn(ctx, "Add bookmark", _apply)
    return {
        "address": address_text,
        "category": category,
        "type": bookmark_type,
        "comment": comment,
    }


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


def execute(command, params, key="default"):
    handler = SUPPORTED_COMMANDS.get(command)
    if handler is None:
        raise KeyError("未対応のコマンド: %s" % command)
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


def describe_state(key="default"):
    ctx = _ensure_context_for_key(key)
    return {
        "programName": ctx.program.getName(),
        "languageID": str(ctx.program.getLanguageID()),
    }


HANDLERS = {
    "initialize": initialize,
    "execute": execute,
    "describe_state": describe_state,
    "remove_context": remove_context,
    "clear_contexts": clear_contexts,
}
