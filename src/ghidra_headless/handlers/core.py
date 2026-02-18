"""Ghidraのヘッドレス操作をラップするハンドラ群。"""

from __future__ import absolute_import, print_function

import threading
from numbers import Integral

import jpype

from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath,
    StructureDataType,
    EnumDataType,
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
    tx_id = ctx.program.startTransaction(description)
    success = False
    try:
        result = func()
        success = True
        return result
    finally:
        ctx.program.endTransaction(tx_id, success)


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
    result = []
    idx = 0
    while iterator.hasNext():
        item = iterator.next()
        if idx >= offset:
            result.append(to_value(item))
            if len(result) >= limit:
                break
        idx += 1
    return result


def _dt_manager(ctx):
    return ctx.program.getDataTypeManager()


def _parse_data_type(ctx, type_str):
    if not type_str:
        raise ValueError("data_typeが指定されていません")

    dtm = _dt_manager(ctx)
    text = type_str.strip()
    for needle in (" const", " volatile", "\t", "\n", "\r"):
        text = text.replace(needle, " ")
    text = " ".join(text.split())

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
        matches = list(dtm.findDataTypes(text))
        if matches:
            dt = matches[0]
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


def _ensure_class_struct(ctx, class_name, parent_namespace):
    category = parent_namespace if parent_namespace else "/classes"
    struct = _get_struct_datatype(ctx, class_name, category)
    if struct is None:
        struct = StructureDataType(CategoryPath(category), class_name, 0)
        struct = _dt_manager(ctx).addDataType(struct, None)
    return struct


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
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    iterator = ctx.function_manager.getFunctions(True)
    return _collect(iterator, offset, limit, lambda f: f.getName())


def list_functions(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)

    def _to_entry(func):
        return {
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
        }

    iterator = ctx.function_manager.getFunctions(True)
    return _collect(iterator, offset, limit, _to_entry)


def list_classes(params):
    ctx = ensure_context()
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)

    namespace_iter = ctx.namespace_manager.getNamespaces(True)

    def _to_entry(namespace):
        return {
            "name": namespace.getName(True),
            "isClass": namespace.isClass(),
        }

    # skip グローバル名前空間
    def _filtered(iterator):
        while iterator.hasNext():
            ns = iterator.next()
            if ns.isGlobal():
                continue
            yield ns

    items = []
    idx = 0
    for namespace in _filtered(namespace_iter):
        if idx >= offset:
            items.append(_to_entry(namespace))
            if len(items) >= limit:
                break
        idx += 1
    return items


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
    blocks = ctx.program.getMemory().getBlocks()
    result = []
    for block in blocks:
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
    return result


def list_imports(params):
    ctx = ensure_context()
    iterator = ctx.symbol_table.getExternalSymbols()
    items = []
    while iterator.hasNext():
        symbol = iterator.next()
        items.append(symbol.getName(True))
    return items


def list_exports(params):
    ctx = ensure_context()
    iterator = ctx.function_manager.getFunctions(True)
    exports = []
    while iterator.hasNext():
        function = iterator.next()
        symbol = function.getSymbol()
        if symbol is not None and symbol.isExported():
            exports.append(symbol.getName(True))
    return exports


def list_namespaces(params):
    ctx = ensure_context()
    iterator = ctx.namespace_manager.getNamespaces(True)
    result = []
    while iterator.hasNext():
        namespace = iterator.next()
        if namespace.isGlobal():
            continue
        result.append(namespace.getName(True))
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
    ctx = ensure_context()
    query = params.get("query")
    if not query:
        raise ValueError("queryが必要です")
    offset = _to_int(params.get("offset"), 0)
    limit = _to_int(params.get("limit"), 100)
    iterator = ctx.function_manager.getFunctions(True)
    matches = []
    idx = 0
    lowered = query.lower()
    while iterator.hasNext():
        function = iterator.next()
        if lowered in function.getName().lower():
            if idx >= offset:
                matches.append({
                    "name": function.getName(),
                    "entry": str(function.getEntryPoint()),
                })
                if len(matches) >= limit:
                    break
            idx += 1
    return matches


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

    target = None
    for local in function.getLocalVariables():
        if local.getName() == old_name:
            target = local
            break
    if target is None:
        raise LookupError("ローカル変数が見つかりません: %s" % old_name)

    def _rename():
        target.setName(new_name, SourceType.USER_DEFINED)
        return True

    _txn(ctx, "Rename variable", _rename)
    return {"name": target.getName()}


def get_function_by_address(params):
    ctx = ensure_context()
    address_text = params.get("address")
    address = _get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)
    return {
        "name": function.getName(),
        "entry": str(function.getEntryPoint()),
    }


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
    while instructions.hasNext():
        inst = instructions.next()
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
                operand_parts.append(operand_repr)

        operands = ", ".join(operand_parts)
        comment = inst.getComment(CodeUnit.EOL_COMMENT)
        line = {
            "address": str(inst.getAddress()),
            "mnemonic": inst.getMnemonicString(),
            "operands": operands,
            "comment": comment or "",
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
        function.setPrototypeString(prototype, SourceType.USER_DEFINED)
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
    while references.hasNext():
        ref = references.next()
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
    while references.hasNext():
        ref = references.next()
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
    while references.hasNext():
        ref = references.next()
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
        struct.clearComponents()
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
    while symbols.hasNext():
        symbol = symbols.next()
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
    if not isinstance(enum_dt, EnumDataType):
        raise TypeError("指定されたデータ型は列挙型ではありません")
    return _describe_enum(enum_dt)


def set_global_data_type(params):
    ctx = ensure_context()
    address_text = params.get("address")
    data_type_text = params.get("data_type")
    length = _to_int(params.get("length"), -1)
    if not address_text or not data_type_text:
        raise ValueError("addressとdata_typeは必須です")
    address = _get_address(ctx, address_text)
    data_type = _parse_data_type(ctx, data_type_text)

    def _apply():
        listing = ctx.listing
        listing.clearCodeUnits(address, address)
        if length > 0:
            listing.createData(address, data_type, length)
        else:
            listing.createData(address, data_type)
        return True

    _txn(ctx, "Set global data type", _apply)
    return {"address": address_text, "data_type": data_type_text}


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
        struct = _ensure_class_struct(ctx, class_name, parent_namespace)
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
        struct = _ensure_class_struct(ctx, class_name, parent_namespace)
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
    if function.isThunk() and not callees:
        thunked = function.getThunkedFunction(False)
        if thunked is not None:
            callees = thunked.getCalledFunctions(TaskMonitor.DUMMY)
    return sorted(["%s @ %s" % (callee.getName(True), callee.getEntryPoint()) for callee in callees])


def add_bookmark(params):
    ctx = ensure_context()
    address_text = params.get("address")
    category = params.get("category")
    comment = params.get("comment", "")
    bookmark_type = params.get("type")
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
        return handler(params or {})
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
