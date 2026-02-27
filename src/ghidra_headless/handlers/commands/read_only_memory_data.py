"""Read-only memory/data commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def list_segments(params, *, ensure_context, to_int):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
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


def list_imports(params, *, ensure_context, to_int):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
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


def list_exports(params, *, ensure_context, to_int, iter_items, is_exported_symbol):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    iterator = ctx.function_manager.getFunctions(True)
    exports = []
    idx = 0
    for function in iter_items(iterator):
        symbol = function.getSymbol()
        if is_exported_symbol(ctx, symbol):
            if idx >= offset:
                exports.append(symbol.getName(True))
                if len(exports) >= limit:
                    break
            idx += 1
    return exports


def list_namespaces(params, *, ensure_context, to_int, iter_namespaces, safe_call):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    result = []
    idx = 0
    for namespace in iter_namespaces(ctx):
        if bool(safe_call(namespace, "isGlobal")):
            continue
        if idx >= offset:
            result.append(namespace.getName(True))
            if len(result) >= limit:
                break
        idx += 1
    return result


def list_data_items(params, *, ensure_context, to_int):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
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


def list_strings(params, *, ensure_context, to_int):
    # シンプルなダンプリスト。Jython環境ではdataIterから抽出。
    ctx = ensure_context()
    filter_text = params.get("filter")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 200)
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
            items.append(
                {
                    "address": str(data.getAddress()),
                    "string": string_value,
                }
            )
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_data_by_label(params, *, ensure_context, iter_items):
    ctx = ensure_context()
    label = params.get("label")
    if not label:
        raise ValueError("labelが必要です")
    symbols = ctx.symbol_table.getSymbols(label)
    results = []
    for symbol in iter_items(symbols):
        address = symbol.getAddress()
        data = ctx.listing.getDefinedDataAt(address)
        representation = data.getDefaultValueRepresentation() if data else ""
        results.append(
            {
                "name": symbol.getName(True),
                "address": str(address),
                "value": representation,
            }
        )
    return results


def get_bytes(params, *, ensure_context, to_int, get_address, hexdump):
    ctx = ensure_context()
    address_text = params.get("address")
    size = to_int(params.get("size"), 1)
    if size <= 0:
        raise ValueError("sizeは正の整数で指定してください")
    address = get_address(ctx, address_text)
    memory = ctx.program.getMemory()
    return hexdump(memory, address, size)


def search_bytes(params, *, ensure_context, to_int, decode_hex_bytes):
    ctx = ensure_context()
    pattern_text = params.get("bytes")
    if not pattern_text:
        raise ValueError("bytesが必要です")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    pattern = decode_hex_bytes(pattern_text)
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


def get_struct(params, *, ensure_context, get_struct_datatype, describe_struct):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    struct = get_struct_datatype(ctx, name, category)
    if struct is None:
        raise LookupError("構造体が見つかりません: %s" % name)
    return describe_struct(struct)


def get_enum(params, *, ensure_context, get_enum_datatype, describe_enum, safe_call):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    enum_dt = get_enum_datatype(ctx, name, category)
    if enum_dt is None:
        raise LookupError("列挙体が見つかりません: %s" % name)
    class_name = safe_call(safe_call(enum_dt, "getClass"), "getName")
    if not class_name or "Enum" not in str(class_name):
        raise TypeError("指定されたデータ型は列挙型ではありません")
    return describe_enum(enum_dt)
