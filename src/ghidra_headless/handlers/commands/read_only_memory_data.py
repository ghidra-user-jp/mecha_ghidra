"""Read-only memory/data commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.pagination import normalize_pagination


MAX_BYTE_PAYLOAD_SIZE = 1024 * 1024


def validate_hex_payload_size(value):
    max_hex_digits = MAX_BYTE_PAYLOAD_SIZE * 2
    hex_digits = 0
    for character in value:
        if character.isspace():
            continue
        hex_digits += 1
        if hex_digits > max_hex_digits:
            raise ValueError("bytes must not exceed %d bytes" % MAX_BYTE_PAYLOAD_SIZE)


def list_segments(params, *, ensure_context, to_int):
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
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
    offset, limit = normalize_pagination(params, to_int, 100)
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
    offset, limit = normalize_pagination(params, to_int, 100)
    iterator = ctx.symbol_table.getExternalEntryPointIterator()
    exports = []
    idx = 0
    for address in iter_items(iterator):
        symbol = ctx.symbol_table.getPrimarySymbol(address)
        if symbol is None or not is_exported_symbol(ctx, symbol):
            continue
        if idx >= offset:
            exports.append(symbol.getName(True))
            if len(exports) >= limit:
                break
        idx += 1
    return exports


def list_namespaces(params, *, ensure_context, to_int, iter_namespaces, safe_call):
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
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
    offset, limit = normalize_pagination(params, to_int, 100)
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
    # Simple dump list; in Jython environments this is extracted from dataIter.
    ctx = ensure_context()
    filter_text = params.get("filter")
    offset, limit = normalize_pagination(params, to_int, 2000)
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
        raise ValueError("label is required")
    symbols = ctx.symbol_table.getSymbols(label)
    results = []
    for symbol in iter_items(symbols):
        address = symbol.getAddress()
        data = ctx.listing.getDefinedDataAt(address)
        if data is None:
            continue
        representation = data.getDefaultValueRepresentation()
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
        raise ValueError("size must be a positive integer")
    if size > MAX_BYTE_PAYLOAD_SIZE:
        raise ValueError("size must not exceed %d bytes" % MAX_BYTE_PAYLOAD_SIZE)
    address = get_address(ctx, address_text)
    memory = ctx.program.getMemory()
    return hexdump(memory, address, size)


def search_bytes(params, *, ensure_context, to_int, decode_hex_bytes):
    pattern_text = params.get("bytes")
    if not pattern_text:
        raise ValueError("bytes is required")
    validate_hex_payload_size(pattern_text)
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    pattern = decode_hex_bytes(pattern_text)
    if not pattern:
        raise ValueError("bytes must contain at least one byte")
    memory = ctx.program.getMemory()
    start = memory.getMinAddress()
    end = memory.getMaxAddress()
    monitor = ctx.monitor()
    results = []
    skipped = 0
    current = start
    while True:
        address = memory.findBytes(current, end, pattern, None, True, monitor)
        if address is None:
            break
        if skipped < offset:
            skipped += 1
        else:
            results.append(str(address))
            if len(results) >= limit:
                break
        if address.compareTo(end) >= 0:
            break
        current = address.add(1)
    return results


def get_struct(params, *, ensure_context, get_struct_datatype, describe_struct):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("name is required")
    category = params.get("category")
    struct = get_struct_datatype(ctx, name, category)
    if struct is None:
        raise LookupError("Struct not found: %s" % name)
    return describe_struct(struct)


def get_enum(params, *, ensure_context, get_enum_datatype, describe_enum, safe_call):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("name is required")
    category = params.get("category")
    enum_dt = get_enum_datatype(ctx, name, category)
    if enum_dt is None:
        raise LookupError("Enum not found: %s" % name)
    class_name = safe_call(safe_call(enum_dt, "getClass"), "getName")
    if not class_name or "Enum" not in str(class_name):
        raise TypeError("Specified data type is not an enum")
    return describe_enum(enum_dt)
