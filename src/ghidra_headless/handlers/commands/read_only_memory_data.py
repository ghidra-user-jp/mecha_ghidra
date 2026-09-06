"""Read-only memory/data commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.pagination import normalize_pagination

MAX_BYTE_PAYLOAD_SIZE = 1024 * 1024


def _bookmark_to_dict(bookmark):
    return {
        "id": int(bookmark.getId()),
        "address": str(bookmark.getAddress()),
        "type": bookmark.getTypeString(),
        "category": bookmark.getCategory(),
        "comment": bookmark.getComment() or "",
    }


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


def _import_entry(symbol):
    parent = symbol.getParentNamespace()
    library = None
    if parent is not None and not bool(parent.isGlobal()):
        library = str(parent.getName())
    return {
        "name": str(symbol.getName()),
        "library": library,
        "full_name": str(symbol.getName(True)),
        "address": str(symbol.getAddress()),
    }


def list_imports(params, *, ensure_context, to_int):
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    iterator = ctx.symbol_table.getExternalSymbols()
    items = []
    idx = 0
    while iterator.hasNext():
        symbol = iterator.next()
        if idx >= offset:
            items.append(_import_entry(symbol))
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
            exports.append({"name": str(symbol.getName(True)), "address": str(address)})
            if len(exports) >= limit:
                break
        idx += 1
    return exports


def _namespace_is_class(namespace, safe_call):
    # Ghidra's Namespace has no isClass(); class-ness is carried by the
    # namespace symbol's SymbolType ("Class").
    symbol = safe_call(namespace, "getSymbol")
    symbol_type = safe_call(symbol, "getSymbolType") if symbol is not None else None
    return symbol_type is not None and str(symbol_type) == "Class"


def list_namespaces(params, *, ensure_context, to_int, iter_namespaces, safe_call):
    """List namespaces; ``classes_only`` keeps only class namespaces."""
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    classes_only = bool(params.get("classes_only", False))
    result = []
    idx = 0
    for namespace in iter_namespaces(ctx):
        if bool(safe_call(namespace, "isGlobal")):
            continue
        is_class = _namespace_is_class(namespace, safe_call)
        if classes_only and not is_class:
            continue
        if idx >= offset:
            result.append({"name": namespace.getName(True), "is_class": is_class})
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
            address = data.getAddress()
            symbol = ctx.symbol_table.getPrimarySymbol(address)
            data_type = data.getDataType()
            item = {
                "address": str(address),
                # getDisplayName(): str(DataType) renders a structure's whole definition.
                "dataType": str(data_type.getDisplayName()) if data_type is not None else None,
                "name": None if symbol is None else str(symbol.getName(True)),
                "length": int(data.getLength()),
                "value": data.getDefaultValueRepresentation(),
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
    # Case-insensitive like every other name filter (list_functions, list_data_types).
    filter_lower = str(filter_text).lower() if filter_text else None
    offset, limit = normalize_pagination(params, to_int, 2000)
    data_iter = ctx.listing.getDefinedData(True)
    items = []
    idx = 0
    while data_iter.hasNext():
        data = data_iter.next()
        if not data.hasStringValue():
            continue
        string_value = str(data.getValue())
        if filter_lower and filter_lower not in string_value.lower():
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


def parse_byte_pattern(pattern_text, decode_hex_bytes):
    """Return (pattern, mask) for a hex pattern; ``??`` marks a wildcard byte.

    Without wildcards the mask is None and the pattern is what ``decode_hex_bytes``
    produces, so plain patterns behave exactly as before.
    """
    cleaned = "".join(str(pattern_text).split())
    if "?" not in cleaned:
        return decode_hex_bytes(pattern_text), None
    if len(cleaned) % 2 != 0:
        raise ValueError("Invalid bytes length")
    pattern = bytearray()
    mask = bytearray()
    for index in range(0, len(cleaned), 2):
        pair = cleaned[index : index + 2]
        if pair == "??":
            pattern.append(0)
            mask.append(0)
            continue
        if "?" in pair:
            raise ValueError("wildcards must cover whole bytes (use ??)")
        try:
            pattern.append(int(pair, 16))
        except ValueError:
            raise ValueError("bytes must be hexadecimal")
        mask.append(0xFF)
    if not any(mask):
        raise ValueError("bytes must contain at least one non-wildcard byte")
    return pattern, mask


def search_bytes(params, *, ensure_context, to_int, decode_hex_bytes):
    pattern_text = params.get("bytes")
    if not pattern_text:
        raise ValueError("bytes is required")
    validate_hex_payload_size(pattern_text)
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    pattern, mask = parse_byte_pattern(pattern_text, decode_hex_bytes)
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
        address = memory.findBytes(current, end, pattern, mask, True, monitor)
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


def list_data_types(params, *, ensure_context, to_int, dt_manager, collect, iter_items, safe_call, describe_data_type):
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    text_filter = params.get("filter")
    category = params.get("category")
    filter_lower = str(text_filter).lower() if text_filter else None
    category_text = str(category) if category else None
    manager = dt_manager(ctx)

    def _matches(data_type):
        if category_text:
            category_path = safe_call(data_type, "getCategoryPath")
            path = category_path.getPath() if category_path else "/"
            if path != category_text:
                return False
        if filter_lower:
            haystack = " ".join(
                str(value)
                for value in (
                    safe_call(data_type, "getName"),
                    safe_call(data_type, "getDisplayName"),
                    safe_call(data_type, "getPathName"),
                )
                if value
            ).lower()
            if filter_lower not in haystack:
                return False
        return True

    iterator = (data_type for data_type in iter_items(manager.getAllDataTypes()) if _matches(data_type))
    return collect(iterator, offset, limit, describe_data_type)


def list_bookmarks(params, *, ensure_context, get_address, to_int, collect, iter_items):
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    address_text = params.get("address")
    bookmark_type = params.get("type")
    category = params.get("category")
    manager = ctx.program.getBookmarkManager()

    if address_text:
        address = get_address(ctx, address_text)
        if bookmark_type:
            bookmarks = manager.getBookmarks(address, bookmark_type)
        else:
            bookmarks = manager.getBookmarks(address)
        iterator = iter_items(bookmarks)
    else:
        iterator = manager.getBookmarksIterator()

    def _matches(bookmark):
        if bookmark_type and bookmark.getTypeString() != bookmark_type:
            return False
        return not (category and bookmark.getCategory() != category)

    return collect(
        (bookmark for bookmark in iter_items(iterator) if _matches(bookmark)), offset, limit, _bookmark_to_dict
    )
