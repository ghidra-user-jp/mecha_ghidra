"""Read-only function commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def list_functions(params, *, ensure_context, to_int, collect):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)

    def _to_entry(func):
        return {
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
        }

    iterator = ctx.function_manager.getFunctions(True)
    return collect(iterator, offset, limit, _to_entry)


def list_classes(params, *, context, to_int, iter_namespaces, safe_call):
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)

    def _is_class(namespace):
        # Ghidra's Namespace has no isClass(); class-ness is carried by the
        # namespace symbol's SymbolType ("Class").
        symbol = safe_call(namespace, "getSymbol")
        symbol_type = safe_call(symbol, "getSymbolType") if symbol is not None else None
        return symbol_type is not None and str(symbol_type) == "Class"

    def _to_entry(namespace):
        return {
            "name": namespace.getName(True),
            "isClass": _is_class(namespace),
        }

    items = []
    idx = 0
    for namespace in iter_namespaces(context):
        if bool(safe_call(namespace, "isGlobal")):
            continue
        if idx >= offset:
            items.append(_to_entry(namespace))
            if len(items) >= limit:
                break
        idx += 1
    return items


def search_functions_by_name(params, *, ensure_context, to_int):
    ctx = ensure_context()
    query = params.get("query")
    if not query:
        raise ValueError("query is required")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    iterator = ctx.function_manager.getFunctions(True)
    matches = []
    idx = 0
    lowered = query.lower()
    while iterator.hasNext():
        function = iterator.next()
        if lowered in function.getName().lower():
            if idx >= offset:
                matches.append(
                    {
                        "name": function.getName(),
                        "entry": str(function.getEntryPoint()),
                    }
                )
                if len(matches) >= limit:
                    break
            idx += 1
    return matches


def get_function(params, *, ensure_context, get_address, find_function_by_name):
    ctx = ensure_context()
    address_text = params.get("address")
    name = params.get("name")
    if address_text:
        address = get_address(ctx, address_text)
        function = ctx.function_manager.getFunctionContaining(address)
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
    else:
        if not name:
            raise ValueError("address or name is required")
        function = find_function_by_name(ctx, name)
        if function is None:
            raise LookupError("Function not found: %s" % name)
    return {
        "name": function.getName(),
        "entry": str(function.getEntryPoint()),
    }
