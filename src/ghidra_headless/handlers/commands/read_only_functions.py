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

    def _to_entry(namespace):
        return {
            "name": namespace.getName(True),
            "isClass": bool(safe_call(namespace, "isClass")) or False,
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


def get_function_by_address(params, *, ensure_context, get_address):
    ctx = ensure_context()
    address_text = params.get("address")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("Function not found: %s" % address_text)
    return {
        "name": function.getName(),
        "entry": str(function.getEntryPoint()),
    }
