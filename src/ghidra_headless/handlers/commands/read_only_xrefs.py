"""Read-only xrefs commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.pagination import normalize_pagination


def _containing_function_name(ctx, address):
    manager = getattr(ctx, "function_manager", None)
    if manager is None or address is None:
        return None
    function = manager.getFunctionContaining(address)
    return None if function is None else str(function.getName())


def _incoming_references(ctx, address, *, offset, limit, iter_items):
    references = ctx.reference_manager.getReferencesTo(address)
    items = []
    idx = 0
    for ref in iter_items(references):
        if idx >= offset:
            from_address = ref.getFromAddress()
            items.append(
                {
                    "from": str(from_address),
                    "from_function": _containing_function_name(ctx, from_address),
                    "type": str(ref.getReferenceType()),
                }
            )
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_xrefs_to(params, *, ensure_context, get_address, to_int, iter_items):
    ctx = ensure_context()
    address_text = params.get("address")
    offset, limit = normalize_pagination(params, to_int, 100)
    address = get_address(ctx, address_text)
    return _incoming_references(ctx, address, offset=offset, limit=limit, iter_items=iter_items)


def get_xrefs_from(params, *, ensure_context, get_address, to_int, iter_items):
    ctx = ensure_context()
    address_text = params.get("address")
    offset, limit = normalize_pagination(params, to_int, 100)
    address = get_address(ctx, address_text)
    references = ctx.reference_manager.getReferencesFrom(address)
    items = []
    idx = 0
    for ref in iter_items(references):
        if idx >= offset:
            to_address = ref.getToAddress()
            items.append(
                {
                    "to": str(to_address),
                    "to_function": _containing_function_name(ctx, to_address),
                    "type": str(ref.getReferenceType()),
                }
            )
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_function_xrefs(params, *, ensure_context, get_address, find_function_by_name, to_int, iter_items):
    """List references to a function's entry point (its callers); address wins over name."""
    ctx = ensure_context()
    address_text = params.get("address")
    name = params.get("name")
    offset, limit = normalize_pagination(params, to_int, 100)
    if address_text:
        function = ctx.function_manager.getFunctionContaining(get_address(ctx, address_text))
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
    else:
        if not name:
            raise ValueError("address or name is required")
        function = find_function_by_name(ctx, name)
        if function is None:
            raise LookupError("Function not found: %s" % name)
    return _incoming_references(ctx, function.getEntryPoint(), offset=offset, limit=limit, iter_items=iter_items)
