"""Read-only xrefs commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def get_xrefs_to(params, *, ensure_context, get_address, to_int, iter_items):
    ctx = ensure_context()
    address_text = params.get("address")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    address = get_address(ctx, address_text)
    references = ctx.reference_manager.getReferencesTo(address)
    items = []
    idx = 0
    for ref in iter_items(references):
        if idx >= offset:
            items.append(
                {
                    "from": str(ref.getFromAddress()),
                    "type": str(ref.getReferenceType()),
                }
            )
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_xrefs_from(params, *, ensure_context, get_address, to_int, iter_items):
    ctx = ensure_context()
    address_text = params.get("address")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    address = get_address(ctx, address_text)
    references = ctx.reference_manager.getReferencesFrom(address)
    items = []
    idx = 0
    for ref in iter_items(references):
        if idx >= offset:
            items.append(
                {
                    "to": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                }
            )
            if len(items) >= limit:
                break
        idx += 1
    return items


def get_function_xrefs(params, *, ensure_context, find_function_by_name, to_int, iter_items):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    function = find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % name)
    entry = function.getEntryPoint()
    references = ctx.reference_manager.getReferencesTo(entry)
    results = []
    idx = 0
    for ref in iter_items(references):
        if idx >= offset:
            results.append(
                {
                    "from": str(ref.getFromAddress()),
                    "type": str(ref.getReferenceType()),
                }
            )
            if len(results) >= limit:
                break
        idx += 1
    return results
