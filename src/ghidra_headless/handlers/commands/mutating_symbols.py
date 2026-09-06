"""Mutating symbol/comment/prototype commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.read_only_memory_data import _bookmark_to_dict, validate_hex_payload_size


def rename_function(params, *, ensure_context, get_address, find_function_by_name, txn, source_type):
    ctx = ensure_context()
    address_text = params.get("address")
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not new_name:
        raise ValueError("newName is required")
    if address_text:
        address = get_address(ctx, address_text)
        function = ctx.function_manager.getFunctionContaining(address)
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
    else:
        if not old_name:
            raise ValueError("address or oldName is required")
        function = find_function_by_name(ctx, old_name)
        if function is None:
            raise LookupError("Function not found: %s" % old_name)

    def _rename():
        function.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename function", _rename)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def rename_data(params, *, ensure_context, get_address, txn, source_type):
    ctx = ensure_context()
    address_text = params.get("address")
    new_name = params.get("newName")
    if not new_name:
        raise ValueError("newName is required")
    address = get_address(ctx, address_text)
    if ctx.function_manager.getFunctionAt(address) is not None:
        raise ValueError("Address is a function entry; use rename_function instead")
    symbol = ctx.symbol_table.getPrimarySymbol(address)
    if symbol is None:
        raise LookupError("No data symbol at address: %s" % address_text)

    def _rename():
        symbol.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename data", _rename)
    return {"name": symbol.getName(), "address": str(symbol.getAddress())}


def _resolve_function(ctx, address_text, name, *, get_address, find_function_by_name):
    """Find a function by address (wins) or by name; raise when neither resolves."""
    if address_text:
        function = ctx.function_manager.getFunctionContaining(get_address(ctx, address_text))
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
        return function
    if not name:
        raise ValueError("function address or function name is required")
    function = find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("Function not found: %s" % name)
    return function


def rename_variable(
    params,
    *,
    ensure_context,
    get_address,
    find_function_by_name,
    decompile_high_function,
    requires_full_param_commit,
    high_function_db_util,
    txn,
    source_type,
):
    ctx = ensure_context()
    function_name = params.get("functionName")
    function_address = params.get("functionAddress")
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not old_name or not new_name:
        raise ValueError("oldName and newName are required")
    if not function_name and not function_address:
        raise ValueError("functionName or functionAddress is required")
    function = _resolve_function(
        ctx,
        function_address,
        function_name,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    )

    if old_name == new_name:
        return {"name": new_name}

    # Prefer updating high-level symbols (locals and parameters) first.
    high_symbol = None
    high_function = None
    try:
        high_function = decompile_high_function(ctx, function)
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
                    raise ValueError("Variable with the same name already exists: %s" % new_name)
                if symbol_name == old_name:
                    high_symbol = symbol
            if high_symbol is not None:

                def _rename_high():
                    if requires_full_param_commit(high_symbol, high_function):
                        high_function_db_util.commitParamsToDatabase(
                            high_function,
                            False,
                            high_function_db_util.ReturnCommitOption.NO_COMMIT,
                            function.getSignatureSource(),
                        )
                    high_function_db_util.updateDBVariable(
                        high_symbol,
                        new_name,
                        None,
                        source_type.USER_DEFINED,
                    )
                    return True

                txn(ctx, "Rename variable", _rename_high)
                return {"name": new_name}

    # Fallback: update locals and parameters directly in the DB.
    target = None
    for local in function.getLocalVariables():
        local_name = local.getName()
        if local_name == new_name and local_name != old_name:
            raise ValueError("Variable with the same name already exists: %s" % new_name)
        if local_name == old_name:
            target = local

    if target is None:
        for param in function.getParameters():
            param_name = param.getName()
            if param_name == new_name and param_name != old_name:
                raise ValueError("Variable with the same name already exists: %s" % new_name)
            if param_name == old_name:
                target = param
                break

    if target is None:
        raise LookupError("Variable not found: %s" % old_name)

    def _rename():
        target.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename variable", _rename)
    return {"name": target.getName()}


COMMENT_KINDS = {
    "pre": "PRE_COMMENT",  # shown above the line in the listing and in the decompiler
    "eol": "EOL_COMMENT",  # end-of-line comment in the listing
    "post": "POST_COMMENT",
    "plate": "PLATE_COMMENT",  # function header block
    "repeatable": "REPEATABLE_COMMENT",
}


def set_comment(params, *, ensure_context, get_address, txn, code_unit):
    """Set (or clear with an empty string) one comment kind at an address."""
    ctx = ensure_context()
    address_text = params.get("address")
    comment = params.get("comment", "")
    kind = str(params.get("kind") or "").strip().lower()
    if kind not in COMMENT_KINDS:
        raise ValueError("kind must be one of: %s" % ", ".join(sorted(COMMENT_KINDS)))
    comment_type = getattr(code_unit, COMMENT_KINDS[kind])
    address = get_address(ctx, address_text)

    def _apply():
        ctx.listing.setComment(address, comment_type, comment)
        return True

    txn(ctx, "Set %s comment" % kind, _apply)
    return {"address": address_text, "kind": kind, "comment": comment}


def set_function_prototype(
    params,
    *,
    ensure_context,
    get_address,
    find_function_by_name,
    build_signature_parser,
    safe_call,
    apply_function_signature_cmd,
    txn,
    source_type,
):
    ctx = ensure_context()
    address_text = params.get("function_address")
    function_name = params.get("function_name")
    prototype = params.get("prototype")
    if not prototype:
        raise ValueError("prototype is required")
    if not address_text and not function_name:
        raise ValueError("function_address or function_name is required")
    function = _resolve_function(
        ctx,
        address_text,
        function_name,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    )

    def _apply():
        parser = build_signature_parser(ctx)
        base_signature = safe_call(function, "getSignature")
        try:
            signature = parser.parse(base_signature, prototype)
        except TypeError:
            signature = parser.parse(None, prototype)
        if signature is None:
            raise ValueError("Failed to parse function prototype: %s" % prototype)

        command = apply_function_signature_cmd(function.getEntryPoint(), signature, source_type.USER_DEFINED)
        if not command.applyTo(ctx.program, ctx.monitor()):
            status_msg = safe_call(command, "getStatusMsg")
            if status_msg:
                raise RuntimeError("Failed to apply function prototype: %s" % status_msg)
            raise RuntimeError("Failed to apply function prototype")
        return True

    txn(ctx, "Set function prototype", _apply)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def set_local_variable_type(
    params,
    *,
    ensure_context,
    get_address,
    find_function_by_name,
    parse_data_type,
    decompile_high_function,
    requires_full_param_commit,
    high_function_db_util,
    txn,
    source_type,
):
    ctx = ensure_context()
    address_text = params.get("function_address")
    function_name = params.get("function_name")
    variable_name = params.get("variable_name")
    type_text = params.get("new_type")
    if not variable_name or not type_text:
        raise ValueError("variable_name and new_type are required")
    if not address_text and not function_name:
        raise ValueError("function_address or function_name is required")
    function = _resolve_function(
        ctx,
        address_text,
        function_name,
        get_address=get_address,
        find_function_by_name=find_function_by_name,
    )

    data_type = parse_data_type(ctx, type_text)

    def _apply():
        high_function = None
        try:
            high_function = decompile_high_function(ctx, function)
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
                    if requires_full_param_commit(target_symbol, high_function):
                        high_function_db_util.commitParamsToDatabase(
                            high_function,
                            False,
                            high_function_db_util.ReturnCommitOption.NO_COMMIT,
                            function.getSignatureSource(),
                        )
                    high_function_db_util.updateDBVariable(
                        target_symbol,
                        target_symbol.getName(),
                        data_type,
                        source_type.USER_DEFINED,
                    )
                    return True
        for local in function.getLocalVariables():
            if local.getName() == variable_name:
                local.setDataType(data_type, source_type.USER_DEFINED)
                return True
        for param in function.getParameters():
            if param.getName() == variable_name:
                param.setDataType(data_type, source_type.USER_DEFINED)
                return True
        raise LookupError("Variable not found: %s" % variable_name)

    txn(ctx, "Set local variable type", _apply)
    return {"function": function.getName(), "variable": variable_name, "type": type_text}


def set_bytes(params, *, ensure_context, get_address, decode_hex_bytes, txn):
    address_text = params.get("address")
    bytes_text = params.get("bytes")
    if not address_text or not bytes_text:
        raise ValueError("address and bytes are required")
    validate_hex_payload_size(bytes_text)
    ctx = ensure_context()
    data = decode_hex_bytes(bytes_text)
    if not data:
        raise ValueError("bytes must contain at least one byte")
    address = get_address(ctx, address_text)

    def _apply():
        ctx.program.getMemory().setBytes(address, data)
        return True

    txn(ctx, "Set bytes", _apply)
    return {"address": address_text, "length": len(data)}


def create_function(params, *, ensure_context, get_address, txn):
    ctx = ensure_context()
    address_text = params.get("address")
    name = params.get("name")
    if not address_text:
        raise ValueError("address is required")
    address = get_address(ctx, address_text)
    existing = ctx.function_manager.getFunctionAt(address)
    if existing is not None:
        return {
            "name": existing.getName(),
            "entry": str(existing.getEntryPoint()),
            "created": False,
            "already_exists": True,
        }
    containing = ctx.function_manager.getFunctionContaining(address)
    if containing is not None:
        raise ValueError("Address is already inside function: %s" % containing.getName())

    def _create():
        if ctx.listing.getInstructionAt(address) is None:
            ctx.flat_api.disassemble(address)
        function = ctx.flat_api.createFunction(address, name)
        if function is None:
            function = ctx.function_manager.getFunctionAt(address)
        if function is None:
            raise RuntimeError("Failed to create function at address: %s" % address_text)
        return function

    function = txn(ctx, "Create function", _create)
    return {
        "name": function.getName(),
        "entry": str(function.getEntryPoint()),
        "created": True,
        "already_exists": False,
    }


def delete_function(params, *, ensure_context, get_address, txn):
    ctx = ensure_context()
    address_text = params.get("address")
    if not address_text:
        raise ValueError("address is required")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionAt(address)
    if function is None:
        function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("Function not found: %s" % address_text)
    name = function.getName()
    entry = function.getEntryPoint()

    def _delete():
        if not bool(ctx.function_manager.removeFunction(entry)):
            raise RuntimeError("Failed to delete function at address: %s" % entry)
        return True

    txn(ctx, "Delete function", _delete)
    return {"name": name, "entry": str(entry), "deleted": True}


def analyze_program(params, *, ensure_context, analyze_program_impl):
    """Run auto-analysis; ``force`` re-runs it on an already analyzed program."""
    ctx = ensure_context()
    force = bool(params.get("force", False))
    analyzed = analyze_program_impl(ctx, force=force)
    return {"analyzed": bool(analyzed), "forced": force}


def add_bookmark(params, *, ensure_context, get_address, txn):
    ctx = ensure_context()
    address_text = params.get("address")
    category = params.get("category")
    comment = params.get("comment", "")
    bookmark_type = params.get("type")
    if not address_text or not category or bookmark_type is None:
        raise ValueError("address, category, and type are required")

    address = get_address(ctx, address_text)
    manager = ctx.program.getBookmarkManager()

    def _apply():
        manager.setBookmark(address, bookmark_type, category, comment)
        return True

    txn(ctx, "Add bookmark", _apply)
    return {
        "address": address_text,
        "category": category,
        "type": bookmark_type,
        "comment": comment,
    }


def delete_bookmark(params, *, ensure_context, get_address, txn, iter_items):
    ctx = ensure_context()
    bookmark_id = params.get("id")
    address_text = params.get("address")
    bookmark_type = params.get("type")
    category = params.get("category")
    comment = params.get("comment")
    manager = ctx.program.getBookmarkManager()

    if bookmark_id is None and not address_text:
        raise ValueError("id or address is required")
    if bookmark_id is None and (not bookmark_type or not category):
        raise ValueError("type and category are required when deleting by address")

    def _candidate_bookmarks():
        if bookmark_id is not None:
            bookmark = manager.getBookmark(int(bookmark_id))
            return [] if bookmark is None else [bookmark]
        address = get_address(ctx, address_text)
        exact = manager.getBookmark(address, bookmark_type, category)
        if exact is not None:
            return [exact]
        return list(iter_items(manager.getBookmarks(address, bookmark_type)))

    candidates = _candidate_bookmarks()
    matched = []
    for bookmark in candidates:
        if bookmark_type and bookmark.getTypeString() != bookmark_type:
            continue
        if category and bookmark.getCategory() != category:
            continue
        if comment is not None and bookmark.getComment() != comment:
            continue
        matched.append(bookmark)
    if not matched:
        raise LookupError("Bookmark not found")
    deleted = [_bookmark_to_dict(bookmark) for bookmark in matched]

    def _delete():
        for bookmark in matched:
            manager.removeBookmark(bookmark)
        return True

    txn(ctx, "Delete bookmark", _delete)
    return {"deleted": len(deleted), "bookmarks": deleted}
