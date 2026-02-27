"""Mutating symbol/comment/prototype commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def rename_function(params, *, ensure_context, find_function_by_name, txn, source_type):
    ctx = ensure_context()
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not old_name or not new_name:
        raise ValueError("oldNameとnewNameが必要です")
    function = find_function_by_name(ctx, old_name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % old_name)

    def _rename():
        function.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename function", _rename)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def rename_function_by_address(params, *, ensure_context, get_address, txn, source_type):
    ctx = ensure_context()
    address_text = params.get("function_address")
    new_name = params.get("new_name") or params.get("newName")
    if not address_text or not new_name:
        raise ValueError("function_addressとnew_nameは必須です")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("アドレスに対応する関数が見つかりません: %s" % address_text)

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
        raise ValueError("newNameが必要です")
    address = get_address(ctx, address_text)
    symbol = ctx.symbol_table.getPrimarySymbol(address)
    if symbol is None:
        raise LookupError("アドレスにデータシンボルが存在しません: %s" % address_text)

    def _rename():
        symbol.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename data", _rename)
    return {"name": symbol.getName(), "address": str(symbol.getAddress())}


def rename_variable(
    params,
    *,
    ensure_context,
    find_function_by_name,
    decompile_high_function,
    requires_full_param_commit,
    high_function_db_util,
    txn,
    source_type,
):
    ctx = ensure_context()
    function_name = params.get("functionName")
    old_name = params.get("oldName")
    new_name = params.get("newName")
    if not function_name or not old_name or not new_name:
        raise ValueError("functionName, oldName, newNameが必要です")

    function = find_function_by_name(ctx, function_name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % function_name)

    if old_name == new_name:
        return {"name": new_name}

    # 高レベルシンボル（ローカル＋引数）を優先して更新する。
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
                    raise ValueError("同名の変数が既に存在します: %s" % new_name)
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
        target.setName(new_name, source_type.USER_DEFINED)
        return True

    txn(ctx, "Rename variable", _rename)
    return {"name": target.getName()}


def set_decompiler_comment(params, *, ensure_context, get_address, txn, code_unit):
    ctx = ensure_context()
    address_text = params.get("address")
    comment = params.get("comment", "")
    address = get_address(ctx, address_text)

    def _apply():
        ctx.listing.setComment(address, code_unit.PRE_COMMENT, comment)
        return True

    txn(ctx, "Set decompiler comment", _apply)
    return {"address": address_text, "comment": comment}


def set_disassembly_comment(params, *, ensure_context, get_address, txn, code_unit):
    ctx = ensure_context()
    address_text = params.get("address")
    comment = params.get("comment", "")
    address = get_address(ctx, address_text)

    def _apply():
        ctx.listing.setComment(address, code_unit.EOL_COMMENT, comment)
        return True

    txn(ctx, "Set disassembly comment", _apply)
    return {"address": address_text, "comment": comment}


def set_function_prototype(
    params,
    *,
    ensure_context,
    get_address,
    build_signature_parser,
    safe_call,
    apply_function_signature_cmd,
    txn,
    source_type,
):
    ctx = ensure_context()
    address_text = params.get("function_address")
    prototype = params.get("prototype")
    if not address_text or not prototype:
        raise ValueError("function_addressとprototypeは必須です")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)

    def _apply():
        parser = build_signature_parser(ctx)
        base_signature = safe_call(function, "getSignature")
        try:
            signature = parser.parse(base_signature, prototype)
        except TypeError:
            signature = parser.parse(None, prototype)
        if signature is None:
            raise ValueError("関数プロトタイプを解析できません: %s" % prototype)

        command = apply_function_signature_cmd(function.getEntryPoint(), signature, source_type.USER_DEFINED)
        if not command.applyTo(ctx.program, ctx.monitor()):
            status_msg = safe_call(command, "getStatusMsg")
            if status_msg:
                raise RuntimeError("関数プロトタイプの適用に失敗しました: %s" % status_msg)
            raise RuntimeError("関数プロトタイプの適用に失敗しました")
        return True

    txn(ctx, "Set function prototype", _apply)
    return {"name": function.getName(), "entry": str(function.getEntryPoint())}


def set_local_variable_type(
    params,
    *,
    ensure_context,
    get_address,
    parse_data_type,
    decompile_high_function,
    requires_full_param_commit,
    high_function_db_util,
    txn,
    source_type,
):
    ctx = ensure_context()
    address_text = params.get("function_address")
    variable_name = params.get("variable_name")
    type_text = params.get("new_type")
    if not address_text or not variable_name or not type_text:
        raise ValueError("function_address, variable_name, new_typeは必須です")

    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)

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
        raise LookupError("変数が見つかりません: %s" % variable_name)

    txn(ctx, "Set local variable type", _apply)
    return {"function": function.getName(), "variable": variable_name, "type": type_text}


def set_bytes(params, *, ensure_context, get_address, decode_hex_bytes, txn):
    ctx = ensure_context()
    address_text = params.get("address")
    bytes_text = params.get("bytes")
    if not address_text or not bytes_text:
        raise ValueError("addressとbytesは必須です")
    address = get_address(ctx, address_text)
    data = decode_hex_bytes(bytes_text)

    def _apply():
        ctx.program.getMemory().setBytes(address, data)
        return True

    txn(ctx, "Set bytes", _apply)
    return {"address": address_text, "length": len(data)}


def add_bookmark(params, *, ensure_context, get_address, txn):
    ctx = ensure_context()
    address_text = params.get("address")
    category = params.get("category")
    comment = params.get("comment", "")
    bookmark_type = params.get("type")
    _bookmark_format = params.get("format", "json")
    if not address_text or not category or bookmark_type is None:
        raise ValueError("address, category, type は必須です")

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
