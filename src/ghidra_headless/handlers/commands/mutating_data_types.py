"""Mutating data-type commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def create_struct(
    params,
    *,
    ensure_context,
    to_int,
    txn,
    dt_manager,
    category_path,
    structure_data_type,
    parse_data_type,
    component_length,
    describe_struct,
):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    size = to_int(params.get("size"), 0)
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _create():
        manager = dt_manager(ctx)
        struct = structure_data_type(category_path(category) if category else category_path("/"), name, size)
        struct = manager.addDataType(struct, None)
        for member in members:
            data_type = parse_data_type(ctx, member.get("type"))
            field_name = member.get("name", "")
            comment = member.get("comment", "")
            offset = member.get("offset")
            length = component_length(data_type)
            if offset is not None:
                struct.replaceAtOffset(int(offset), data_type, length, field_name, comment)
            else:
                struct.add(data_type, length, field_name, comment)
        manager.replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Create struct", _create)
    return describe_struct(struct_dt)


def add_struct_members(
    params,
    *,
    ensure_context,
    txn,
    get_struct_datatype,
    parse_data_type,
    component_length,
    dt_manager,
    describe_struct,
):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        for member in members:
            data_type = parse_data_type(ctx, member.get("type"))
            field_name = member.get("name", "")
            comment = member.get("comment", "")
            offset = member.get("offset")
            length = component_length(data_type)
            if offset is not None:
                struct.replaceAtOffset(int(offset), data_type, length, field_name, comment)
            else:
                struct.add(data_type, length, field_name, comment)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Add struct members", _update)
    return describe_struct(struct_dt)


def clear_struct(
    params,
    *,
    ensure_context,
    txn,
    get_struct_datatype,
    safe_call,
    iter_items,
    dt_manager,
    describe_struct,
):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")

    def _clear():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        cleared = False
        clear_components = getattr(struct, "clearComponents", None)
        if callable(clear_components):
            clear_components()
            cleared = True
        else:
            num_components = safe_call(struct, "getNumComponents")
            if num_components is None:
                num_components = len(list(iter_items(struct.getComponents())))
            for ordinal in range(int(num_components) - 1, -1, -1):
                struct.delete(ordinal)
                cleared = True
        if not cleared:
            raise RuntimeError("構造体メンバーのクリアに失敗しました")
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Clear struct", _clear)
    return describe_struct(struct_dt)


def create_enum(
    params,
    *,
    ensure_context,
    to_int,
    txn,
    category_path,
    enum_data_type,
    to_int_auto,
    dt_manager,
    describe_enum,
):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    category = params.get("category")
    size = to_int(params.get("size"), 4)
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _create():
        enum_dt = enum_data_type(category_path(category) if category else category_path("/"), name, size)
        for value in values:
            enum_dt.add(value.get("name"), to_int_auto(value.get("value")), value.get("comment"))
        dt_manager(ctx).addDataType(enum_dt, None)
        return enum_dt

    enum_dt = txn(ctx, "Create enum", _create)
    return describe_enum(enum_dt)


def add_enum_values(params, *, ensure_context, txn, get_enum_datatype, to_int_auto, dt_manager, describe_enum):
    ctx = ensure_context()
    name = params.get("enum_name")
    if not name:
        raise ValueError("enum_nameが必要です")
    category = params.get("category")
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _update():
        enum_dt = get_enum_datatype(ctx, name, category)
        if enum_dt is None:
            raise LookupError("列挙体が見つかりません: %s" % name)
        for value in values:
            enum_dt.add(value.get("name"), to_int_auto(value.get("value")), value.get("comment"))
        dt_manager(ctx).replaceDataType(enum_dt, enum_dt, True)
        return enum_dt

    enum_dt = txn(ctx, "Add enum values", _update)
    return describe_enum(enum_dt)


def remove_enum_values(params, *, ensure_context, txn, get_enum_datatype, dt_manager, describe_enum):
    ctx = ensure_context()
    name = params.get("enum_name")
    if not name:
        raise ValueError("enum_nameが必要です")
    category = params.get("category")
    values = params.get("values") or []
    if not isinstance(values, (list, tuple)):
        raise ValueError("valuesはリストで指定してください")

    def _update():
        enum_dt = get_enum_datatype(ctx, name, category)
        if enum_dt is None:
            raise LookupError("列挙体が見つかりません: %s" % name)
        for value in values:
            enum_dt.remove(value)
        dt_manager(ctx).replaceDataType(enum_dt, enum_dt, True)
        return enum_dt

    enum_dt = txn(ctx, "Remove enum values", _update)
    return describe_enum(enum_dt)


def remove_struct_members(params, *, ensure_context, txn, get_struct_datatype, dt_manager, describe_struct):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_nameが必要です")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("構造体が見つかりません: %s" % struct_name)
        target_names = set(members)
        for component in list(struct.getComponents()):
            if component.getFieldName() in target_names:
                struct.delete(component.getOrdinal())
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Remove struct members", _update)
    return describe_struct(struct_dt)


def set_global_data_type(
    params,
    *,
    ensure_context,
    to_int,
    get_address,
    parse_data_type,
    parse_clear_data_mode,
    txn,
    data_utilities,
):
    ctx = ensure_context()
    address_text = params.get("address")
    data_type_text = params.get("data_type")
    length = to_int(params.get("length"), -1)
    clear_mode_text = params.get("clear_mode")
    if not address_text or not data_type_text:
        raise ValueError("addressとdata_typeは必須です")
    address = get_address(ctx, address_text)
    data_type = parse_data_type(ctx, data_type_text)
    clear_mode = parse_clear_data_mode(clear_mode_text)

    def _apply():
        created = data_utilities.createData(ctx.program, address, data_type, length, clear_mode)
        if created is None:
            raise RuntimeError("データ型の設定に失敗しました")
        return True

    txn(ctx, "Set global data type", _apply)
    return {"address": address_text, "data_type": data_type_text, "clear_mode": str(clear_mode)}
