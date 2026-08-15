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
        raise ValueError("name is required")
    category = params.get("category")
    size = to_int(params.get("size"), 0)
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("members must be a list")

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
        raise ValueError("struct_name is required")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("members must be a list")

    def _update():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("Struct not found: %s" % struct_name)
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
        raise ValueError("struct_name is required")
    category = params.get("category")

    def _clear():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("Struct not found: %s" % struct_name)
        delete_all = getattr(struct, "deleteAll", None)
        if callable(delete_all):
            delete_all()
        else:
            num_components = safe_call(struct, "getNumComponents")
            if num_components is None:
                num_components = len(list(iter_items(struct.getComponents())))
            for ordinal in range(int(num_components) - 1, -1, -1):
                struct.delete(ordinal)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Clear struct", _clear)
    return describe_struct(struct_dt)


def remove_struct_members(params, *, ensure_context, txn, get_struct_datatype, dt_manager, describe_struct):
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_name is required")
    category = params.get("category")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("members must be a list")

    def _update():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("Struct not found: %s" % struct_name)
        target_names = set(members)
        ordinals = [
            component.getOrdinal()
            for component in list(struct.getComponents())
            if component.getFieldName() in target_names
        ]
        for ordinal in sorted(ordinals, reverse=True):
            struct.delete(ordinal)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Remove struct members", _update)
    return describe_struct(struct_dt)


def delete_struct(params, *, ensure_context, txn, get_struct_datatype, dt_manager, describe_struct):
    ctx = ensure_context()
    struct_name = params.get("struct_name") or params.get("name")
    if not struct_name:
        raise ValueError("struct_name is required")
    category = params.get("category")

    def _delete():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("Struct not found: %s" % struct_name)
        info = describe_struct(struct)
        if not bool(dt_manager(ctx).remove(struct)):
            raise RuntimeError("Failed to delete struct: %s" % struct_name)
        return info

    deleted = txn(ctx, "Delete struct", _delete)
    return {"deleted": True, "data_type": deleted}


def rename_data_type(
    params,
    *,
    ensure_context,
    txn,
    dt_manager,
    category_path,
    find_data_type_by_name,
    describe_data_type,
):
    ctx = ensure_context()
    name = params.get("name")
    new_name = params.get("new_name") or params.get("newName")
    category = params.get("category")
    if not name or not new_name:
        raise ValueError("name and new_name are required")

    def _rename():
        manager = dt_manager(ctx)
        data_type = None
        if category:
            data_type = manager.getDataType(category_path(category), name)
        if data_type is None:
            data_type = find_data_type_by_name(manager, name)
        if data_type is None:
            raise LookupError("Data type not found: %s" % name)
        data_type.setName(new_name)
        return describe_data_type(data_type)

    return txn(ctx, "Rename data type", _rename)


def list_data_types(params, *, ensure_context, to_int, dt_manager, collect, iter_items, safe_call, describe_data_type):
    ctx = ensure_context()
    offset = to_int(params.get("offset"), 0)
    limit = to_int(params.get("limit"), 100)
    if limit <= 0:
        return []
    if offset < 0:
        offset = 0
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
        raise ValueError("address and data_type are required")
    address = get_address(ctx, address_text)
    data_type = parse_data_type(ctx, data_type_text)
    clear_mode = parse_clear_data_mode(clear_mode_text)

    def _apply():
        created = data_utilities.createData(ctx.program, address, data_type, length, clear_mode)
        if created is None:
            raise RuntimeError("Failed to set global data type")
        return True

    txn(ctx, "Set global data type", _apply)
    return {"address": address_text, "data_type": data_type_text, "clear_mode": str(clear_mode)}
