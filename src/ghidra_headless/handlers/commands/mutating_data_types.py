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


def remove_struct_members(params, *, ensure_context, txn, get_struct_datatype, dt_manager, describe_struct):
    """Remove the named members; with ``members`` omitted every member is removed."""
    ctx = ensure_context()
    struct_name = params.get("struct_name")
    if not struct_name:
        raise ValueError("struct_name is required")
    category = params.get("category")
    members = params.get("members")
    if members is not None and not isinstance(members, (list, tuple)):
        raise ValueError("members must be a list")
    remove_all = not members

    def _update():
        struct = get_struct_datatype(ctx, struct_name, category)
        if struct is None:
            raise LookupError("Struct not found: %s" % struct_name)
        target_names = set()
        for member in members or ():
            name = member.get("name") if isinstance(member, dict) else member
            if not name:
                raise ValueError("members must contain member names or {name} objects")
            target_names.add(str(name))
        ordinals = [
            component.getOrdinal()
            for component in list(struct.getComponents())
            if remove_all or component.getFieldName() in target_names
        ]
        for ordinal in sorted(ordinals, reverse=True):
            struct.delete(ordinal)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Clear struct" if remove_all else "Remove struct members", _update)
    return describe_struct(struct_dt)


def delete_data_type(
    params,
    *,
    ensure_context,
    txn,
    dt_manager,
    category_path,
    find_data_type_by_name,
    describe_data_type,
):
    """Delete any data type (struct, union, enum, typedef, ...) by name."""
    ctx = ensure_context()
    name = params.get("name")
    category = params.get("category")
    if not name:
        raise ValueError("name is required")

    def _delete():
        manager = dt_manager(ctx)
        data_type = None
        if category:
            data_type = manager.getDataType(category_path(category), name)
        if data_type is None:
            data_type = find_data_type_by_name(manager, name)
        if data_type is None:
            raise LookupError("Data type not found: %s" % name)
        info = describe_data_type(data_type)
        if not bool(manager.remove(data_type)):
            raise RuntimeError("Failed to delete data type: %s" % name)
        return info

    deleted = txn(ctx, "Delete data type", _delete)
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
    new_name = params.get("new_name")
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


ENUM_SIZES = (1, 2, 4, 8)
MAX_C_SOURCE_CHARS = 1_000_000


def _enum_value(raw):
    """Accept an int, a numeric string (0x.. allowed) or {"value", "comment"}."""
    comment = ""
    if isinstance(raw, dict):
        comment = str(raw.get("comment") or "")
        raw = raw.get("value")
    if isinstance(raw, bool) or raw is None:
        raise ValueError("enum values must be integers")
    if isinstance(raw, int):
        return int(raw), comment
    try:
        return int(str(raw).strip(), 0), comment
    except ValueError:
        raise ValueError("enum value is not an integer: %r" % (raw,))


def _normalize_enum_values(values):
    if values is None:
        return []
    if not isinstance(values, dict):
        raise ValueError("values must be an object of {name: value}")
    entries = []
    for name, raw in values.items():
        text = str(name).strip()
        if not text:
            raise ValueError("enum value names must not be empty")
        value, comment = _enum_value(raw)
        entries.append((text, value, comment))
    return entries


def create_enum(params, *, ensure_context, to_int, txn, dt_manager, category_path, enum_data_type, describe_enum):
    ctx = ensure_context()
    name = str(params.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    size = to_int(params.get("size"), 4)
    if size not in ENUM_SIZES:
        raise ValueError("size must be one of: %s" % ", ".join(str(item) for item in ENUM_SIZES))
    category = params.get("category")
    entries = _normalize_enum_values(params.get("values"))

    def _create():
        manager = dt_manager(ctx)
        enum_dt = enum_data_type(category_path(category) if category else category_path("/"), name, size)
        for value_name, value, comment in entries:
            enum_dt.add(value_name, value, comment)
        return manager.addDataType(enum_dt, None)

    created = txn(ctx, "Create enum", _create)
    return describe_enum(created)


def set_enum_values(params, *, ensure_context, txn, get_enum_datatype, describe_enum, iter_items):
    """Add or replace named values and/or remove names on an existing enum."""
    ctx = ensure_context()
    name = str(params.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    category = params.get("category")
    entries = _normalize_enum_values(params.get("values"))
    remove = params.get("remove") or []
    if isinstance(remove, (str, bytes)) or not isinstance(remove, (list, tuple)):
        raise ValueError("remove must be a list of value names")
    remove_names = [str(item).strip() for item in remove if str(item).strip()]
    if not entries and not remove_names:
        raise ValueError("values or remove is required")

    def _update():
        enum_dt = get_enum_datatype(ctx, name, category)
        if enum_dt is None:
            raise LookupError("Enum not found: %s" % name)
        existing = {str(item) for item in iter_items(enum_dt.getNames())}
        missing = [item for item in remove_names if item not in existing]
        if missing:
            raise LookupError("Enum values not found: %s" % ", ".join(missing))
        for value_name in remove_names:
            enum_dt.remove(value_name)
            existing.discard(value_name)
        for value_name, value, comment in entries:
            if value_name in existing:
                enum_dt.remove(value_name)
            enum_dt.add(value_name, value, comment)
            existing.add(value_name)
        return enum_dt

    updated = txn(ctx, "Set enum values", _update)
    return describe_enum(updated)


def parse_c_declarations(params, *, ensure_context, txn, dt_manager, iter_items):
    """Parse C declarations (structs, unions, enums, typedefs, prototypes) into the program's types."""
    ctx = ensure_context()
    source = params.get("source")
    if not source or not str(source).strip():
        raise ValueError("source is required")
    if len(str(source)) > MAX_C_SOURCE_CHARS:
        raise ValueError("source must not exceed %d characters" % MAX_C_SOURCE_CHARS)

    from ghidra.app.util.cparser.C import CParser, ParseException

    from ghidra_headless.errors import HeadlessError

    def _names(mapping):
        return sorted(str(key) for key in iter_items(mapping.keySet()))

    def _parse():
        # storeDataType=True resolves every parsed type into the program's manager;
        # the one-argument constructor only collects them in the parser.
        parser = CParser(dt_manager(ctx), True, None)
        try:
            parser.parse(str(source))
        except ParseException as exc:
            # HeadlessError keeps the parser's line/column text in the public message.
            raise HeadlessError("C_PARSE_FAILED: %s" % str(exc).strip())
        messages = str(parser.getParseMessages() or "").strip()
        if not bool(parser.didParseSucceed()):
            raise HeadlessError("C_PARSE_FAILED: %s" % (messages or "parser reported failure"))
        return {
            "composites": _names(parser.getComposites()),
            "enums": _names(parser.getEnums()),
            "typedefs": _names(parser.getTypes()),
            "functions": _names(parser.getFunctions()),
            "messages": messages or None,
        }

    result = txn(ctx, "Parse C declarations", _parse)
    result["status"] = "ok"
    return result
