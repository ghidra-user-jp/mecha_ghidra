"""Mutating class commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def create_class(
    params,
    *,
    ensure_context,
    txn,
    resolve_namespace,
    find_ghidra_class,
    source_type,
    build_class_category_path,
    get_struct_datatype,
    category_path,
    structure_data_type,
    dt_manager,
    apply_members_to_struct,
    safe_call,
    describe_struct,
):
    ctx = ensure_context()
    class_name = params.get("name")
    if not class_name:
        raise ValueError("nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _create():
        parent = resolve_namespace(ctx, parent_namespace)
        if parent is None:
            raise LookupError("親名前空間が見つかりません: %s" % parent_namespace)
        existing_class = find_ghidra_class(ctx, class_name, parent)
        if existing_class is not None:
            raise ValueError("クラスが既に存在します: %s" % class_name)

        class_namespace = ctx.symbol_table.createClass(parent, class_name, source_type.USER_DEFINED)
        category = build_class_category_path(class_namespace)
        struct = get_struct_datatype(ctx, class_name, category)
        if struct is None:
            struct = structure_data_type(category_path(category), class_name, 0)
            struct = dt_manager(ctx).addDataType(struct, None)
        apply_members_to_struct(ctx, struct, members)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return class_namespace, struct

    class_namespace, struct_dt = txn(ctx, "Create class", _create)
    namespace_name = safe_call(class_namespace, "getName", True)
    if not namespace_name:
        namespace_name = class_namespace.getName()
    return {
        "class": namespace_name,
        "struct": describe_struct(struct_dt),
    }


def add_class_members(
    params,
    *,
    ensure_context,
    txn,
    ensure_class_struct,
    apply_members_to_struct,
    dt_manager,
    describe_struct,
):
    ctx = ensure_context()
    class_name = params.get("class_name")
    if not class_name:
        raise ValueError("class_nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        _, struct = ensure_class_struct(
            ctx,
            class_name,
            parent_namespace,
            create_class_if_missing=False,
            create_struct_if_missing=False,
        )
        apply_members_to_struct(ctx, struct, members)
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Add class members", _update)
    return describe_struct(struct_dt)


def remove_class_members(params, *, ensure_context, txn, ensure_class_struct, dt_manager, describe_struct):
    ctx = ensure_context()
    class_name = params.get("class_name")
    if not class_name:
        raise ValueError("class_nameが必要です")
    parent_namespace = params.get("parent_namespace")
    members = params.get("members") or []
    if not isinstance(members, (list, tuple)):
        raise ValueError("membersはリストで指定してください")

    def _update():
        _, struct = ensure_class_struct(
            ctx,
            class_name,
            parent_namespace,
            create_class_if_missing=False,
            create_struct_if_missing=False,
        )
        target_names = set(members)
        for component in list(struct.getComponents()):
            if component.getFieldName() in target_names:
                struct.delete(component.getOrdinal())
        dt_manager(ctx).replaceDataType(struct, struct, True)
        return struct

    struct_dt = txn(ctx, "Remove class members", _update)
    return describe_struct(struct_dt)
