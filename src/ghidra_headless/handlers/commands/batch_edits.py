"""Apply bounded annotation edits while preserving transaction outcomes."""

from ghidra_headless.errors import HeadlessError

from .mutating_symbols import COMMENT_KINDS
from .query_support import function_ref, program_metadata, program_revision

_FIELDS = {
    "rename_function": {"address": "address", "new_name": "newName"},
    "rename_data": {"address": "address", "new_name": "newName"},
    "rename_variable": {"function_address": "functionAddress", "old_name": "oldName", "new_name": "newName"},
    "set_function_prototype": {"function_address": "function_address", "prototype": "prototype"},
    "set_local_variable_type": {
        "function_address": "function_address",
        "variable_name": "variable_name",
        "new_type": "new_type",
    },
    "set_global_data_type": {"address": "address", "data_type": "data_type", "length": "length"},
    "set_comment": {"address": "address", "comment": "comment", "comment_type": "kind"},
}


def _snapshot(ctx, edit, *, after, get_address, decompile_high_function, iter_items, code_unit):
    kind = edit["kind"]
    address = get_address(ctx, edit.get("function_address") or edit.get("address"))
    if kind == "set_comment":
        comment_type = getattr(code_unit, COMMENT_KINDS[edit["comment_type"]])
        return {"address": str(address), "comment": ctx.listing.getComment(comment_type, address) or ""}
    if kind == "rename_data":
        symbol = ctx.symbol_table.getPrimarySymbol(address)
        return {"address": str(address), "name": None if symbol is None else str(symbol.getName(True))}
    if kind == "set_global_data_type":
        data = ctx.listing.getDataAt(address)
        return {"address": str(address), "type": None if data is None else str(data.getDataType().getPathName())}
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("Function not found: %s" % address)
    state = {"function": function_ref(function)}
    if kind == "set_function_prototype":
        state["prototype"] = str(function.getPrototypeString(True, True))
    if kind in {"rename_variable", "set_local_variable_type"}:
        name = (edit["new_name"] if after else edit["old_name"]) if kind == "rename_variable" else edit["variable_name"]
        high = decompile_high_function(ctx, function)
        symbol = next((s for s in iter_items(high.getLocalSymbolMap().getSymbols()) if str(s.getName()) == name), None)
        if symbol is None:
            raise LookupError("Variable not found: %s" % name)
        state["variable"] = {
            "name": name,
            "type": str(symbol.getDataType().getDisplayName()),
            "storage": str(symbol.getStorage()),
        }
    return state


def apply_edits(params, *, ensure_context, execute_edit, get_address, decompile_high_function, iter_items, code_unit):
    ctx = ensure_context()
    edits = params.get("edits")
    if not isinstance(edits, list) or not 1 <= len(edits) <= 100:
        raise ValueError("edits must contain between 1 and 100 operations")
    for edit in edits:
        if not isinstance(edit, dict) or edit.get("kind") not in _FIELDS:
            raise ValueError("unsupported edit kind")
        if set(edit) - {"kind", *_FIELDS[edit["kind"]]}:
            raise ValueError("unknown edit fields")
    previous_revision = program_revision(ctx)
    expected = params.get("expected_revision")
    if expected is not None and expected != previous_revision:
        raise HeadlessError("SESSION_CHANGED: program changed; read current state before applying edits")
    atomic = params.get("atomic", True)
    dry_run = params.get("dry_run", False)
    outer = ctx.program.startTransaction("Apply annotation edits") if atomic or dry_run else None
    results = []
    completed = False
    try:
        for index, edit in enumerate(edits):
            result = {"index": index, "kind": edit["kind"]}
            # An item includes both the mutation and its verified after-state.
            # In non-atomic mode a failed item rolls back without losing prior items.
            item_transaction = ctx.program.startTransaction("Annotation edit") if outer is None else None
            item_ok = False
            try:
                snapshot_args = dict(
                    get_address=get_address,
                    decompile_high_function=decompile_high_function,
                    iter_items=iter_items,
                    code_unit=code_unit,
                )
                result["before"] = _snapshot(ctx, edit, after=False, **snapshot_args)
                args = {
                    internal: edit[public]
                    for public, internal in _FIELDS[edit["kind"]].items()
                    if edit.get(public) is not None
                }
                execute_edit(edit["kind"], args)
                result["after"] = _snapshot(ctx, edit, after=True, **snapshot_args)
                result["status"] = "applied"
                item_ok = True
            except Exception as exc:
                result["status"] = "failed"
                result["error"] = {"code": getattr(exc, "code", "EDIT_FAILED"), "message": str(exc)}
            finally:
                if item_transaction is not None:
                    ctx.program.endTransaction(item_transaction, item_ok)
                    if not item_ok:
                        ctx.reset_decompiler()
            results.append(result)
            if not item_ok and atomic:
                break
        completed = len(results) == len(edits) and all(r["status"] == "applied" for r in results)
    finally:
        if outer is not None:
            ctx.program.endTransaction(outer, completed and not dry_run)
            if dry_run or not completed:
                ctx.reset_decompiler()
    rolled_back = outer is not None and (dry_run or not completed)
    if rolled_back:
        for result in results:
            if result["status"] == "applied":
                result["status"] = "simulated" if dry_run else "rolled_back"
    for index in range(len(results), len(edits)):
        results.append({"index": index, "kind": edits[index]["kind"], "status": "not_attempted"})
    count = sum(r["status"] == "applied" for r in results)
    status = (
        ("dry_run" if completed else "dry_run_failed")
        if dry_run
        else ("applied" if completed else "rolled_back" if atomic else "partial")
    )
    return {
        **program_metadata(ctx),
        "previous_revision": previous_revision,
        "status": status,
        "atomic": atomic,
        "dry_run": dry_run,
        "applied_count": count,
        "results": results,
    }
