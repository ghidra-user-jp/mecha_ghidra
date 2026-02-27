"""Read-only decompile/disassembly commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def decompile_function(params, *, ensure_context, find_function_by_name, decompile_function_object):
    ctx = ensure_context()
    name = params.get("name")
    if not name:
        raise ValueError("nameが必要です")
    function = find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % name)

    return decompile_function_object(ctx, function)


def decompile_function_by_address(params, *, ensure_context, get_address, decompile_function_object):
    ctx = ensure_context()
    address_text = params.get("address")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("アドレスに対応する関数が見つかりません: %s" % address_text)
    return decompile_function_object(ctx, function)


def disassemble_function(params, *, ensure_context, get_address, iter_items, code_unit):
    ctx = ensure_context()
    address_text = params.get("address")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)
    body = function.getBody()
    instructions = ctx.listing.getInstructions(body, True)
    lines = []
    for inst in iter_items(instructions):
        operand_parts = []
        try:
            operand_count = inst.getNumOperands()
        except Exception:
            operand_count = 0

        for operand_index in range(operand_count):
            try:
                operand_repr = inst.getDefaultOperandRepresentation(operand_index)
            except Exception:
                operand_repr = None
            if operand_repr:
                operand_parts.append(str(operand_repr))

        operands = ", ".join(operand_parts)
        comment = inst.getComment(code_unit.EOL_COMMENT)
        line = {
            "address": str(inst.getAddress()),
            "mnemonic": str(inst.getMnemonicString()),
            "operands": str(operands),
            "comment": str(comment) if comment else "",
        }
        lines.append(line)
    return lines


def get_callee(params, *, ensure_context, get_address, iter_items, task_monitor):
    ctx = ensure_context()
    address_text = params.get("address")
    if not address_text:
        raise ValueError("addressが必要です")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("関数が見つかりません: %s" % address_text)
    callees = function.getCalledFunctions(task_monitor.DUMMY)
    callees_list = list(iter_items(callees))
    if function.isThunk() and not callees_list:
        thunked = function.getThunkedFunction(False)
        if thunked is not None:
            callees_list = list(iter_items(thunked.getCalledFunctions(task_monitor.DUMMY)))
    return sorted(["%s @ %s" % (callee.getName(True), callee.getEntryPoint()) for callee in callees_list])
