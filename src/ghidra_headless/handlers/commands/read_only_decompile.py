"""Read-only decompile/disassembly commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function


def _instruction_to_dict(inst, code_unit):
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
    return {
        "address": str(inst.getAddress()),
        "mnemonic": str(inst.getMnemonicString()),
        "operands": str(operands),
        "comment": str(comment) if comment else "",
    }


def decompile_function(params, *, ensure_context, get_address, find_function_by_name, decompile_function_object):
    ctx = ensure_context()
    address_text = params.get("address")
    name = params.get("name")
    if address_text:
        address = get_address(ctx, address_text)
        function = ctx.function_manager.getFunctionContaining(address)
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
        return decompile_function_object(ctx, function)
    if not name:
        raise ValueError("address or name is required")
    function = find_function_by_name(ctx, name)
    if function is None:
        raise LookupError("Function not found: %s" % name)

    return decompile_function_object(ctx, function)
