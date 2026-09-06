"""Read-only decompile/disassembly commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.pagination import normalize_limit


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


def disassemble_function(params, *, ensure_context, get_address, iter_items, code_unit):
    ctx = ensure_context()
    address_text = params.get("address")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("Function not found: %s" % address_text)
    body = function.getBody()
    instructions = ctx.listing.getInstructions(body, True)
    lines = []
    for inst in iter_items(instructions):
        lines.append(_instruction_to_dict(inst, code_unit))
    return lines


def disassemble_range(params, *, ensure_context, get_address, to_int, iter_items, code_unit):
    ctx = ensure_context()
    start_text = params.get("start_address")
    end_text = params.get("end_address")
    length = params.get("length")
    limit = normalize_limit(params, to_int, 200)
    if not start_text:
        raise ValueError("start_address is required")
    if end_text is None and length is None:
        raise ValueError("end_address or length is required")
    start = get_address(ctx, start_text)
    if end_text is not None:
        end = get_address(ctx, end_text)
    else:
        normalized_length = to_int(length, 0)
        if normalized_length <= 0:
            raise ValueError("length must be > 0")
        try:
            end = start.add(normalized_length - 1)
        except Exception as exc:
            # Address.add() raises an AddressOverflowException at the end of an
            # address space (and the Python/Java bridge rejects values outside a
            # signed long). Expose either case as an invalid user range instead of
            # leaking a backend-specific exception.
            raise ValueError("length exceeds the address space") from exc
    if start.compareTo(end) > 0:
        raise ValueError("start_address must be <= end_address")
    lines = []
    instructions = ctx.listing.getInstructions(start, True)
    for inst in iter_items(instructions):
        if inst.getAddress().compareTo(end) > 0:
            break
        lines.append(_instruction_to_dict(inst, code_unit))
        if len(lines) >= limit:
            break
    return lines


def get_callee(params, *, ensure_context, get_address, iter_items, task_monitor):
    ctx = ensure_context()
    address_text = params.get("address")
    if not address_text:
        raise ValueError("address is required")
    address = get_address(ctx, address_text)
    function = ctx.function_manager.getFunctionContaining(address)
    if function is None:
        raise LookupError("Function not found: %s" % address_text)
    callees = function.getCalledFunctions(task_monitor.DUMMY)
    callees_list = list(iter_items(callees))
    if function.isThunk() and not callees_list:
        thunked = function.getThunkedFunction(False)
        if thunked is not None:
            callees_list = list(iter_items(thunked.getCalledFunctions(task_monitor.DUMMY)))
    rows = [
        {
            "name": str(callee.getName(True)),
            "entry": str(callee.getEntryPoint()),
            "is_external": bool(callee.isExternal()),
        }
        for callee in callees_list
    ]
    return sorted(rows, key=lambda row: (row["name"], row["entry"]))
