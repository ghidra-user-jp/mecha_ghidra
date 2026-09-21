"""Small, composable analysis queries with consistent identities and pagination."""

from itertools import chain

from .query_support import function_ref, page, program_metadata, resolve_function
from .read_only_decompile import _instruction_to_dict


def get_xrefs(params, *, ensure_context, get_address, iter_items):
    ctx = ensure_context()
    address = get_address(ctx, params["address"])
    direction = params.get("direction", "to")
    if direction not in {"to", "from"}:
        raise ValueError("direction must be to or from")
    manager = ctx.reference_manager
    refs = manager.getReferencesTo(address) if direction == "to" else manager.getReferencesFrom(address)

    def describe(ref):
        source, destination = ref.getFromAddress(), ref.getToAddress()
        return {
            "from": str(source),
            "to": str(destination),
            "type": str(ref.getReferenceType()),
            "operand_index": int(ref.getOperandIndex()),
            "from_function": function_ref(ctx.function_manager.getFunctionContaining(source)),
            "to_function": function_ref(ctx.function_manager.getFunctionContaining(destination)),
        }

    return page(ctx, "get_xrefs", params, iter_items(refs), convert=describe)


def _call_edge(ctx, ref, include_tail_calls):
    kind = ref.getReferenceType()
    caller = ctx.function_manager.getFunctionContaining(ref.getFromAddress())
    callee = ctx.function_manager.getFunctionContaining(ref.getToAddress())
    if kind.isCall():
        edge_kind = "call"
    elif include_tail_calls and kind.isJump() and callee is not None and caller != callee:
        edge_kind = "tail_call"
    else:
        return None
    return {
        "caller": caller,
        "callee": callee,
        "call_site": str(ref.getFromAddress()),
        "destination": str(ref.getToAddress()),
        "kind": edge_kind,
        "reference_type": str(kind),
        "resolved": callee is not None,
    }


def _thunk_edge(caller, callee):
    # This is a semantic transfer from Ghidra's thunk relation. No instruction
    # address is invented when the listing contains no corresponding flow ref.
    return {
        "caller": caller,
        "callee": callee,
        "call_site": None,
        "destination": str(callee.getEntryPoint()),
        "kind": "thunk",
        "reference_type": "THUNK",
        "resolved": True,
    }


def get_call_edges(params, *, ensure_context, get_address, find_function_by_name, iter_items):
    ctx = ensure_context()
    function = resolve_function(ctx, params, get_address, find_function_by_name)
    direction = params.get("direction", "out")
    if direction not in {"in", "out"}:
        raise ValueError("direction must be in or out")
    tail_calls = params.get("include_tail_calls", True)
    unresolved = params.get("include_unresolved", True)
    manager = ctx.reference_manager

    def outgoing():
        thunked = function.getThunkedFunction(False) if function.isThunk() else None
        found_thunk = False
        for inst in iter_items(ctx.listing.getInstructions(function.getBody(), True)):
            emitted = False
            for ref in iter_items(manager.getReferencesFrom(inst.getAddress())):
                edge = _call_edge(ctx, ref, tail_calls)
                if edge is None:
                    continue
                emitted = True
                if thunked is not None and edge["destination"] == str(thunked.getEntryPoint()):
                    edge["kind"] = "thunk"
                    found_thunk = True
                if edge["resolved"] or unresolved:
                    yield edge
            if unresolved and not emitted and inst.getFlowType().isCall():
                yield {
                    "caller": function,
                    "callee": None,
                    "call_site": str(inst.getAddress()),
                    "destination": None,
                    "kind": "call",
                    "reference_type": str(inst.getFlowType()),
                    "resolved": False,
                }
        if thunked is not None and not found_thunk:
            yield _thunk_edge(function, thunked)

    def incoming():
        seen_thunks = set()
        # The entry can be in EXTERNAL space, which is not in a memory body.
        destinations = chain(
            [function.getEntryPoint()],
            (
                addr
                for addr in iter_items(manager.getReferenceDestinationIterator(function.getBody(), True))
                if addr != function.getEntryPoint()
            ),
        )
        for destination in destinations:
            for ref in iter_items(manager.getReferencesTo(destination)):
                edge = _call_edge(ctx, ref, tail_calls)
                if edge is not None:
                    caller = ctx.function_manager.getFunctionContaining(ref.getFromAddress())
                    if caller is not None and caller.isThunk() and caller.getThunkedFunction(False) == function:
                        edge["kind"] = "thunk"
                        seen_thunks.add(str(caller.getEntryPoint()))
                    yield edge
        for address in sorted(iter_items(function.getFunctionThunkAddresses(False) or []), key=str):
            if str(address) not in seen_thunks:
                caller = ctx.function_manager.getFunctionAt(address)
                if caller is not None:
                    yield _thunk_edge(caller, function)

    def describe(edge):
        return {**edge, "caller": function_ref(edge["caller"]), "callee": function_ref(edge["callee"])}

    return page(ctx, "get_call_edges", params, incoming() if direction == "in" else outgoing(), convert=describe)


def disassemble(params, *, ensure_context, get_address, find_function_by_name, iter_items, comment_types):
    ctx = ensure_context()
    function_selector = bool(params.get("address") or params.get("name"))
    range_selector = any(params.get(k) is not None for k in ("start_address", "end_address", "length"))
    if function_selector == range_selector:
        raise ValueError("select a function (address/name) or a range (start_address with end_address/length)")
    if function_selector:
        function = resolve_function(ctx, params, get_address, find_function_by_name)
        body = function.getBody()
        start, end = body.getMinAddress(), body.getMaxAddress()
    else:
        if not params.get("start_address") or (params.get("end_address") is None) == (params.get("length") is None):
            raise ValueError("start_address and exactly one of end_address or length are required")
        start = get_address(ctx, params["start_address"])
        if params.get("length") is not None:
            if params["length"] < 1:
                raise ValueError("length must be positive")
            try:
                end = start.add(params["length"] - 1)
            except Exception as exc:
                raise ValueError("range exceeds address space") from exc
        else:
            end = get_address(ctx, params["end_address"])
        if start.getAddressSpace() != end.getAddressSpace() or start.compareTo(end) > 0:
            raise ValueError("range must be ordered and within one address space")

    def instructions(resume):
        begin = get_address(ctx, resume) if resume is not None else start
        if begin is None or end is None:
            return
        if function_selector:
            if not body.contains(begin):
                raise ValueError("cursor address is outside the selected function body")
            remaining = body
            if resume is not None:
                from ghidra.program.model.address import AddressSet

                # Trim ranges, not individual instructions. Preserve holes and
                # address spaces in a non-contiguous function body.
                remaining = AddressSet(body)
                remaining.deleteFromMin(begin)
                remaining.add(begin)
            yield from iter_items(ctx.listing.getInstructions(remaining, True))
            return
        if begin.getAddressSpace() != start.getAddressSpace() or begin.compareTo(start) < 0 or begin.compareTo(end) > 0:
            raise ValueError("cursor address is outside the selected instruction range")
        for inst in iter_items(ctx.listing.getInstructions(begin, True)):
            address = inst.getAddress()
            if address.getAddressSpace() != end.getAddressSpace() or address.compareTo(end) > 0:
                break
            yield inst

    return page(
        ctx,
        "disassemble",
        params,
        instructions,
        convert=lambda inst: _instruction_to_dict(inst, comment_types),
        seek_key=lambda inst: str(inst.getAddress()),
    )


def get_data_type(
    params, *, ensure_context, dt_manager, find_data_type_by_name, describe_data_type, describe_struct, describe_enum
):
    ctx = ensure_context()
    data_type = find_data_type_by_name(dt_manager(ctx), params["path"])
    if data_type is None:
        raise LookupError("Data type not found: %s" % params["path"])
    result = {**program_metadata(ctx), **describe_data_type(data_type)}
    is_enum = hasattr(data_type, "getNames") and hasattr(data_type, "getValue")
    if is_enum:
        result.update(count=int(data_type.getCount()), isSigned=bool(data_type.isSigned()))
    if params.get("include_members", True):
        if hasattr(data_type, "getComponents"):
            result["members"] = describe_struct(data_type)["members"]
        elif is_enum:
            result["values"] = describe_enum(data_type)["values"]
    if hasattr(data_type, "getBaseDataType"):
        result["base_type"] = str(data_type.getBaseDataType().getPathName())
    return result
