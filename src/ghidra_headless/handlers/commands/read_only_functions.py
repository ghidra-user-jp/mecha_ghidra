"""Read-only function commands extracted from legacy core handler."""

from __future__ import absolute_import, print_function

from ghidra_headless.handlers.commands.pagination import normalize_pagination


def _body_size(function):
    body = function.getBody()
    if body is None:
        return 0
    return int(body.getNumAddresses())


def _is_default_name(function, source_type):
    symbol = function.getSymbol()
    return symbol is not None and symbol.getSource() == source_type.DEFAULT


def list_functions(params, *, ensure_context, to_int, collect, iter_items, source_type):
    """List functions; ``filter`` is a case-insensitive name substring and
    ``only_default_names`` keeps only functions Ghidra named itself (FUN_...)."""
    ctx = ensure_context()
    offset, limit = normalize_pagination(params, to_int, 100)
    filter_text = params.get("filter")
    lowered = str(filter_text).lower() if filter_text else None
    only_default_names = bool(params.get("only_default_names", False))

    def _matches(func):
        if lowered and lowered not in func.getName().lower():
            return False
        return not only_default_names or _is_default_name(func, source_type)

    def _to_entry(func):
        return {
            "name": func.getName(),
            "entry": str(func.getEntryPoint()),
            "size": _body_size(func),
            "is_thunk": bool(func.isThunk()),
        }

    iterator = (func for func in iter_items(ctx.function_manager.getFunctions(True)) if _matches(func))
    return collect(iterator, offset, limit, _to_entry)


def _variable_entry(variable, safe_call):
    data_type = safe_call(variable, "getDataType")
    storage = safe_call(variable, "getVariableStorage")
    return {
        "name": str(variable.getName()),
        "type": None if data_type is None else str(data_type.getDisplayName()),
        "storage": None if storage is None else str(storage),
    }


def _describe_function(ctx, function, *, safe_call, iter_items):
    symbol = safe_call(function, "getSymbol")
    namespace = safe_call(function, "getParentNamespace")
    return_type = safe_call(function, "getReturnType")
    body = safe_call(function, "getBody")
    thunked = safe_call(function, "getThunkedFunction", False) if bool(safe_call(function, "isThunk")) else None
    prototype = safe_call(function, "getPrototypeString", True, True)
    if prototype is None:
        signature = safe_call(function, "getSignature")
        prototype = None if signature is None else str(signature)
    parameters = []
    for index, parameter in enumerate(iter_items(safe_call(function, "getParameters") or ())):
        entry = _variable_entry(parameter, safe_call)
        entry["ordinal"] = index
        parameters.append(entry)
    local_variables = [
        _variable_entry(variable, safe_call) for variable in iter_items(safe_call(function, "getLocalVariables") or ())
    ]
    comment = safe_call(function, "getComment")
    full_name = safe_call(function, "getName", True)
    return {
        "name": function.getName(),
        "entry": str(function.getEntryPoint()),
        "full_name": function.getName() if full_name is None else str(full_name),
        "namespace": None if namespace is None else str(namespace.getName(True)),
        "signature": None if prototype is None else str(prototype),
        "return_type": None if return_type is None else str(return_type.getDisplayName()),
        "calling_convention": safe_call(function, "getCallingConventionName"),
        "parameters": parameters,
        "local_variables": local_variables,
        "body": None
        if body is None
        else {
            "min_address": str(body.getMinAddress()),
            "max_address": str(body.getMaxAddress()),
            "size": int(body.getNumAddresses()),
        },
        "is_thunk": bool(safe_call(function, "isThunk")),
        "thunked_function": None
        if thunked is None
        else {"name": str(thunked.getName(True)), "entry": str(thunked.getEntryPoint())},
        "is_external": bool(safe_call(function, "isExternal")),
        "has_varargs": bool(safe_call(function, "hasVarArgs")),
        "has_no_return": bool(safe_call(function, "hasNoReturn")),
        "name_source": None if symbol is None else str(symbol.getSource()),
        "comment": None if comment is None else str(comment),
    }


def get_function(params, *, ensure_context, get_address, find_function_by_name, safe_call, iter_items):
    ctx = ensure_context()
    address_text = params.get("address")
    name = params.get("name")
    if address_text:
        address = get_address(ctx, address_text)
        function = ctx.function_manager.getFunctionContaining(address)
        if function is None:
            raise LookupError("No function found for address: %s" % address_text)
    else:
        if not name:
            raise ValueError("address or name is required")
        function = find_function_by_name(ctx, name)
        if function is None:
            raise LookupError("Function not found: %s" % name)
    return _describe_function(ctx, function, safe_call=safe_call, iter_items=iter_items)
