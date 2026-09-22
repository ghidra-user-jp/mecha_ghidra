"""What a valid ``batch_read`` request is: the single source for the MCP schema and the core guard.

JVM-free on purpose (see ``ghidra_headless.contracts``).
"""

BATCH_READ_TOOLS = frozenset(
    {
        "get_function",
        "get_comments",
        "get_data_type",
        "get_xrefs",
        "get_call_edges",
        "decompile_function",
        "disassemble",
    }
)
MAX_BATCH_DECOMPILES = 5
MAX_BATCH_RESULT_BYTES = 8 * 1024 * 1024


def validate_requests(requests):
    """Reject a malformed batch.  Called by the MCP input model and again by the core command for direct callers."""
    if not isinstance(requests, list) or not 1 <= len(requests) <= 20:
        raise ValueError("batch_read requires 1-20 requests")
    ids = set()
    page_rows = 0
    decompiles = 0
    for request in requests:
        if not isinstance(request, dict) or request.get("tool") not in BATCH_READ_TOOLS:
            raise ValueError("unsupported batch_read tool")
        request_id = request.get("id")
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 32 or request_id in ids:
            raise ValueError("batch_read ids must be unique strings of 1-32 characters")
        ids.add(request_id)
        arguments = request.get("arguments")
        if not isinstance(arguments, dict) or "target" in arguments:
            raise ValueError("batch_read arguments must be an object without target")
        tool = request["tool"]
        if tool in {"get_function", "get_call_edges", "decompile_function"} and not (
            arguments.get("address") or arguments.get("name")
        ):
            raise ValueError("%s requires address or name" % tool)
        item_timeout = request.get("item_timeout_seconds")
        if tool == "decompile_function":
            decompiles += 1
            if request.get("fields") is not None:
                raise ValueError("decompile_function does not support fields")
            if "item_timeout_seconds" in request and (type(item_timeout) is not int or not 1 <= item_timeout <= 60):
                raise ValueError("item_timeout_seconds must be between 1 and 60")
        elif "item_timeout_seconds" in request:
            raise ValueError("item_timeout_seconds is only supported for decompile_function")
        if tool == "disassemble":
            function = bool(arguments.get("address") or arguments.get("name"))
            range_selector = any(arguments.get(k) is not None for k in ("start_address", "end_address", "length"))
            if function == range_selector:
                raise ValueError("disassemble requires a function or a range")
            if range_selector and (
                not arguments.get("start_address")
                or (arguments.get("end_address") is None) == (arguments.get("length") is None)
            ):
                raise ValueError("disassemble requires start_address and exactly one of end_address or length")
            length = arguments.get("length")
            if length is not None and (type(length) is not int or length < 1):
                raise ValueError("disassemble length must be positive")
        if tool in {"get_xrefs", "get_comments"} and not arguments.get("address"):
            raise ValueError("%s requires address" % tool)
        if tool == "get_data_type" and not arguments.get("path"):
            raise ValueError("get_data_type requires path")
        if tool in {"get_xrefs", "get_call_edges", "disassemble"}:
            limit = arguments.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 10000:
                raise ValueError("limit must be between 1 and 10000")
            page_rows += limit
    if page_rows > 2000:
        raise ValueError("batch_read page limits must total at most 2000 rows")
    if decompiles > MAX_BATCH_DECOMPILES:
        raise ValueError("batch_read supports at most 5 decompiles")
