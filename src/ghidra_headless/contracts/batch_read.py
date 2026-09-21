"""What a valid ``batch_read`` request is: the single source for the MCP schema and the core guard.

JVM-free on purpose (see ``ghidra_headless.contracts``).
"""

BATCH_READ_TOOLS = frozenset({"get_function", "get_comments", "get_data_type", "get_xrefs", "get_call_edges"})


def validate_requests(requests):
    """Reject a malformed batch.  Called by the MCP input model and again by the core command for direct callers."""
    if not isinstance(requests, list) or not 1 <= len(requests) <= 20:
        raise ValueError("batch_read requires 1-20 requests")
    ids = set()
    page_rows = 0
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
        if tool in {"get_function", "get_call_edges"} and not (arguments.get("address") or arguments.get("name")):
            raise ValueError("%s requires address or name" % tool)
        if tool in {"get_xrefs", "get_comments"} and not arguments.get("address"):
            raise ValueError("%s requires address" % tool)
        if tool == "get_data_type" and not arguments.get("path"):
            raise ValueError("get_data_type requires path")
        if tool in {"get_xrefs", "get_call_edges"}:
            limit = arguments.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 10000:
                raise ValueError("limit must be between 1 and 10000")
            page_rows += limit
    if page_rows > 2000:
        raise ValueError("batch_read page limits must total at most 2000 rows")
