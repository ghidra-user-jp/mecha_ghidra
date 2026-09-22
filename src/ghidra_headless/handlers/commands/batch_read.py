"""Bounded reads executed inside one normal target/project lock acquisition."""

import json
import time

from ghidra_headless.contracts.batch_read import MAX_BATCH_RESULT_BYTES, validate_requests
from ghidra_headless.errors import HeadlessError
from ghidra_headless.handlers.read_budget import ReadBudget

from .query_support import program_metadata, program_revision


def _json_size(value, limit):
    """Bound retained JSON payload, without an additional payload-sized bytes copy."""
    size = 0
    for part in json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), default=str).iterencode(value):
        for offset in range(0, len(part), 65536):
            # Presentation normalizes isolated surrogates to U+FFFD (3 bytes).
            # surrogatepass counts those conservatively instead of as '?' (1).
            size += len(part[offset : offset + 65536].encode("utf-8", errors="surrogatepass"))
            if size > limit:
                return size
    return size


def batch_read(params, *, ensure_context, execute_read, clock=time.monotonic):
    requests = params.get("requests")
    validate_requests(requests)
    timeout = params.get("timeout_seconds", 10)
    if type(timeout) is not int or not 1 <= timeout <= 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    ctx = ensure_context()
    metadata = program_metadata(ctx)
    if params.get("expected_revision") not in (None, metadata["revision"]):
        raise HeadlessError("SESSION_CHANGED: program changed before batch_read")
    deadline = clock() + timeout
    items = []
    # Leave room for identities, statuses and bounded errors even when data
    # exhausts the payload budget. Native allocation itself is not bounded here.
    remaining_bytes = max(
        0, MAX_BATCH_RESULT_BYTES - _json_size(metadata, MAX_BATCH_RESULT_BYTES) - 512 * len(requests)
    )
    result_exhausted = False
    for request in requests:
        # A GUI/background edit is not excluded by the MCP target lock.
        if ensure_context() is not ctx or program_revision(ctx) != metadata["revision"]:
            raise HeadlessError("SESSION_CHANGED: program changed during batch_read; discard all results")
        item = {"id": request["id"], "tool": request["tool"]}
        now = clock()
        if result_exhausted:
            item.update(status="not_run", reason="result_budget_exhausted")
        elif now >= deadline or (request["tool"] == "decompile_function" and deadline - now < 1):
            item.update(status="not_run", reason="time_budget_exhausted")
        else:
            try:
                if request["tool"] in {"decompile_function", "disassemble"}:
                    item_deadline = deadline
                    if request["tool"] == "decompile_function":
                        item_deadline = min(deadline, now + request.get("item_timeout_seconds", 15))
                    budget = ReadBudget(item_deadline, clock=clock)
                    data = execute_read(request["tool"], request["arguments"], budget=budget)
                    budget.check("DECOMPILE_TIMEOUT" if request["tool"] == "decompile_function" else "READ_TIMEOUT")
                else:
                    data = execute_read(request["tool"], request["arguments"])
                size = _json_size(data, MAX_BATCH_RESULT_BYTES)
                if size > remaining_bytes:
                    result_exhausted = size <= MAX_BATCH_RESULT_BYTES
                    item.update(
                        status="error",
                        error={
                            "code": "RESULT_BUDGET_EXHAUSTED" if result_exhausted else "ITEM_RESULT_TOO_LARGE",
                            "message": "Read result exceeds the retained batch payload budget; request a smaller read",
                            "size_bytes_lower_bound": size,
                        },
                    )
                else:
                    item.update(status="ok", data=data)
                    remaining_bytes -= size
                del data
            except HeadlessError as exc:
                # Session/runtime failures invalidate the entire batch. Only
                # anticipated query errors are independent item failures.
                if exc.code not in {
                    "AMBIGUOUS_FUNCTION",
                    "AMBIGUOUS_DATA_TYPE",
                    "DECOMPILE_TIMEOUT",
                    "DECOMPILE_FAILED",
                    "READ_TIMEOUT",
                }:
                    raise
                item.update(status="error", error={"code": exc.code, "message": str(exc)})
                if exc.details is not None:
                    item["error"]["details"] = exc.details
            except (LookupError, ValueError) as exc:
                if isinstance(exc, (KeyError, IndexError)):
                    raise
                code = "NOT_FOUND" if isinstance(exc, LookupError) else "VALIDATION_ERROR"
                item.update(status="error", error={"code": code, "message": str(exc)})
        if item["status"] == "error":
            size = _json_size(item["error"], remaining_bytes)
            if size > remaining_bytes:
                item["error"] = {
                    "code": item["error"]["code"],
                    "message": "Error details exceed the batch payload budget",
                    "details_truncated": True,
                }
            else:
                remaining_bytes -= size
        items.append(item)
    if ensure_context() is not ctx or program_revision(ctx) != metadata["revision"]:
        raise HeadlessError("SESSION_CHANGED: program changed during batch_read; discard all results")
    succeeded = sum(item["status"] == "ok" for item in items)
    failed = sum(item["status"] == "error" for item in items)
    not_run = len(items) - succeeded - failed
    return {
        **metadata,
        "status": "ok" if succeeded == len(items) else "partial" if succeeded else "error",
        "succeeded_count": succeeded,
        "failed_count": failed,
        "not_run_count": not_run,
        "items": items,
    }
