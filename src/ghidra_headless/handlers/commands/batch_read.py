"""Bounded reads executed inside one normal target/project lock acquisition."""

import time

from ghidra_headless.contracts.batch_read import validate_requests
from ghidra_headless.errors import HeadlessError

from .query_support import program_metadata, program_revision


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
    for request in requests:
        # A GUI/background edit is not excluded by the MCP target lock.
        if ensure_context() is not ctx or program_revision(ctx) != metadata["revision"]:
            raise HeadlessError("SESSION_CHANGED: program changed during batch_read; discard all results")
        item = {"id": request["id"], "tool": request["tool"]}
        if clock() >= deadline:
            item.update(status="not_run", reason="time_budget_exhausted")
        else:
            try:
                item.update(status="ok", data=execute_read(request["tool"], request["arguments"]))
            except HeadlessError as exc:
                # Session/runtime failures invalidate the entire batch. Only
                # anticipated query errors are independent item failures.
                if exc.code not in {"AMBIGUOUS_FUNCTION", "AMBIGUOUS_DATA_TYPE"}:
                    raise
                item.update(status="error", error={"code": exc.code, "message": str(exc)})
                if exc.details is not None:
                    item["error"]["details"] = exc.details
            except (LookupError, ValueError) as exc:
                if isinstance(exc, (KeyError, IndexError)):
                    raise
                code = "NOT_FOUND" if isinstance(exc, LookupError) else "VALIDATION_ERROR"
                item.update(status="error", error={"code": code, "message": str(exc)})
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
