"""Program-bound pagination shared by the consolidated query tools."""

import base64
import hashlib
import json
import sys
from itertools import islice

from ghidra_headless.errors import HeadlessError


def program_revision(ctx):
    return "%s:%s" % (ctx.generation, ctx.program.getModificationNumber())


def program_metadata(ctx):
    domain_file = ctx.program.getDomainFile()
    return {
        "program": None if domain_file is None else str(domain_file.getPathname()),
        "revision": program_revision(ctx),
    }


def page(ctx, tool, params, rows, *, convert=None, seek_key=None):
    limit = int(params.get("limit", 100))
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be between 1 and 10000")
    metadata = program_metadata(ctx)
    query = {k: v for k, v in params.items() if k not in {"cursor", "limit"} and v is not None}
    fingerprint = hashlib.sha256(json.dumps([tool, query], sort_keys=True).encode()).hexdigest()[:16]
    offset = 0
    cursor = params.get("cursor")
    if cursor:
        try:
            if len(cursor) > 1024:
                raise ValueError("cursor is too long")
            prior_revision, prior_query, offset = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if isinstance(offset, dict):
                if (
                    seek_key is None
                    or set(offset) != {"seek"}
                    or not isinstance(offset["seek"], str)
                    or len(offset["seek"]) > 256
                ):
                    raise ValueError("invalid seek cursor")
            elif type(offset) is not int or not 0 <= offset <= sys.maxsize - limit - 1:
                raise ValueError("invalid cursor offset")
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid pagination cursor") from exc
        if prior_query != fingerprint:
            raise ValueError("cursor belongs to a different query")
        if prior_revision != metadata["revision"]:
            raise HeadlessError("SESSION_CHANGED: program changed; restart pagination")
    if callable(rows):
        rows = rows(offset["seek"] if isinstance(offset, dict) else None)
    if isinstance(offset, dict):
        offset = 0
    selected = list(islice(rows, offset, offset + limit + 1))
    items = selected[:limit] if convert is None else [convert(row) for row in selected[:limit]]
    if program_revision(ctx) != metadata["revision"]:
        raise HeadlessError("SESSION_CHANGED: program changed while reading; restart pagination")
    has_more = len(selected) > limit
    next_cursor = None
    if has_more:
        next_cursor = base64.urlsafe_b64encode(
            json.dumps(
                [
                    metadata["revision"],
                    fingerprint,
                    {"seek": seek_key(selected[limit])} if seek_key is not None else offset + limit,
                ]
            ).encode()
        ).decode()
    return {**metadata, "items": items, "has_more": has_more, "next_cursor": next_cursor}


def resolve_function(ctx, params, get_address, find_function_by_name):
    if params.get("address"):
        fn = ctx.function_manager.getFunctionContaining(get_address(ctx, params["address"]))
    elif params.get("name"):
        fn = find_function_by_name(ctx, params["name"])
    else:
        raise ValueError("address or name is required")
    if fn is None:
        raise LookupError("Function not found")
    return fn


def function_ref(fn):
    return (
        None
        if fn is None
        else {"entry": str(fn.getEntryPoint()), "name": str(fn.getName(True)), "is_external": bool(fn.isExternal())}
    )
