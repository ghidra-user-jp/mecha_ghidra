"""MCP resources and tools that read back stored large results."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from typing import Annotated, Any, Literal

import regex
from mcp.types import ToolAnnotations
from pydantic import Field

from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.result_compaction import (
    _RESULT_METADATA_JSON_CHARS,
    _bounded_json_string,
    _json_text,
    structured_result_wire_chars,
)
from ghidra_mcp.presentation.result_json import read_json_items
from ghidra_mcp.presentation.result_store import ResultResourceStore, StoredToolResult
from ghidra_mcp.presentation.tool_binding import bind_function
from ghidra_mcp.presentation.tool_errors import ToolError

logger = logging.getLogger(__name__)

_SEARCH_CONTEXT_MAX_CHARS = 2000
_SEARCH_MATCH_DISPLAY_MAX_CHARS = 500
_SEARCH_MAX_MATCHES_CAP = 100
_SEARCH_SCAN_CAP = 10_000
_SEARCH_MAX_PATTERN_CHARS = 512
_MIN_RESULT_TOOL_RESPONSE_CHARS = 1024
_ResultId = Annotated[
    str,
    Field(min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$"),
]


# Static pattern screening cannot reliably separate safe expressions from ReDoS
# patterns. Matching therefore uses the third-party `regex` engine's timeout and
# runs in a worker thread so an expensive expression does not block the MCP SDK's
# event loop. ``concurrent=True`` asks regex to release the GIL while matching.
_SEARCH_TIMEOUT_SECONDS = 1.0


def _validate_search_pattern(pattern: str) -> None:
    if len(pattern) > _SEARCH_MAX_PATTERN_CHARS:
        raise ValueError(f"Search pattern too long ({len(pattern)} chars; max {_SEARCH_MAX_PATTERN_CHARS}).")


def _get_entry(store: ResultResourceStore, result_id: str) -> StoredToolResult:
    try:
        return store.get(result_id)
    except KeyError as exc:
        # The protocol handler preserves this anticipated, public-safe failure
        # as an isError result with matching text and structured error data.
        raise ToolError(str(exc.args[0]) if exc.args else str(exc)) from exc


def _read_result_payload(
    entry: StoredToolResult,
    *,
    offset: int,
    chunk: str,
) -> dict[str, Any]:
    tool, tool_truncated = _bounded_json_string(
        entry.tool,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    target, target_truncated = _bounded_json_string(
        entry.target,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    mime_type, mime_type_truncated = _bounded_json_string(
        entry.mime_type,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    next_offset = offset + len(chunk)
    has_more = next_offset < entry.size_chars
    return {
        "result_id": entry.result_id,
        "tool": tool,
        "target": target,
        "mime_type": mime_type,
        "metadata_truncated": tool_truncated or target_truncated or mime_type_truncated,
        "offset_chars": offset,
        "chunk_chars": len(chunk),
        "total_chars": entry.size_chars,
        "has_more": has_more,
        "next_offset_chars": next_offset if has_more else None,
        "chunk": chunk,
    }


def _fit_read_result_chunk(
    entry: StoredToolResult,
    *,
    offset: int,
    candidate: str,
    configured_budget: int,
) -> dict[str, Any]:
    budget = max(configured_budget, _MIN_RESULT_TOOL_RESPONSE_CHARS)
    full = _read_result_payload(entry, offset=offset, chunk=candidate)
    if structured_result_wire_chars(full) <= budget:
        return full
    low = 0
    high = len(candidate) - 1
    while low < high:
        middle = (low + high + 1) // 2
        payload = _read_result_payload(entry, offset=offset, chunk=candidate[:middle])
        if structured_result_wire_chars(payload) <= budget:
            low = middle
        else:
            high = middle - 1
    # The bounded metadata plus the 1024-character infrastructure minimum leave
    # room for at least one maximally escaped character, so every non-empty page
    # still makes progress without violating the complete-response cap.
    if candidate and low == 0:
        raise AssertionError("read_result response metadata exhausted the minimum budget")
    return _read_result_payload(entry, offset=offset, chunk=candidate[:low])


def _search_result_payload(
    entry: StoredToolResult,
    *,
    pattern: str,
    pattern_truncated: bool,
    match_count: int,
    scan_truncated: bool,
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "result_id": entry.result_id,
        "pattern": pattern,
        "pattern_truncated": pattern_truncated,
        "match_count": match_count,
        "scan_truncated": scan_truncated,
        "matches_shown": len(matches),
        "matches": matches,
    }


def _merge_search_contexts(entry: StoredToolResult, matches: list[dict[str, Any]]) -> tuple[list, list]:
    regions: list[dict[str, Any]] = []
    result = []
    # Input follows the regex engine's order. Sort only the context intervals;
    # the returned matches keep their original order (including reverse regex).
    intervals = sorted((m["context_offset_chars"], m["context_offset_chars"] + len(m["context"])) for m in matches)
    for start, end in intervals:
        if regions and start <= regions[-1]["end"]:
            regions[-1]["end"] = max(end, regions[-1]["end"])
        else:
            regions.append({"offset_chars": start, "end": end})
    for match in matches:
        start = match["context_offset_chars"]
        end = start + len(match["context"])
        index = next(i for i, r in enumerate(regions) if r["offset_chars"] <= start and end <= r["end"])
        result.append(
            {**{k: v for k, v in match.items() if k not in {"context", "context_offset_chars"}}, "context_index": index}
        )
    return result, [
        {"offset_chars": r["offset_chars"], "text": entry.text[r["offset_chars"] : r["end"]]} for r in regions
    ]


def _search_stored_result(
    entry: StoredToolResult,
    *,
    pattern: str,
    context_chars: int,
    max_matches: int,
    configured_budget: int,
    merge_context: bool = False,
    count_mode: str = "bounded",
    offset_chars: int = 0,
    cursor: str | None = None,
) -> dict[str, Any]:
    _validate_search_pattern(pattern)
    if count_mode not in {"bounded", "none"}:
        raise ValueError("count_mode must be bounded or none")
    if count_mode == "none" and max_matches == 0:
        raise ValueError("count_mode=none requires max_matches > 0")
    try:
        compiled = regex.compile(pattern)
    except regex.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc
    fingerprint = hashlib.sha256(pattern.encode("utf-8", errors="replace")).hexdigest()[:16]
    offset = min(max(0, offset_chars), entry.size_chars)
    skip = 0
    if cursor is not None:
        if offset_chars:
            raise ValueError("Use cursor or offset_chars, not both")
        try:
            if len(cursor) > 256:
                raise ValueError
            identity, prior_pattern, offset, skip = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if identity != entry.result_id or prior_pattern != fingerprint:
                raise ValueError
            if (
                type(offset) is not int
                or not 0 <= offset <= entry.size_chars
                or type(skip) is not int
                or skip not in (0, 1)
            ):
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid search cursor or cursor belongs to a different result/pattern") from exc
    reverse = bool(getattr(compiled, "flags", 0) & regex.REVERSE)
    if reverse and (cursor is not None or count_mode == "none" or offset_chars):
        raise ValueError("Reverse regex supports bounded search from the beginning only")
    context = max(0, min(context_chars, _SEARCH_CONTEXT_MAX_CHARS))
    shown_limit = min(max(max_matches, 0), _SEARCH_MAX_MATCHES_CAP)
    candidates = []
    match_count = 0
    scan_truncated = False
    deadline = time.monotonic() + _SEARCH_TIMEOUT_SECONDS
    try:
        kwargs = {"timeout": _SEARCH_TIMEOUT_SECONDS, "concurrent": True}
        if offset:
            kwargs["pos"] = offset
        for found in compiled.finditer(entry.text, **kwargs):
            if skip:
                skip = 0
                # A zero-length match can still consume a prefix via \K.
                # Only skip a repeated empty match at the previous end.
                if found.span() == (offset, offset):
                    continue
            if match_count >= _SEARCH_SCAN_CAP or time.monotonic() >= deadline:
                scan_truncated = True
                break
            match_count += 1
            if len(candidates) < shown_limit:
                start, end = found.span()
                display_end = min(end, start + _SEARCH_MATCH_DISPLAY_MAX_CHARS)
                context_start = max(0, start - context)
                context_end = min(len(entry.text), display_end + context)
                candidates.append(
                    {
                        "offset_chars": start,
                        "end_offset": end,
                        "match_chars": end - start,
                        "match_truncated": display_end < end,
                        "match": entry.text[start:display_end],
                        "context_offset_chars": context_start,
                        "context": entry.text[context_start:context_end],
                    }
                )
            if count_mode == "none" and len(candidates) >= shown_limit:
                scan_truncated = True
                break
    except TimeoutError as exc:
        raise ValueError(
            f"Search timed out after {_SEARCH_TIMEOUT_SECONDS:g}s — simplify the pattern or use read_result."
        ) from exc

    budget = max(configured_budget, _MIN_RESULT_TOOL_RESPONSE_CHARS)

    def response(matches, display_limit=None):
        reported_pattern = pattern[:display_limit]
        if display_limit is not None:
            matches = [
                {
                    **match,
                    "match": match["match"][:display_limit],
                    "match_truncated": len(match["match"][:display_limit]) < match["match_chars"],
                }
                for match in matches
            ]
        data = _search_result_payload(
            entry,
            pattern=reported_pattern,
            pattern_truncated=len(reported_pattern) < len(pattern),
            match_count=match_count,
            scan_truncated=scan_truncated,
            matches=matches,
        )
        data["count_complete"] = not scan_truncated
        if matches and not reverse and (scan_truncated or len(matches) < match_count):
            last = matches[-1]
            resume = [entry.result_id, fingerprint, last["end_offset"], int(last["match_chars"] == 0)]
            data["next_cursor"] = base64.urlsafe_b64encode(_json_text(resume).encode()).decode()
        else:
            data["next_cursor"] = None
        if merge_context:
            data["matches"], data["contexts"] = _merge_search_contexts(entry, matches)
        return data

    full = response(candidates)
    if structured_result_wire_chars(full) <= budget:
        return full
    low, high = 0, max(0, len(candidates) - 1)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = response(candidates[:middle])
        if structured_result_wire_chars(candidate) <= budget:
            low = middle
        else:
            high = middle - 1
    if low:
        return response(candidates[:low])
    # Keep one match's offsets and continuation before spending the remaining
    # budget on display text. Measure the complete response, including merged
    # contexts and the cursor, instead of reserving a fixed metadata allowance.
    minimal = [{**match, "context_offset_chars": match["offset_chars"], "context": ""} for match in candidates[:1]]
    best = response(minimal, display_limit=0)
    if structured_result_wire_chars(best) > budget:
        raise AssertionError("search_result response metadata exhausted the minimum budget")
    low, high = 0, max(len(pattern), len(minimal[0]["match"]) if minimal else 0)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = response(minimal, display_limit=middle)
        if structured_result_wire_chars(candidate) <= budget:
            low, best = middle, candidate
        else:
            high = middle - 1
    return best


def build_result_tools(*, store: ResultResourceStore, config: ToolPresentationConfig):
    """Register retrieval tools over the stored large results.

    These are presentation-layer infrastructure tools (not ToolSpec-based):
    tools-only MCP clients — most local-LLM harnesses — cannot issue
    resources/read, so paged reads and regex search over stored payloads must be
    reachable through tools/call.
    """
    annotations = ToolAnnotations(read_only_hint=True, idempotent_hint=True)

    read_description = (
        "Read a slice of a stored large tool result. Use the result_id from a "
        "truncated tool result, then page with offset_chars/limit_chars until "
        "has_more is false. limit_chars defaults to the server's "
        "compaction threshold and is capped at the threshold. The complete "
        "response is capped at max(threshold, 1024) serialized characters. mode=json reads array items "
        "at path='' (root) or '/items' with offset_items/limit_items and optional object fields. "
        "An oversized item is skipped: item_too_large reports its raw offset_chars/item_chars for mode=text "
        "and next_offset_items advances past it."
    )

    def read_result(
        result_id: _ResultId,
        offset_chars: int = 0,
        limit_chars: int | None = None,
        mode: Literal["text", "json"] = "text",
        path: Literal["", "/items"] = "",
        offset_items: Annotated[int, Field(ge=0)] = 0,
        limit_items: Annotated[int, Field(ge=1, le=1000)] = 20,
        fields: Annotated[list[Annotated[str, Field(max_length=128)]] | None, Field(max_length=32)] = None,
    ) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        if mode == "json":
            if offset_chars or limit_chars is not None:
                raise ToolError("JSON mode uses offset_items/limit_items, not character offsets")
            try:
                return read_json_items(
                    store,
                    entry,
                    path=path,
                    offset=offset_items,
                    limit=limit_items,
                    fields=fields,
                    budget=max(config.large_result_threshold_chars, 1024),
                    json_text=_json_text,
                    response_size=structured_result_wire_chars,
                )
            except ValueError as exc:
                raise ToolError(str(exc)) from exc
        if path or offset_items or fields is not None or limit_items != 20:
            raise ToolError("JSON selectors require mode=json")
        offset = min(max(0, offset_chars), entry.size_chars)
        if limit_chars is None:
            limit_chars = config.large_result_threshold_chars
        # Cap slices at the compaction threshold and choose the longest prefix
        # whose complete the MCP SDK JSON response fits the response budget.
        limit = max(1, min(limit_chars, config.large_result_threshold_chars))
        candidate = entry.text[offset : offset + limit]
        return _fit_read_result_chunk(
            entry,
            offset=offset,
            candidate=candidate,
            configured_budget=config.large_result_threshold_chars,
        )

    search_description = (
        "Search a stored large tool result with a Python regex. Returns matches "
        "with character offsets (usable as read_result offset_chars) and "
        "surrounding context. match_chars/end_offset describe the complete match, "
        "and match_truncated reports whether the displayed match was shortened. "
        "At most 100 snippets are returned, with context_chars limited to 2,000 "
        "characters on each side. "
        "Pass max_matches=0 to count up to the 10,000-match scan cap without "
        "returning snippets; check scan_truncated before treating match_count "
        "as complete. The "
        "complete response is capped at max(threshold, 1024) serialized characters; "
        "the echoed pattern and displayed snippets may be shortened. merge_context=true shares overlapping "
        "contexts; matches reference context_index. count_mode=none stops after the requested snippets "
        "without counting all matches. count_complete discloses incomplete counts; next_cursor resumes "
        "after returned matches with the same result_id/pattern. Reverse regex cannot use continuation."
    )

    async def search_result(
        result_id: _ResultId,
        # Publish the protocol limit without replacing the actionable custom
        # validation error from _validate_search_pattern inside the worker.
        pattern: Annotated[
            str,
            Field(json_schema_extra={"maxLength": _SEARCH_MAX_PATTERN_CHARS}),
        ],
        context_chars: Annotated[
            int,
            Field(ge=0, le=_SEARCH_CONTEXT_MAX_CHARS),
        ] = 200,
        max_matches: Annotated[
            int,
            Field(ge=0, le=_SEARCH_MAX_MATCHES_CAP),
        ] = 20,
        merge_context: bool = False,
        count_mode: Literal["bounded", "none"] = "bounded",
        offset_chars: Annotated[int, Field(ge=0)] = 0,
        cursor: Annotated[str | None, Field(max_length=256)] = None,
    ) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        try:
            return await asyncio.to_thread(
                _search_stored_result,
                entry,
                pattern=pattern,
                context_chars=context_chars,
                max_matches=max_matches,
                configured_budget=config.large_result_threshold_chars,
                merge_context=merge_context,
                count_mode=count_mode,
                offset_chars=offset_chars,
                cursor=cursor,
            )
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    result_id = {"type": "string", "pattern": "^[0-9a-f]{16}$"}
    read_schema = {
        "type": "object",
        "required": ["result_id", "has_more"],
        "properties": {
            "result_id": result_id,
            "has_more": {"type": "boolean"},
            "chunk": {"type": "string"},
            "items": {"type": "array"},
        },
        "anyOf": [{"required": ["chunk", "offset_chars"]}, {"required": ["items", "offset_items"]}],
    }
    search_schema = {
        "type": "object",
        "required": ["result_id", "matches", "match_count", "scan_truncated"],
        "properties": {
            "result_id": result_id,
            "matches": {"type": "array", "items": {"type": "object"}},
            "match_count": {"type": "integer", "minimum": 0},
            "scan_truncated": {"type": "boolean"},
        },
    }
    return [
        bind_function(read_result, description=read_description, annotations=annotations, output_schema=read_schema),
        bind_function(
            search_result, description=search_description, annotations=annotations, output_schema=search_schema
        ),
    ]


__all__ = ["build_result_tools"]
