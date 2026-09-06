"""MCP resources and tools that read back stored large results."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated, Any

import regex
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.result_compaction import _RESULT_METADATA_JSON_CHARS, _bounded_json_string, _json_text
from ghidra_mcp.presentation.result_store import ResultResourceStore, StoredToolResult

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


def register_result_resources(mcp, *, store: ResultResourceStore) -> None:
    """Advertise ``ghidra://results/{result_id}`` through the public resource API.

    The SDK template carries a single static MIME type.  ``GhidraMCPServer``
    overrides the public ``read_resource`` hook to serve each stored entry with
    its own MIME type; this decorator-registered template keeps the URI listed
    in ``resources/templates/list`` and serves reads on a plain ``MCPServer``.
    """

    @mcp.resource(
        "ghidra://results/{result_id}",
        name="ghidra_tool_result",
        description="Full payload for a truncated Ghidra MCP tool result.",
        mime_type="text/plain",
    )
    def _read_result_resource(result_id: str) -> str:
        return store.read_text(result_id)


def _get_entry(store: ResultResourceStore, result_id: str) -> StoredToolResult:
    try:
        return store.get(result_id)
    except KeyError as exc:
        # ToolError is the SDK's "anticipated failure": the message reaches the
        # client verbatim instead of being replaced by a generic crash notice.
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
    low = 0
    high = len(candidate)
    while low < high:
        middle = (low + high + 1) // 2
        payload = _read_result_payload(entry, offset=offset, chunk=candidate[:middle])
        if len(_json_text(payload, indent=2)) <= budget:
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


def _fit_reported_search_pattern(
    entry: StoredToolResult,
    *,
    pattern: str,
    match_count: int,
    scan_truncated: bool,
    budget: int,
) -> tuple[str, bool]:
    full_response = _search_result_payload(
        entry,
        pattern=pattern,
        pattern_truncated=False,
        match_count=match_count,
        scan_truncated=scan_truncated,
        matches=[],
    )
    if len(_json_text(full_response, indent=2)) <= budget:
        return pattern, False

    low = 0
    high = len(pattern)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = _search_result_payload(
            entry,
            pattern=pattern[:middle],
            pattern_truncated=True,
            match_count=match_count,
            scan_truncated=scan_truncated,
            matches=[],
        )
        if len(_json_text(candidate, indent=2)) <= budget:
            low = middle
        else:
            high = middle - 1
    return pattern[:low], True


def _search_stored_result(
    entry: StoredToolResult,
    *,
    pattern: str,
    context_chars: int,
    max_matches: int,
    configured_budget: int,
) -> dict[str, Any]:
    _validate_search_pattern(pattern)
    try:
        compiled = regex.compile(pattern)
    except regex.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc

    context = max(0, min(context_chars, _SEARCH_CONTEXT_MAX_CHARS))
    shown_limit = min(max(max_matches, 0), _SEARCH_MAX_MATCHES_CAP)
    candidates: list[dict[str, Any]] = []
    first_minimal: dict[str, Any] | None = None
    match_count = 0
    scan_truncated = False
    deadline = time.monotonic() + _SEARCH_TIMEOUT_SECONDS
    try:
        for found in compiled.finditer(
            entry.text,
            timeout=_SEARCH_TIMEOUT_SECONDS,
            concurrent=True,
        ):
            if match_count >= _SEARCH_SCAN_CAP or time.monotonic() >= deadline:
                scan_truncated = True
                break
            match_count += 1
            if len(candidates) >= shown_limit:
                continue
            start, end = found.span()
            display_end = min(end, start + _SEARCH_MATCH_DISPLAY_MAX_CHARS)
            matched = entry.text[start:display_end]
            context_start = max(0, start - context)
            context_end = min(len(entry.text), display_end + context)
            snippet = entry.text[context_start:context_end]
            candidate = {
                "offset_chars": start,
                "end_offset": end,
                "match_chars": end - start,
                "match_truncated": display_end < end,
                "match": matched,
                "context_offset_chars": context_start,
                "context": snippet,
            }
            candidates.append(candidate)
            if first_minimal is None:
                first_minimal = {
                    "offset_chars": start,
                    "end_offset": end,
                    "match_chars": end - start,
                    "match_truncated": end - start > len(matched[:80]),
                    "match": matched[:80],
                    "context_offset_chars": start,
                    "context": "",
                }
    except TimeoutError as exc:
        raise ValueError(
            f"Search timed out after {_SEARCH_TIMEOUT_SECONDS:g}s — the pattern is "
            "too expensive for the stored text (e.g. catastrophic backtracking). "
            "Simplify the pattern or page through the payload with read_result."
        ) from exc

    budget = max(configured_budget, _MIN_RESULT_TOOL_RESPONSE_CHARS)
    reported_pattern, pattern_truncated = _fit_reported_search_pattern(
        entry,
        pattern=pattern,
        match_count=match_count,
        scan_truncated=scan_truncated,
        budget=budget,
    )
    while candidates:
        response = _search_result_payload(
            entry,
            pattern=reported_pattern,
            pattern_truncated=pattern_truncated,
            match_count=match_count,
            scan_truncated=scan_truncated,
            matches=candidates,
        )
        if len(_json_text(response, indent=2)) <= budget:
            return response
        candidates.pop()

    if first_minimal is not None and shown_limit > 0:
        minimal_response = _search_result_payload(
            entry,
            pattern=reported_pattern,
            pattern_truncated=pattern_truncated,
            match_count=match_count,
            scan_truncated=scan_truncated,
            matches=[first_minimal],
        )
        if len(_json_text(minimal_response, indent=2)) <= budget:
            return minimal_response

    return _search_result_payload(
        entry,
        pattern=reported_pattern,
        pattern_truncated=pattern_truncated,
        match_count=match_count,
        scan_truncated=scan_truncated,
        matches=[],
    )


def register_result_tools(mcp, *, store: ResultResourceStore, config: ToolPresentationConfig) -> None:
    """Register retrieval tools over the stored large results.

    These are presentation-layer infrastructure tools (not ToolSpec-based):
    tools-only MCP clients — most local-LLM harnesses — cannot issue
    resources/read, so paged reads and regex search over stored payloads must be
    reachable through tools/call.
    """
    annotations = ToolAnnotations(read_only_hint=True, idempotent_hint=True)

    # structured_output=False keeps the MCP SDK from delivering every response
    # twice (indent=2 JSON text plus a structuredContent duplicate), which
    # would defeat the size cap these tools exist to enforce.
    @mcp.tool(
        annotations=annotations,
        structured_output=False,
        description=(
            "Read a slice of a stored large tool result. Use the result_id from a "
            "truncated tool result, then page with offset_chars/limit_chars until "
            "has_more is false. limit_chars defaults to a third of the server's "
            "compaction threshold and is capped at the threshold. The complete "
            "response is capped at max(threshold, 1024) serialized characters."
        ),
    )
    def read_result(result_id: _ResultId, offset_chars: int = 0, limit_chars: int | None = None) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        offset = min(max(0, offset_chars), entry.size_chars)
        # Default page: a third of the threshold, so operators tuning the
        # threshold get a proportionate page size without a second knob.
        if limit_chars is None:
            limit_chars = max(1, config.large_result_threshold_chars // 3)
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

    @mcp.tool(
        annotations=annotations,
        structured_output=False,
        description=(
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
            "the echoed pattern and displayed snippets may be shortened."
        ),
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
            )
        except ValueError as exc:
            raise ToolError(str(exc)) from exc


__all__ = ["register_result_resources", "register_result_tools"]
