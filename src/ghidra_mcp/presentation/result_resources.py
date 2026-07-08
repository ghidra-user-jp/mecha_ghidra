"""In-memory resources for large MCP tool results."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import regex

from mcp.server.fastmcp.resources import FunctionResource
from mcp.server.fastmcp.resources.templates import ResourceTemplate
from mcp.types import CallToolResult, ResourceLink, TextContent, ToolAnnotations
from pydantic import PrivateAttr
from pydantic_core import to_json

from ghidra_mcp.presentation.config import ToolPresentationConfig


logger = logging.getLogger(__name__)


RESULT_RESOURCE_PREFIX = "ghidra://results/"

_SEARCH_CONTEXT_MAX_CHARS = 2000
_SEARCH_MATCH_DISPLAY_MAX_CHARS = 500
_SEARCH_MAX_MATCHES_CAP = 100
_SEARCH_SCAN_CAP = 10_000
_SEARCH_MAX_PATTERN_CHARS = 512

# search_result runs a client-supplied regex inline on the server's event loop
# (FastMCP calls sync tools directly, and CPython regex engines hold the GIL), so
# a catastrophic-backtracking pattern would hang the whole server. Static pattern
# screening cannot draw that line reliably — it both misses dangerous patterns
# (e.g. "(a|a)+x") and rejects safe ones (e.g. "(\w+) +=") — so matching runs on
# the third-party `regex` engine, which enforces a hard per-step timeout, plus an
# overall scan deadline between matches.
_SEARCH_TIMEOUT_SECONDS = 1.0


def _validate_search_pattern(pattern: str) -> None:
    if len(pattern) > _SEARCH_MAX_PATTERN_CHARS:
        raise ValueError(
            f"Search pattern too long ({len(pattern)} chars; max {_SEARCH_MAX_PATTERN_CHARS})."
        )


@dataclass(frozen=True, slots=True)
class StoredToolResult:
    result_id: str
    uri: str
    text: str
    mime_type: str
    size_chars: int
    size_bytes: int
    tool: str
    target: str
    result_type: str
    item_count: int | None


class ResultResourceStore:
    def __init__(self, *, max_entries: int = 512, max_bytes: int = 134_217_728) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        if max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._total_bytes = 0
        self._entries: OrderedDict[str, StoredToolResult] = OrderedDict()

    def add(
        self,
        *,
        tool: str,
        target: str,
        text: str,
        mime_type: str,
        result_type: str,
        item_count: int | None,
    ) -> StoredToolResult | None:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > self._max_bytes:
            # A single payload larger than the whole cache budget can never be
            # retained without exceeding the operator-configured memory cap;
            # refuse to cache it instead of silently blowing past the cap.
            return None
        payload_hash = hashlib.sha256(encoded).hexdigest()
        # Content-addressed id: repeating the same call reuses the stored entry
        # instead of duplicating it, and the URI stays stable across turns.
        seed = f"{tool}:{target}:{mime_type}:{payload_hash}".encode()
        result_id = hashlib.sha256(seed).hexdigest()[:16]
        existing = self._entries.get(result_id)
        if existing is not None:
            self._entries.move_to_end(result_id)
            return existing
        entry = StoredToolResult(
            result_id=result_id,
            uri=f"{RESULT_RESOURCE_PREFIX}{result_id}",
            text=text,
            mime_type=mime_type,
            size_chars=len(text),
            size_bytes=len(encoded),
            tool=tool,
            target=target,
            result_type=result_type,
            item_count=item_count,
        )
        self._entries[result_id] = entry
        self._total_bytes += entry.size_bytes
        # Evict oldest entries past either budget, but never the entry just added.
        while len(self._entries) > 1 and (
            len(self._entries) > self._max_entries or self._total_bytes > self._max_bytes
        ):
            _, evicted = self._entries.popitem(last=False)
            self._total_bytes -= evicted.size_bytes
        return entry

    def get(self, result_id: str) -> StoredToolResult:
        try:
            entry = self._entries[result_id]
        except KeyError as exc:
            raise KeyError(
                f"Unknown or evicted result id: {result_id}. Stored results are dropped "
                "when the cache budget is exceeded; re-run the original tool to regenerate it."
            ) from exc
        self._entries.move_to_end(result_id)
        return entry

    def read_text(self, result_id: str) -> str:
        return self.get(result_id).text


class _ResultResourceTemplate(ResourceTemplate):
    _store: ResultResourceStore = PrivateAttr()

    def bind_store(self, store: ResultResourceStore) -> "_ResultResourceTemplate":
        self._store = store
        return self

    async def create_resource(self, uri: str, params: dict[str, Any], context=None) -> FunctionResource:  # noqa: ANN001, ARG002
        entry = self._store.get(str(params["result_id"]))
        return FunctionResource(
            uri=uri,  # type: ignore[arg-type]
            name=self.name,
            title=self.title,
            description=self.description,
            mime_type=entry.mime_type,
            icons=self.icons,
            annotations=self.annotations,
            meta=self.meta,
            fn=lambda: entry.text,
        )


def _is_normalized_empty_list_result(result: CallToolResult) -> bool:
    if result.isError or result.structuredContent is not None or len(result.content) != 1:
        return False
    item = result.content[0]
    return isinstance(item, TextContent) and item.text == "[]"


def _json_text(value: Any, *, indent: int | None = None) -> str:
    # pydantic_core.to_json is the serializer FastMCP delivers inline results
    # with: unlike json.dumps(default=str) it also stringifies non-string dict
    # keys (enums, Java objects) instead of raising TypeError, and serializes
    # pydantic models structurally instead of as repr strings — so the stored
    # payload matches what inline delivery would have produced.
    return to_json(value, fallback=str, indent=indent).decode("utf-8")


def _serialize_result(result: Any, *, tool_name: str) -> tuple[str, str, str, int | None]:
    if isinstance(result, str):
        mime_type = "text/x-c" if tool_name == "decompile_function" else "text/plain"
        return result, mime_type, "string", None
    if isinstance(result, CallToolResult):
        if (
            result.structuredContent is None
            and len(result.content) == 1
            and isinstance(result.content[0], TextContent)
        ):
            return result.content[0].text, "text/plain", "call_tool_result_text", None
        return (
            _json_text(result.model_dump(mode="json", by_alias=True)),
            "application/json",
            "call_tool_result",
            len(result.content),
        )
    if isinstance(result, (list, tuple)):
        return _json_text(result), "application/json", "list", len(result)
    if isinstance(result, dict):
        return _json_text(result), "application/json", "dict", None
    return str(result), "text/plain", type(result).__name__, None


def _delivered_inline_size(result: Any, *, tool_name: str) -> int:
    """Chars FastMCP would put in context if this result were returned inline.

    The compaction decision must reflect what the client actually receives.
    FastMCP re-serializes non-string results with pydantic_core.to_json(indent=2)
    (per item for lists), which is ~1.6-1.8x larger than compact json.dumps. We
    still *store* the compact form (cheaper to page), but we *decide* on the
    indent=2 size so results are not silently delivered inline over the cap.
    """
    if isinstance(result, str):
        return len(result)
    if isinstance(result, CallToolResult):
        # FastMCP passes CallToolResult through unchanged.
        text, *_ = _serialize_result(result, tool_name=tool_name)
        return len(text)
    if isinstance(result, (list, tuple)):
        return sum(_delivered_inline_size(item, tool_name=tool_name) for item in result)
    return len(_json_text(result, indent=2))


def _embedded_json_chars(text: str) -> int:
    """Chars ``text`` occupies once embedded as a JSON string (sans quotes)."""
    return len(json.dumps(text, ensure_ascii=False)) - 2


# Preview budgets by result type, as fractions of the configured
# large_result_preview_chars. Text payloads (e.g. decompiled C) front-load
# meaning, so they get the full budget; homogeneous JSON lists only need a few
# complete example items to convey their schema; structured dicts sit between.
_PREVIEW_BUDGET_SCALE: dict[str, float] = {
    "list": 0.25,
    "dict": 0.5,
    "call_tool_result": 0.5,
}


def _preview_budget(result_type: str, configured_chars: int) -> int:
    return int(configured_chars * _PREVIEW_BUDGET_SCALE.get(result_type, 1.0))


def _list_preview(items, budget: int) -> tuple[str, int, int] | None:
    """Preview the first complete items of a list result, as valid JSON.

    Returns ``(preview, covered_chars, shown_items)`` where ``covered_chars``
    is the prefix of the stored compact JSON the preview corresponds to (the
    read_result continuation offset), or None when not even one item fits —
    callers then fall back to a plain prefix slice.
    """
    if budget <= 2:
        return None
    parts: list[str] = []
    used = 2  # "[" and "]"
    for item in items:
        piece = _json_text(item)
        cost = len(piece) + (1 if parts else 0)
        if used + cost > budget:
            break
        parts.append(piece)
        used += cost
    if not parts:
        return None
    # The stored text is "[" + ",".join(all pieces) + "]"; the preview covers
    # its first `used - 1` chars (the closing bracket stands in for the comma).
    return "[" + ",".join(parts) + "]", used - 1, len(parts)


def _preview_slice(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    # Prefer cutting at a line boundary near the limit so code/JSON previews do
    # not end mid-token; fall back to a hard cut for single-line payloads.
    cut = text.rfind("\n", (limit * 4) // 5, limit + 1)
    if cut > 0:
        return text[:cut]
    return text[:limit]


def _truncation_notice(
    entry: StoredToolResult,
    preview: str,
    *,
    preview_desc: str,
    continue_offset: int,
) -> str:
    lines = [
        f"[{entry.tool}] result is {entry.size_chars:,} chars; {preview_desc}.",
        (
            f"Continue with read_result(result_id='{entry.result_id}', offset_chars={continue_offset}) "
            f"or find specific content with search_result(result_id='{entry.result_id}', pattern='...')."
        ),
        f"Clients with MCP resource support can read the full payload at {entry.uri}.",
    ]
    if preview:
        lines.append("----- preview -----")
        lines.append(preview)
    return "\n".join(lines)


def maybe_compact_tool_result(
    *,
    tool_name: str,
    target: str,
    result: Any,
    config: ToolPresentationConfig,
    store: ResultResourceStore | None,
) -> Any:
    if store is None or config.large_result_mode == "inline":
        return result
    if isinstance(result, CallToolResult):
        if result.isError or _is_normalized_empty_list_result(result):
            return result
    text, mime_type, result_type, item_count = _serialize_result(result, tool_name=tool_name)
    threshold = config.large_result_threshold_chars
    if isinstance(result, (str, CallToolResult)):
        # FastMCP delivers exactly the serialized text for these.
        if len(text) <= threshold:
            return result
    else:
        # The compact text minus list separators lower-bounds the delivered
        # indent=2 size, so payloads already over the threshold in compact form
        # skip the expensive full re-serialization of the probe.
        separators = item_count + 1 if isinstance(result, (list, tuple)) else 0
        if len(text) - separators <= threshold and (
            _delivered_inline_size(result, tool_name=tool_name) <= threshold
        ):
            return result

    entry = store.add(
        tool=tool_name,
        target=target,
        text=text,
        mime_type=mime_type,
        result_type=result_type,
        item_count=item_count,
    )
    if entry is None:
        # Larger than the whole cache budget: caching would break the
        # operator-configured memory cap, so deliver the payload inline.
        return result
    budget = _preview_budget(result_type, config.large_result_preview_chars)
    preview = _preview_slice(text, budget)
    preview_desc = f"showing the first {len(preview):,}"
    continue_offset = len(preview)
    if isinstance(result, (list, tuple)):
        item_preview = _list_preview(result, budget)
        if item_preview is not None:
            preview, continue_offset, shown_items = item_preview
            preview_desc = f"showing the first {shown_items} of {item_count} items"
    metadata = {
        "tool": tool_name,
        "target": target,
        "truncated": True,
        "result_id": entry.result_id,
        "resource_uri": entry.uri,
        "size_chars": entry.size_chars,
        "preview_chars": len(preview),
        "mime_type": mime_type,
        "result_type": result_type,
        "item_count": item_count,
    }
    return CallToolResult(
        content=[
            # The preview must live in the text block: many clients only surface
            # `content` to the model, so structuredContent-only data is invisible.
            TextContent(
                type="text",
                text=_truncation_notice(
                    entry,
                    preview,
                    preview_desc=preview_desc,
                    continue_offset=continue_offset,
                ),
            ),
            ResourceLink(
                type="resource_link",
                name=f"{tool_name} result",
                uri=entry.uri,
                description=f"Full result from {tool_name}.",
                mimeType=mime_type,
                size=entry.size_bytes,
            ),
        ],
        structuredContent=metadata,
    )


def register_result_resources(mcp, *, store: ResultResourceStore) -> None:
    def _read_result_resource(result_id: str) -> str:
        return store.read_text(result_id)

    template = _ResultResourceTemplate.from_function(
        _read_result_resource,
        uri_template="ghidra://results/{result_id}",
        name="ghidra_tool_result",
        description="Full payload for a truncated Ghidra MCP tool result.",
        mime_type="text/plain",
    ).bind_store(store)
    # FastMCP's public resource decorator stores a static mime_type on templates.
    # The result template needs per-entry MIME types, so register this small
    # ResourceTemplate subclass directly with the SDK's resource manager. The
    # mcp dependency pin is open (<2), so guard the private attributes and fall
    # back to the public decorator (static text/plain MIME type) instead of
    # crashing server startup if a future release renames them.
    resource_manager = getattr(mcp, "_resource_manager", None)
    templates = getattr(resource_manager, "_templates", None)
    if isinstance(templates, dict):
        templates[template.uri_template] = template
        return
    logger.warning(
        "FastMCP private resource-template registry is unavailable; registering "
        "ghidra://results/{result_id} with a static text/plain MIME type instead"
    )
    mcp.resource(
        "ghidra://results/{result_id}",
        name="ghidra_tool_result",
        description="Full payload for a truncated Ghidra MCP tool result.",
        mime_type="text/plain",
    )(_read_result_resource)


def _get_entry(store: ResultResourceStore, result_id: str) -> StoredToolResult:
    try:
        return store.get(result_id)
    except KeyError as exc:
        raise ValueError(str(exc.args[0]) if exc.args else str(exc)) from exc


def register_result_tools(mcp, *, store: ResultResourceStore, config: ToolPresentationConfig) -> None:
    """Register retrieval tools over the stored large results.

    These are presentation-layer infrastructure tools (not ToolSpec-based):
    tools-only MCP clients — most local-LLM harnesses — cannot issue
    resources/read, so paged reads and regex search over stored payloads must be
    reachable through tools/call.
    """
    annotations = ToolAnnotations(readOnlyHint=True, idempotentHint=True)

    # structured_output=False keeps FastMCP from delivering every response
    # twice (indent=2 JSON text plus a structuredContent duplicate), which
    # would defeat the size cap these tools exist to enforce.
    @mcp.tool(
        annotations=annotations,
        structured_output=False,
        description=(
            "Read a slice of a stored large tool result. Use the result_id from a "
            "truncated tool result, then page with offset_chars/limit_chars until "
            "has_more is false."
        ),
    )
    def read_result(result_id: str, offset_chars: int = 0, limit_chars: int = 4000) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        offset = max(0, offset_chars)
        # Cap slices at the compaction threshold, measured as delivered: the
        # response embeds the chunk as a JSON string, so escaping (newlines,
        # quotes) inflates its size. Trim until the embedded cost fits; the
        # fixed metadata fields only add a small constant on top.
        limit = max(1, min(limit_chars, config.large_result_threshold_chars))
        chunk = entry.text[offset : offset + limit]
        while len(chunk) > 1:
            excess = _embedded_json_chars(chunk) - config.large_result_threshold_chars
            if excess <= 0:
                break
            chunk = chunk[: max(1, len(chunk) - excess)]
        next_offset = offset + len(chunk)
        has_more = next_offset < entry.size_chars
        return {
            "result_id": entry.result_id,
            "tool": entry.tool,
            "target": entry.target,
            "mime_type": entry.mime_type,
            "offset_chars": offset,
            "chunk_chars": len(chunk),
            "total_chars": entry.size_chars,
            "has_more": has_more,
            "next_offset_chars": next_offset if has_more else None,
            "chunk": chunk,
        }

    @mcp.tool(
        annotations=annotations,
        structured_output=False,
        description=(
            "Search a stored large tool result with a Python regex. Returns matches "
            "with character offsets (usable as read_result offset_chars) and "
            "surrounding context."
        ),
    )
    def search_result(
        result_id: str,
        pattern: str,
        context_chars: int = 200,
        max_matches: int = 20,
    ) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        _validate_search_pattern(pattern)
        try:
            compiled = regex.compile(pattern)
        except regex.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        context = max(0, min(context_chars, _SEARCH_CONTEXT_MAX_CHARS))
        shown_limit = max(1, min(max_matches, _SEARCH_MAX_MATCHES_CAP))
        budget = config.large_result_threshold_chars
        matches: list[dict[str, Any]] = []
        used_chars = 0
        match_count = 0
        scan_truncated = False
        # The per-step timeout bounds a single matching step; the deadline bounds
        # the whole scan when every step is slow but succeeds.
        deadline = time.monotonic() + _SEARCH_TIMEOUT_SECONDS
        try:
            for found in compiled.finditer(entry.text, timeout=_SEARCH_TIMEOUT_SECONDS):
                if match_count >= _SEARCH_SCAN_CAP or time.monotonic() >= deadline:
                    scan_truncated = True
                    break
                match_count += 1
                if len(matches) >= shown_limit or used_chars >= budget:
                    continue
                start, end = found.span()
                matched = found.group(0)
                if len(matched) > _SEARCH_MATCH_DISPLAY_MAX_CHARS:
                    matched = matched[:_SEARCH_MATCH_DISPLAY_MAX_CHARS]
                context_start = max(0, start - context)
                context_end = min(len(entry.text), end + context)
                context_end = min(context_end, context_start + 2 * context + _SEARCH_MATCH_DISPLAY_MAX_CHARS)
                snippet = entry.text[context_start:context_end]
                if matches and used_chars + len(snippet) > budget:
                    # Admitting this snippet would blow the response budget by up
                    # to 2*context + 500 chars; only the first match may exceed it
                    # so a tiny budget still returns something actionable.
                    continue
                used_chars += len(snippet)
                matches.append(
                    {
                        "offset_chars": start,
                        "match": matched,
                        "context_offset_chars": context_start,
                        "context": snippet,
                    }
                )
        except TimeoutError as exc:
            raise ValueError(
                f"Search timed out after {_SEARCH_TIMEOUT_SECONDS:g}s — the pattern is "
                "too expensive for the stored text (e.g. catastrophic backtracking). "
                "Simplify the pattern or page through the payload with read_result."
            ) from exc
        return {
            "result_id": entry.result_id,
            "pattern": pattern,
            "match_count": match_count,
            "scan_truncated": scan_truncated,
            "matches_shown": len(matches),
            "matches": matches,
        }


__all__ = [
    "RESULT_RESOURCE_PREFIX",
    "ResultResourceStore",
    "StoredToolResult",
    "maybe_compact_tool_result",
    "register_result_resources",
    "register_result_tools",
]
