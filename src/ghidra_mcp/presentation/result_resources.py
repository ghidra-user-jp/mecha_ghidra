"""In-memory resources for large MCP tool results."""

from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp.resources import FunctionResource
from mcp.server.fastmcp.resources.templates import ResourceTemplate
from mcp.types import CallToolResult, ResourceLink, TextContent, ToolAnnotations
from pydantic import PrivateAttr

from ghidra_mcp.presentation.config import ToolPresentationConfig


RESULT_RESOURCE_PREFIX = "ghidra://results/"

_SEARCH_CONTEXT_MAX_CHARS = 2000
_SEARCH_MATCH_DISPLAY_MAX_CHARS = 500
_SEARCH_MAX_MATCHES_CAP = 100
_SEARCH_SCAN_CAP = 10_000


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
    ) -> StoredToolResult:
        encoded = text.encode("utf-8", errors="replace")
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
            json.dumps(result.model_dump(mode="json", by_alias=True), ensure_ascii=False, default=str),
            "application/json",
            "call_tool_result",
            len(result.content),
        )
    if isinstance(result, list):
        return json.dumps(result, ensure_ascii=False, default=str), "application/json", "list", len(result)
    if isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False, default=str), "application/json", "dict", None
    return str(result), "text/plain", type(result).__name__, None


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


def _truncation_notice(entry: StoredToolResult, preview: str) -> str:
    lines = [
        f"[{entry.tool}] result is {entry.size_chars:,} chars; showing the first {len(preview):,}.",
        (
            f"Continue with read_result(result_id='{entry.result_id}', offset_chars={len(preview)}) "
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
    if config.large_result_mode == "inline":
        return result
    if isinstance(result, CallToolResult):
        if result.isError or _is_normalized_empty_list_result(result):
            return result
    text, mime_type, result_type, item_count = _serialize_result(result, tool_name=tool_name)
    if len(text) <= config.large_result_threshold_chars:
        return result
    if store is None:
        return result

    entry = store.add(
        tool=tool_name,
        target=target,
        text=text,
        mime_type=mime_type,
        result_type=result_type,
        item_count=item_count,
    )
    preview = _preview_slice(text, config.large_result_preview_chars)
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
            TextContent(type="text", text=_truncation_notice(entry, preview)),
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
    # ResourceTemplate subclass directly with the SDK's resource manager.
    mcp._resource_manager._templates[template.uri_template] = template  # noqa: SLF001


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

    @mcp.tool(
        annotations=annotations,
        description=(
            "Read a slice of a stored large tool result. Use the result_id from a "
            "truncated tool result, then page with offset_chars/limit_chars until "
            "has_more is false."
        ),
    )
    def read_result(result_id: str, offset_chars: int = 0, limit_chars: int = 4000) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        offset = max(0, offset_chars)
        # Cap slices below the compaction threshold so a read_result response can
        # never itself qualify as a "large result".
        limit = max(1, min(limit_chars, config.large_result_threshold_chars))
        chunk = entry.text[offset : offset + limit]
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
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        context = max(0, min(context_chars, _SEARCH_CONTEXT_MAX_CHARS))
        shown_limit = max(1, min(max_matches, _SEARCH_MAX_MATCHES_CAP))
        budget = config.large_result_threshold_chars
        matches: list[dict[str, Any]] = []
        used_chars = 0
        match_count = 0
        scan_truncated = False
        for found in compiled.finditer(entry.text):
            if match_count >= _SEARCH_SCAN_CAP:
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
            used_chars += len(snippet)
            matches.append(
                {
                    "offset_chars": start,
                    "match": matched,
                    "context_offset_chars": context_start,
                    "context": snippet,
                }
            )
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
