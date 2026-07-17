"""In-memory resources for large MCP tool results."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Annotated, Any

import regex

from mcp.server.fastmcp import Audio, Image
from mcp.server.fastmcp.resources import FunctionResource
from mcp.server.fastmcp.resources.templates import ResourceTemplate
from mcp.types import CallToolResult, ContentBlock, ResourceLink, TextContent, ToolAnnotations
from pydantic import BaseModel, Field, PrivateAttr
from pydantic_core import to_json

from ghidra_mcp.presentation.config import ToolPresentationConfig


logger = logging.getLogger(__name__)


RESULT_RESOURCE_PREFIX = "ghidra://results/"

_SEARCH_CONTEXT_MAX_CHARS = 2000
_SEARCH_MATCH_DISPLAY_MAX_CHARS = 500
_SEARCH_MAX_MATCHES_CAP = 100
_SEARCH_SCAN_CAP = 10_000
_SEARCH_MAX_PATTERN_CHARS = 512
_MIN_RESULT_TOOL_RESPONSE_CHARS = 1024
_MIN_COMPACT_RESULT_RESPONSE_CHARS = 2048
_RESULT_METADATA_JSON_CHARS = 128
_ResultId = Annotated[
    str,
    Field(min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$"),
]

# Static pattern screening cannot reliably separate safe expressions from ReDoS
# patterns. Matching therefore uses the third-party `regex` engine's timeout and
# runs in a worker thread so an expensive expression does not block FastMCP's
# event loop. ``concurrent=True`` asks regex to release the GIL while matching.
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
    cache_size_bytes: int
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
        # FastMCP may execute synchronous tools concurrently in worker threads,
        # while resource reads and search requests touch the same LRU. Keep each
        # identity-check/insert/evict and get/move operation atomic.
        self._lock = threading.RLock()

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

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
        payload_hash = hashlib.sha256(encoded).hexdigest()
        # Content-addressed id: repeating the same call reuses the stored entry
        # instead of duplicating it, and the URI stays stable across turns.
        # Metadata participates in the identity as well as the payload. The
        # same JSON text can legitimately represent different logical result
        # types; reusing an entry from another type would return stale metadata
        # and could invalidate the response-size calculation performed before
        # insertion.
        seed = to_json(
            [tool, target, mime_type, result_type, item_count, payload_hash],
            fallback=str,
        )
        result_id = hashlib.sha256(seed).hexdigest()[:16]
        uri = f"{RESULT_RESOURCE_PREFIX}{result_id}"
        # ``size_bytes`` remains the payload size exposed to MCP clients.  Cache
        # accounting also includes every retained metadata value, otherwise a
        # tiny payload with a multi-megabyte target/tool name can bypass the
        # operator's memory budget.  The serialized representation is a stable,
        # conservative logical footprint (independent of Python object layout).
        metadata = {
            "result_id": result_id,
            "uri": uri,
            "mime_type": mime_type,
            "size_chars": len(text),
            "size_bytes": len(encoded),
            "tool": tool,
            "target": target,
            "result_type": result_type,
            "item_count": item_count,
        }
        cache_size_bytes = len(encoded) + len(to_json(metadata, fallback=str))
        with self._lock:
            existing = self._entries.get(result_id)
            if existing is not None:
                self._entries.move_to_end(result_id)
                return existing
            if cache_size_bytes > self._max_bytes:
                # A single entry larger than the whole cache budget can never be
                # retained without exceeding the operator-configured memory cap.
                return None
            entry = StoredToolResult(
                result_id=result_id,
                uri=uri,
                text=text,
                mime_type=mime_type,
                size_chars=len(text),
                size_bytes=len(encoded),
                cache_size_bytes=cache_size_bytes,
                tool=tool,
                target=target,
                result_type=result_type,
                item_count=item_count,
            )
            self._entries[result_id] = entry
            self._total_bytes += entry.cache_size_bytes
            # Evict oldest entries past either budget, but never the entry just added.
            while len(self._entries) > 1 and (
                len(self._entries) > self._max_entries
                or self._total_bytes > self._max_bytes
            ):
                _, evicted = self._entries.popitem(last=False)
                self._total_bytes -= evicted.cache_size_bytes
            return entry

    def get(self, result_id: str) -> StoredToolResult:
        if (
            not isinstance(result_id, str)
            or len(result_id) != 16
            or any(char not in "0123456789abcdef" for char in result_id)
        ):
            raise KeyError(
                "Invalid result id. Expected exactly 16 lowercase hexadecimal characters."
            )
        with self._lock:
            try:
                entry = self._entries[result_id]
            except KeyError as exc:
                raise KeyError(
                    f"Unknown or evicted result id: {result_id}. Stored results are dropped "
                    "when the cache budget is exceeded. Do not automatically re-run the "
                    "original tool because it may have had side effects; regenerate the "
                    "result only when the call is known to be safe or idempotent."
                ) from exc
            self._entries.move_to_end(result_id)
            return entry

    def read_text(self, result_id: str) -> str:
        return self.get(result_id).text


class _ResultResourceTemplate(ResourceTemplate):
    # FastMCP's base model defaults this field to ``text/plain`` even though
    # the MCP wire type permits it to be omitted.  Stored results can be C,
    # JSON, or plain text, so an absent template-level MIME is the only honest
    # declaration; create_resource supplies the concrete entry's MIME below.
    mime_type: str | None = Field(default=None)
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
    if (
        result.isError
        or result.meta is not None
        or bool(result.model_extra)
        or result.structuredContent is not None
        or len(result.content) != 1
    ):
        return False
    item = result.content[0]
    return (
        isinstance(item, TextContent)
        and item.text == "[]"
        and item.annotations is None
        and item.meta is None
        and not item.model_extra
    )


def _json_text(value: Any, *, indent: int | None = None) -> str:
    # pydantic_core.to_json is the serializer FastMCP delivers inline results
    # with: unlike json.dumps(default=str) it also stringifies non-string dict
    # keys (enums, Java objects) instead of raising TypeError, and serializes
    # pydantic models structurally instead of as repr strings — so the stored
    # payload matches what inline delivery would have produced.
    return to_json(value, fallback=str, indent=indent).decode("utf-8")


def _bounded_json_string(value: str, *, max_json_chars: int) -> tuple[str, bool]:
    """Bound a displayed string by its serialized JSON cost.

    User-controlled target names and patterns may consist entirely of control
    characters, quotes, or backslashes.  A raw-character slice therefore does
    not provide a response-size bound because each character can expand several
    times when FastMCP serializes the tool response.
    """
    if len(_json_text(value)) <= max_json_chars:
        return value, False
    low = 0
    high = len(value)
    while low < high:
        middle = (low + high + 1) // 2
        if len(_json_text(value[:middle])) <= max_json_chars:
            low = middle
        else:
            high = middle - 1
    return value[:low], True


def _is_plain_text_content(value: TextContent) -> bool:
    """Whether storing only ``text`` preserves the complete MCP block."""
    return (
        value.annotations is None
        and value.meta is None
        and not value.model_extra
    )


def _is_plain_text_call_result(value: CallToolResult) -> bool:
    """Whether a CallToolResult is exactly one unannotated success text block."""
    return (
        not value.isError
        and value.meta is None
        and not value.model_extra
        and value.structuredContent is None
        and len(value.content) == 1
        and isinstance(value.content[0], TextContent)
        and _is_plain_text_content(value.content[0])
    )


def _contains_explicit_content(value: Any) -> bool:
    """Return whether FastMCP will adapt any value into a non-generic block."""
    if isinstance(value, ContentBlock) or isinstance(value, (Image, Audio)):
        return True
    if isinstance(value, (list, tuple)):
        return any(_contains_explicit_content(item) for item in value)
    return False


def _content_block_payload(block: ContentBlock) -> dict[str, Any]:
    # MCP transports omit absent optional fields. Keeping the same shape avoids
    # storing synthetic nulls and makes wire-size comparisons exact.
    return block.model_dump(mode="json", by_alias=True, exclude_none=True)


def _prepare_result_for_compaction(value: Any) -> tuple[Any, bool]:
    """Normalize stateful FastMCP adapters and container subclasses once.

    FastMCP converts Image/Audio helpers once and iterates list/tuple subclasses
    using their Python iterator. The compaction pipeline performs several probes
    (storage, threshold, wire comparison, preview), so sharing one prepared value
    prevents repeated file reads/base64 work and keeps every probe on one order.
    Dicts are atomic to FastMCP's converter; pydantic_core observes their base
    storage rather than an overridden ``items()``, which we mirror for previews.
    """
    if isinstance(value, Image):
        return value.to_image_content(), True
    if isinstance(value, Audio):
        return value.to_audio_content(), True
    if isinstance(value, list):
        if type(value) is not list:
            prepared_items: list[Any] = []
            for item in value:
                prepared, _ = _prepare_result_for_compaction(item)
                prepared_items.append(prepared)
            return prepared_items, True
        prepared_items = None
        for index, item in enumerate(value):
            prepared, item_changed = _prepare_result_for_compaction(item)
            if item_changed and prepared_items is None:
                prepared_items = value[:index]
            if prepared_items is not None:
                prepared_items.append(prepared)
        return (prepared_items, True) if prepared_items is not None else (value, False)
    if isinstance(value, tuple):
        if type(value) is not tuple:
            prepared_items = []
            for item in value:
                prepared, _ = _prepare_result_for_compaction(item)
                prepared_items.append(prepared)
            return tuple(prepared_items), True
        prepared_items = None
        for index, item in enumerate(value):
            prepared, item_changed = _prepare_result_for_compaction(item)
            if item_changed and prepared_items is None:
                prepared_items = list(value[:index])
            if prepared_items is not None:
                prepared_items.append(prepared)
        return (
            (tuple(prepared_items), True)
            if prepared_items is not None
            else (value, False)
        )
    if isinstance(value, dict) and type(value) is not dict:
        # Call the base methods explicitly: a subclass may override iteration or
        # items() even though pydantic_core serializes the underlying dict order.
        return (
            {
                key: dict.__getitem__(value, key)
                for key in dict.keys(value)
            },
            True,
        )
    return value, False


def _serialize_result(result: Any, *, tool_name: str) -> tuple[str, str, str, int | None]:
    if isinstance(result, str):
        mime_type = "text/x-c" if tool_name == "decompile_function" else "text/plain"
        return result, mime_type, "string", None
    if isinstance(result, CallToolResult):
        if _is_plain_text_call_result(result):
            return result.content[0].text, "text/plain", "call_tool_result_text", None
        return (
            _json_text(
                result.model_dump(mode="json", by_alias=True, exclude_none=True)
            ),
            "application/json",
            "call_tool_result",
            len(result.content),
        )
    if isinstance(result, TextContent):
        # FastMCP returns a single TextContent block directly; its user-visible
        # payload is the text. Annotations and _meta are nevertheless part of
        # the result and require the structural representation to avoid loss.
        if _is_plain_text_content(result):
            return result.text, "text/plain", "text_content", None
        return (
            _json_text(_content_block_payload(result)),
            "application/json",
            "text_content_block",
            None,
        )
    if isinstance(result, ContentBlock):
        # Non-text blocks have no standalone text payload. Preserve the exact
        # MCP structure as JSON so resource reads can reconstruct what FastMCP
        # would otherwise have delivered inline.
        return (
            _json_text(_content_block_payload(result)),
            "application/json",
            "content_block",
            None,
        )
    if isinstance(result, (Image, Audio)):
        # These public FastMCP helpers have deliberately small repr strings,
        # while their wire blocks contain base64 payloads. Convert them before
        # thresholding/storing so large binary results cannot bypass compaction.
        block = _inline_content_blocks(result)[0]
        result_type = "image_content" if isinstance(result, Image) else "audio_content"
        return (
            _json_text(_content_block_payload(block)),
            "application/json",
            result_type,
            None,
        )
    if isinstance(result, (list, tuple)):
        if _contains_explicit_content(result):
            # FastMCP recursively flattens mixed lists containing ContentBlock,
            # Image, or Audio values. Store that actual wire-equivalent sequence
            # instead of helper repr strings that cannot reconstruct the result.
            blocks = _inline_content_blocks(result)
            return (
                _json_text([_content_block_payload(block) for block in blocks]),
                "application/json",
                "content_blocks",
                len(blocks),
            )
        return _json_text(result), "application/json", "list", len(result)
    if isinstance(result, dict):
        # item_count counts top-level entries, mirroring list semantics.
        return _json_text(result), "application/json", "dict", len(result)
    if isinstance(result, BaseModel):
        # FastMCP uses pydantic_core JSON for model results. Keep the compact
        # structural form in the resource rather than Python's repr.
        return _json_text(result), "application/json", "pydantic_model", None
    # Match FastMCP's generic conversion. pydantic_core handles dataclasses and
    # other supported values structurally, then uses repr-like fallback only
    # for values without a JSON representation.
    return _json_text(result), "application/json", type(result).__name__, None


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
        # FastMCP passes a top-level CallToolResult through, but its content
        # blocks represent the same user-visible payload as a raw list of those
        # blocks. Count block payloads consistently, then add only meaningful
        # outer metadata/structured content (not transport envelope overhead).
        content_chars = sum(
            _delivered_content_block_size(block) for block in result.content
        )
        outer = result.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"content", "isError"},
        )
        return content_chars + (len(_json_text(outer, indent=2)) if outer else 0)
    if isinstance(result, TextContent):
        if _is_plain_text_content(result):
            return len(result.text)
        return len(_json_text(_content_block_payload(result), indent=2))
    if isinstance(result, ContentBlock):
        return len(_json_text(_content_block_payload(result), indent=2))
    if isinstance(result, (Image, Audio)):
        block = _inline_content_blocks(result)[0]
        return _delivered_content_block_size(block)
    if isinstance(result, (list, tuple)):
        # Nested CallToolResult values are not passed through by FastMCP: only a
        # top-level CallToolResult is special. Its recursive list converter turns
        # each nested value into a TextContent JSON string. Measure those actual
        # converted blocks instead of applying top-level semantics recursively.
        return sum(
            _delivered_content_block_size(block)
            for block in _inline_content_blocks(result)
        )
    if result is None:
        return 0
    return len(_json_text(result, indent=2))


# Preview budgets by result type, as fractions of the configured
# large_result_preview_chars. Text payloads (e.g. decompiled C) front-load
# meaning, so they get the full budget; JSON lists and dicts only need a few
# complete example items/entries to convey their schema. Full CallToolResult
# dumps are heterogeneous (content blocks plus metadata), so they sit between.
_PREVIEW_BUDGET_SCALE: dict[str, float] = {
    "list": 0.25,
    "dict": 0.25,
    "call_tool_result": 0.5,
}


def _preview_budget(result_type: str, configured_chars: int) -> int:
    return int(configured_chars * _PREVIEW_BUDGET_SCALE.get(result_type, 1.0))


def _container_preview(pieces, open_char: str, close_char: str, budget: int) -> tuple[str, int, int] | None:
    """Assemble a valid-JSON preview from pre-serialized container pieces.

    Returns ``(preview, covered_chars, shown_pieces)`` where ``covered_chars``
    is the prefix of the stored compact JSON the preview corresponds to (the
    read_result continuation offset), or None when not even one piece fits —
    callers then fall back to a plain prefix slice.
    """
    if budget <= 2:
        return None
    parts: list[str] = []
    used = 2  # the enclosing pair of brackets/braces
    for piece in pieces:
        cost = len(piece) + (1 if parts else 0)
        if used + cost > budget:
            break
        parts.append(piece)
        used += cost
    if not parts:
        return None
    # The stored text is open + ",".join(all pieces) + close; the preview
    # covers its first `used - 1` chars (the closer stands in for the comma).
    return open_char + ",".join(parts) + close_char, used - 1, len(parts)


def _list_preview(items, budget: int) -> tuple[str, int, int] | None:
    """Preview the first complete items of a list result, as valid JSON."""
    return _container_preview((_json_text(item) for item in items), "[", "]", budget)


def _dict_preview(mapping: dict, budget: int) -> tuple[str, int, int] | None:
    """Preview the first complete top-level entries of a dict result.

    Each piece is serialized as a single-entry object with the braces stripped,
    so keys are stringified exactly as in the stored payload.
    """
    pieces = (
        _json_text({key: value})[1:-1]
        for key, value in dict.items(mapping)
    )
    return _container_preview(pieces, "{", "}", budget)


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


def _preview_for_budget(
    result: Any,
    *,
    text: str,
    result_type: str,
    item_count: int | None,
    budget: int,
) -> tuple[str, str, int]:
    """Build a preview and its exact continuation offset for one budget."""
    preview = _preview_slice(text, budget)
    preview_desc = f"showing the first {len(preview):,}"
    continue_offset = len(preview)
    container_preview = noun = None
    if result_type == "list" and isinstance(result, (list, tuple)):
        container_preview = _list_preview(result, budget)
        noun = "items"
    elif result_type == "dict" and isinstance(result, dict):
        container_preview = _dict_preview(result, budget)
        noun = "entries"
    if container_preview is not None:
        preview, continue_offset, shown = container_preview
        preview_desc = f"showing the first {shown} of {item_count} {noun}"
    return preview, preview_desc, continue_offset


def _truncation_notice(
    entry: StoredToolResult,
    preview: str,
    *,
    display_tool: str,
    preview_desc: str,
    continue_offset: int,
) -> str:
    lines = [
        f"[{display_tool}] result is {entry.size_chars:,} chars; {preview_desc}.",
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


def _build_compacted_result(
    entry: StoredToolResult,
    *,
    preview: str,
    preview_desc: str,
    continue_offset: int,
) -> CallToolResult:
    display_tool, tool_truncated = _bounded_json_string(
        entry.tool,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    display_target, target_truncated = _bounded_json_string(
        entry.target,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    display_result_type, result_type_truncated = _bounded_json_string(
        entry.result_type,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    metadata = {
        "tool": display_tool,
        "target": display_target,
        "truncated": True,
        "result_id": entry.result_id,
        "resource_uri": entry.uri,
        "size_chars": entry.size_chars,
        "preview_chars": len(preview),
        "mime_type": entry.mime_type,
        "result_type": display_result_type,
        "item_count": entry.item_count,
        "metadata_truncated": tool_truncated or target_truncated or result_type_truncated,
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
                    display_tool=display_tool,
                    preview_desc=preview_desc,
                    continue_offset=continue_offset,
                ),
            ),
            ResourceLink(
                type="resource_link",
                name=f"{display_tool} result",
                uri=entry.uri,
                description=f"Full result from {display_tool}.",
                mimeType=entry.mime_type,
                size=entry.size_bytes,
            ),
        ],
        structuredContent=metadata,
    )


def _uncacheable_result(
    *,
    tool_name: str,
    target: str,
    text: str,
    size_bytes: int,
    mime_type: str,
    result_type: str,
    item_count: int | None,
    cache_max_bytes: int,
) -> CallToolResult:
    display_tool, tool_truncated = _bounded_json_string(
        tool_name,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    display_target, target_truncated = _bounded_json_string(
        target,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    display_result_type, result_type_truncated = _bounded_json_string(
        result_type,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    message = (
        f"RESULT_TOO_LARGE: [{display_tool}] completed successfully and produced "
        f"{len(text):,} chars ({size_bytes:,} UTF-8 payload bytes), but the payload "
        f"and its metadata could not be retained within the result cache limit of "
        f"{cache_max_bytes:,} bytes. The full payload was not returned inline. "
        "Do not re-run a non-idempotent tool solely to recover this payload; narrow "
        "a subsequent query or increase --result-cache-max-bytes before a future call."
    )
    return CallToolResult(
        isError=False,
        content=[TextContent(type="text", text=message)],
        structuredContent={
            "tool": display_tool,
            "target": display_target,
            "truncated": True,
            "result_unavailable": True,
            "operation_succeeded": True,
            "size_chars": len(text),
            "size_bytes": size_bytes,
            "cache_max_bytes": cache_max_bytes,
            "mime_type": mime_type,
            "result_type": display_result_type,
            "item_count": item_count,
            "metadata_truncated": tool_truncated or target_truncated or result_type_truncated,
        },
    )


def _call_tool_result_wire_chars(result: CallToolResult) -> int:
    # stdio, SSE, websocket, and streamable HTTP transports all serialize MCP
    # models compactly with aliases and exclude_none=True. Outer JSON-RPC fields
    # are identical for inline/compacted results and therefore cancel out.
    return len(
        _json_text(
            result.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
    )


def _delivered_content_block_size(block: ContentBlock) -> int:
    """Measure one block using FastMCP's user-visible payload convention."""
    if isinstance(block, TextContent) and _is_plain_text_content(block):
        return len(block.text)
    return len(_json_text(_content_block_payload(block), indent=2))


def _inline_content_blocks(result: Any) -> list[ContentBlock]:
    """Mirror FastMCP's unstructured result conversion for wire comparison."""
    if result is None:
        return []
    if isinstance(result, ContentBlock):
        return [result]
    if isinstance(result, Image):
        return [result.to_image_content()]
    if isinstance(result, Audio):
        return [result.to_audio_content()]
    if isinstance(result, (list, tuple)):
        blocks: list[ContentBlock] = []
        for item in result:
            blocks.extend(_inline_content_blocks(item))
        return blocks
    text = result if isinstance(result, str) else _json_text(result, indent=2)
    return [TextContent(type="text", text=text)]


def _inline_result_wire_chars(result: Any) -> int:
    """Serialized CallToolResult size FastMCP would deliver without compaction."""
    if isinstance(result, CallToolResult):
        return _call_tool_result_wire_chars(result)
    return _call_tool_result_wire_chars(CallToolResult(content=_inline_content_blocks(result)))


def _maybe_compact_tool_result(
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
    prepared_result, prepared = _prepare_result_for_compaction(result)
    # A prepared helper/block sequence is wire-equivalent to the original and
    # avoids making FastMCP invoke a stateful adapter a second time on fallback.
    inline_result = prepared_result if prepared else result
    text, mime_type, result_type, item_count = _serialize_result(
        prepared_result,
        tool_name=tool_name,
    )
    threshold = config.large_result_threshold_chars
    inline_chars = _delivered_inline_size(prepared_result, tool_name=tool_name)
    if inline_chars <= threshold:
        return inline_result
    inline_wire_chars = _inline_result_wire_chars(prepared_result)

    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > store.max_bytes:
        uncacheable = _uncacheable_result(
            tool_name=tool_name,
            target=target,
            text=text,
            size_bytes=len(encoded),
            mime_type=mime_type,
            result_type=result_type,
            item_count=item_count,
            cache_max_bytes=store.max_bytes,
        )
        # A deliberately tiny threshold/cache must not turn a short result into
        # a larger error envelope.  Real oversized payloads still take the
        # compact error path and never leak their full contents inline.
        if _call_tool_result_wire_chars(uncacheable) >= inline_wire_chars:
            return inline_result
        return uncacheable

    # Result ids and URIs have fixed lengths. Build a provisional response before
    # touching the cache so very small thresholds do not replace a short inline
    # value with a larger notice/resource envelope.
    provisional = StoredToolResult(
        result_id="0" * 16,
        uri=f"{RESULT_RESOURCE_PREFIX}{'0' * 16}",
        text=text,
        mime_type=mime_type,
        size_chars=len(text),
        size_bytes=len(encoded),
        cache_size_bytes=0,
        tool=tool_name,
        target=target,
        result_type=result_type,
        item_count=item_count,
    )
    preview_budget = _preview_budget(result_type, config.large_result_preview_chars)
    preview, preview_desc, continue_offset = _preview_for_budget(
        prepared_result,
        text=text,
        result_type=result_type,
        item_count=item_count,
        budget=preview_budget,
    )
    provisional_result = _build_compacted_result(
        provisional,
        preview=preview,
        preview_desc=preview_desc,
        continue_offset=continue_offset,
    )
    response_budget = max(threshold, _MIN_COMPACT_RESULT_RESPONSE_CHARS)
    if _call_tool_result_wire_chars(provisional_result) > response_budget:
        # Preview characters can expand up to sixfold as JSON escapes. Find the
        # largest source preview whose *complete* CallToolResult stays inside
        # the response budget; for containers this also preserves valid JSON
        # and an exact continuation offset.
        low = 0
        high = preview_budget
        best = _preview_for_budget(
            prepared_result,
            text=text,
            result_type=result_type,
            item_count=item_count,
            budget=0,
        )
        while low < high:
            middle = (low + high + 1) // 2
            candidate = _preview_for_budget(
                prepared_result,
                text=text,
                result_type=result_type,
                item_count=item_count,
                budget=middle,
            )
            candidate_result = _build_compacted_result(
                provisional,
                preview=candidate[0],
                preview_desc=candidate[1],
                continue_offset=candidate[2],
            )
            if _call_tool_result_wire_chars(candidate_result) <= response_budget:
                low = middle
                best = candidate
            else:
                high = middle - 1
        preview, preview_desc, continue_offset = best
        provisional_result = _build_compacted_result(
            provisional,
            preview=preview,
            preview_desc=preview_desc,
            continue_offset=continue_offset,
        )
    if _call_tool_result_wire_chars(provisional_result) >= inline_wire_chars:
        return inline_result

    entry = store.add(
        tool=tool_name,
        target=target,
        text=text,
        mime_type=mime_type,
        result_type=result_type,
        item_count=item_count,
    )
    if entry is None:
        uncacheable = _uncacheable_result(
            tool_name=tool_name,
            target=target,
            text=text,
            size_bytes=len(encoded),
            mime_type=mime_type,
            result_type=result_type,
            item_count=item_count,
            cache_max_bytes=store.max_bytes,
        )
        if _call_tool_result_wire_chars(uncacheable) >= inline_wire_chars:
            return inline_result
        return uncacheable
    return _build_compacted_result(
        entry,
        preview=preview,
        preview_desc=preview_desc,
        continue_offset=continue_offset,
    )


def maybe_compact_tool_result(
    *,
    tool_name: str,
    target: str,
    result: Any,
    config: ToolPresentationConfig,
    store: ResultResourceStore | None,
) -> Any:
    """Compact a completed result without turning presentation faults into retries.

    The underlying tool may already have changed a Ghidra project by the time
    this presentation layer runs. A serializer/adapter/cache defect must not
    convert that completed operation into an MCP error, because an agent could
    then repeat a non-idempotent call. Fall back to the original result and log
    only the exception class; exception messages can contain result data and
    must not leak payloads into server logs.
    """
    try:
        return _maybe_compact_tool_result(
            tool_name=tool_name,
            target=target,
            result=result,
            config=config,
            store=store,
        )
    except Exception as exc:  # noqa: BLE001 - post-execution safety boundary
        logger.warning(
            "Large-result presentation failed for tool %s (%s); returning the "
            "original completed result",
            tool_name,
            type(exc).__name__,
        )
        return result


def register_result_resources(mcp, *, store: ResultResourceStore) -> None:
    def _read_result_resource(result_id: str) -> str:
        return store.read_text(result_id)

    template = _ResultResourceTemplate.from_function(
        _read_result_resource,
        uri_template="ghidra://results/{result_id}",
        name="ghidra_tool_result",
        description="Full payload for a truncated Ghidra MCP tool result.",
        mime_type=None,
    ).bind_store(store)
    # ResourceTemplate.from_function normalizes a false-y MIME to text/plain.
    # Restore the subclass' dynamic-MIME sentinel after it has built the input
    # schema and validated wrapper function.
    template.mime_type = None
    # FastMCP's public resource decorator stores a static mime_type on templates.
    # The result template needs per-entry MIME types, so register this small
    # ResourceTemplate subclass directly with the SDK's resource manager. The
    # mcp dependency pin is open (<2), so guard the private attributes and fall
    # back to the public decorator if a future release renames them.
    resource_manager = getattr(mcp, "_resource_manager", None)
    templates = getattr(resource_manager, "_templates", None)
    if isinstance(templates, dict):
        templates[template.uri_template] = template
        return
    logger.warning(
        "FastMCP private resource-template registry is unavailable; registering "
        "ghidra://results/{result_id} with FastMCP's static text/plain fallback"
    )
    mcp.resource(
        "ghidra://results/{result_id}",
        name="ghidra_tool_result",
        description="Full payload for a truncated Ghidra MCP tool result.",
        mime_type=None,
    )(_read_result_resource)


def _get_entry(store: ResultResourceStore, result_id: str) -> StoredToolResult:
    try:
        return store.get(result_id)
    except KeyError as exc:
        raise ValueError(str(exc.args[0]) if exc.args else str(exc)) from exc


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
            "has_more is false. limit_chars defaults to a third of the server's "
            "compaction threshold and is capped at the threshold. The complete "
            "response is capped at max(threshold, 1024) serialized characters."
        ),
    )
    def read_result(
        result_id: _ResultId, offset_chars: int = 0, limit_chars: int | None = None
    ) -> dict[str, Any]:
        entry = _get_entry(store, result_id)
        offset = min(max(0, offset_chars), entry.size_chars)
        # Default page: a third of the threshold, so operators tuning the
        # threshold get a proportionate page size without a second knob.
        if limit_chars is None:
            limit_chars = max(1, config.large_result_threshold_chars // 3)
        # Cap slices at the compaction threshold and choose the longest prefix
        # whose complete FastMCP JSON response fits the response budget.
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
        return await asyncio.to_thread(
            _search_stored_result,
            entry,
            pattern=pattern,
            context_chars=context_chars,
            max_matches=max_matches,
            configured_budget=config.large_result_threshold_chars,
        )


__all__ = [
    "RESULT_RESOURCE_PREFIX",
    "ResultResourceStore",
    "StoredToolResult",
    "maybe_compact_tool_result",
    "register_result_resources",
    "register_result_tools",
]
