"""Compaction of large tool results into previews plus stored resources."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import Audio, Image
from mcp.types import CallToolResult, ContentBlock, ResourceLink, TextContent
from pydantic import BaseModel
from pydantic_core import to_json

from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.result_store import (
    RESULT_RESOURCE_PREFIX,
    ResultResourceStore,
    StoredToolResult,
    _normalize_json_surrogates,
    _normalize_surrogate_text,
    _utf8_size_and_sha256,
)

logger = logging.getLogger(__name__)

_MIN_COMPACT_RESULT_RESPONSE_CHARS = 2048
_RESULT_METADATA_JSON_CHARS = 128


@dataclass(slots=True)
class _CompactionFallback:
    value: Any


def _is_normalized_empty_list_result(result: CallToolResult) -> bool:
    if (
        result.is_error
        or result.meta is not None
        or bool(result.model_extra)
        or result.structured_content is not None
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
    # pydantic_core.to_json is the serializer the MCP SDK delivers inline results
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
    times when the MCP SDK serializes the tool response.
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
    return value.annotations is None and value.meta is None and not value.model_extra


def _is_plain_text_call_result(value: CallToolResult) -> bool:
    """Whether a CallToolResult is exactly one unannotated success text block."""
    return (
        not value.is_error
        and value.meta is None
        and not value.model_extra
        and value.structured_content is None
        and len(value.content) == 1
        and isinstance(value.content[0], TextContent)
        and _is_plain_text_content(value.content[0])
    )


def _contains_explicit_content(value: Any) -> bool:
    """Return whether the MCP SDK will adapt any value into a non-generic block."""
    if isinstance(value, ContentBlock) or isinstance(value, (Image, Audio)):  # noqa: SIM101 - ContentBlock is a Union
        return True
    if isinstance(value, (list, tuple)):
        return any(_contains_explicit_content(item) for item in value)
    return False


def _content_block_payload(block: ContentBlock) -> dict[str, Any]:
    # MCP transports omit absent optional fields. Keeping the same shape avoids
    # storing synthetic nulls and makes wire-size comparisons exact.
    return block.model_dump(mode="json", by_alias=True, exclude_none=True)


def _prepare_result_for_compaction(value: Any) -> tuple[Any, bool]:
    """Normalize stateful the MCP SDK adapters and container subclasses once.

    the MCP SDK converts Image/Audio helpers once and iterates list/tuple subclasses
    using their Python iterator. The compaction pipeline performs several probes
    (storage, threshold, wire comparison, preview), so sharing one prepared value
    prevents repeated file reads/base64 work and keeps every probe on one order.
    Dicts are atomic to the MCP SDK's converter; pydantic_core observes their base
    storage rather than an overridden ``items()``, which we mirror for previews.
    """
    if isinstance(value, str):
        normalized = _normalize_surrogate_text(value)
        return normalized, normalized is not value
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
        return (tuple(prepared_items), True) if prepared_items is not None else (value, False)
    if isinstance(value, dict):
        # Call the base methods explicitly: a subclass may override iteration or
        # items() even though pydantic_core serializes the underlying dict order.
        return _normalize_json_surrogates(value)
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="python", by_alias=True)
        normalized, changed = _normalize_json_surrogates(payload)
        if changed:
            return type(value).model_validate(normalized), True
    return value, False


def _serialize_result(result: Any, *, tool_name: str) -> tuple[str, str, str, int | None]:
    if isinstance(result, str):
        mime_type = "text/x-c" if tool_name == "decompile_function" else "text/plain"
        return result, mime_type, "string", None
    if isinstance(result, CallToolResult):
        if _is_plain_text_call_result(result):
            return result.content[0].text, "text/plain", "call_tool_result_text", None
        return (
            _json_text(result.model_dump(mode="json", by_alias=True, exclude_none=True)),
            "application/json",
            "call_tool_result",
            len(result.content),
        )
    if isinstance(result, TextContent):
        # the MCP SDK returns a single TextContent block directly; its user-visible
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
        # MCP structure as JSON so resource reads can reconstruct what the MCP SDK
        # would otherwise have delivered inline.
        return (
            _json_text(_content_block_payload(result)),
            "application/json",
            "content_block",
            None,
        )
    if isinstance(result, (Image, Audio)):
        # These public the MCP SDK helpers have deliberately small repr strings,
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
            # the MCP SDK recursively flattens mixed lists containing ContentBlock,
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
        # the MCP SDK uses pydantic_core JSON for model results. Keep the compact
        # structural form in the resource rather than Python's repr.
        return _json_text(result), "application/json", "pydantic_model", None
    # Match the MCP SDK's generic conversion. pydantic_core handles dataclasses and
    # other supported values structurally, then uses repr-like fallback only
    # for values without a JSON representation.
    return _json_text(result), "application/json", type(result).__name__, None


def _delivered_inline_size(
    result: Any,
    *,
    tool_name: str,
    stop_after: int | None = None,
) -> int:
    """Chars the MCP SDK would put in context if this result were returned inline.

    The compaction decision must reflect what the client actually receives.
    the MCP SDK re-serializes non-string results with pydantic_core.to_json(indent=2)
    (per item for lists), which is ~1.6-1.8x larger than compact json.dumps. We
    still *store* the compact form (cheaper to page), but we *decide* on the
    indent=2 size so results are not silently delivered inline over the cap.
    """
    if isinstance(result, str):
        return len(result)
    if isinstance(result, CallToolResult):
        # the MCP SDK passes a top-level CallToolResult through, but its content
        # blocks represent the same user-visible payload as a raw list of those
        # blocks. Count block payloads consistently, then add only meaningful
        # outer metadata/structured content (not transport envelope overhead).
        content_chars = _delivered_blocks_size(
            iter(result.content),
            stop_after=stop_after,
        )
        if stop_after is not None and content_chars > stop_after:
            return content_chars
        outer = result.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"content", "is_error", "result_type"},
        )
        return content_chars + (len(_json_text(outer, indent=2)) if outer else 0)
    if isinstance(result, TextContent):
        if _is_plain_text_content(result):
            return len(result.text)
        return len(_json_text(_content_block_payload(result), indent=2))
    if isinstance(result, ContentBlock):
        return len(_json_text(_content_block_payload(result), indent=2))
    if isinstance(result, (Image, Audio)):
        block = next(_iter_inline_content_blocks(result))
        return _delivered_content_block_size(block)
    if isinstance(result, (list, tuple)):
        # Nested CallToolResult values are not passed through by the MCP SDK: only a
        # top-level CallToolResult is special. Its recursive list converter turns
        # each nested value into a TextContent JSON string. Measure those actual
        # converted blocks instead of applying top-level semantics recursively.
        return _delivered_blocks_size(
            _iter_inline_content_blocks(result),
            stop_after=stop_after,
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
    pieces = (_json_text({key: value})[1:-1] for key, value in dict.items(mapping))
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
                mime_type=entry.mime_type,
                size=entry.size_bytes,
            ),
        ],
        structured_content=metadata,
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
        is_error=False,
        content=[TextContent(type="text", text=message)],
        structured_content={
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


def _presentation_failure_result(tool_name: str, target: str) -> CallToolResult:
    """Report completed execution when its result cannot be represented safely."""

    display_tool, tool_truncated = _bounded_json_string(
        tool_name,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    display_target, target_truncated = _bounded_json_string(
        target,
        max_json_chars=_RESULT_METADATA_JSON_CHARS,
    )
    return CallToolResult(
        is_error=False,
        content=[
            TextContent(
                type="text",
                text=(
                    f"RESULT_PRESENTATION_FAILED: [{display_tool}] completed successfully, "
                    "but its result could not be represented safely. Do not automatically "
                    "retry a side-effecting tool solely to recover this result."
                ),
            )
        ],
        structured_content={
            "tool": display_tool,
            "target": display_target,
            "operation_succeeded": True,
            "result_unavailable": True,
            "presentation_failed": True,
            "metadata_truncated": tool_truncated or target_truncated,
        },
    )


def _call_tool_result_wire_chars(result: CallToolResult) -> int:
    # stdio, SSE, websocket, and streamable HTTP transports all serialize MCP
    # models compactly with aliases and exclude_none=True. Outer JSON-RPC fields
    # are identical for inline/compacted results and therefore cancel out.
    return len(_json_text(result.model_dump(mode="json", by_alias=True, exclude_none=True)))


def _delivered_content_block_size(block: ContentBlock) -> int:
    """Measure one block using the MCP SDK's user-visible payload convention."""
    if isinstance(block, TextContent) and _is_plain_text_content(block):
        return len(block.text)
    return len(_json_text(_content_block_payload(block), indent=2))


def _delivered_blocks_size(
    blocks,
    *,
    stop_after: int | None,
) -> int:
    total = 0
    for block in blocks:
        total += _delivered_content_block_size(block)
        if stop_after is not None and total > stop_after:
            break
    return total


def _iter_inline_content_blocks(result: Any):
    """Mirror the MCP SDK's unstructured result conversion for wire comparison."""
    if result is None:
        return
    if isinstance(result, ContentBlock):
        yield result
        return
    if isinstance(result, Image):
        yield result.to_image_content()
        return
    if isinstance(result, Audio):
        yield result.to_audio_content()
        return
    if isinstance(result, (list, tuple)):
        for item in result:
            yield from _iter_inline_content_blocks(item)
        return
    text = result if isinstance(result, str) else _json_text(result, indent=2)
    yield TextContent(type="text", text=text)


def _inline_content_blocks(result: Any) -> list[ContentBlock]:
    return list(_iter_inline_content_blocks(result))


def _inline_result_wire_chars(result: Any) -> int:
    """Serialized CallToolResult size the MCP SDK would deliver without compaction."""
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
    fallback: _CompactionFallback | None = None,
) -> Any:
    if store is None or config.large_result_mode == "inline":
        return result
    if isinstance(result, CallToolResult):
        if result.is_error or _is_normalized_empty_list_result(result):
            return result
    if fallback is not None:
        # Preparing the MCP SDK Image/Audio helpers can consume one-shot state. If a
        # later helper fails, returning the original value would make the MCP SDK
        # consume the earlier helper again and turn a completed mutation into an
        # apparent tool error. Start with a serialization-safe success notice;
        # replace it with the exact prepared value only after preparation ends.
        fallback.value = _presentation_failure_result(tool_name, target)
    prepared_result, prepared = _prepare_result_for_compaction(result)
    # A prepared helper/block sequence is wire-equivalent to the original and
    # avoids making the MCP SDK invoke a stateful adapter a second time on fallback.
    inline_result = prepared_result if prepared else result
    if fallback is not None:
        fallback.value = inline_result
    threshold = config.large_result_threshold_chars
    inline_chars = _delivered_inline_size(
        prepared_result,
        tool_name=tool_name,
        stop_after=threshold,
    )
    if inline_chars <= threshold:
        return inline_result
    text, mime_type, result_type, item_count = _serialize_result(
        prepared_result,
        tool_name=tool_name,
    )

    # Both the delivered payload measurement and the compact stored form are
    # lower bounds for most inline results, but each has one exceptional shape:
    # pretty-printed explicit content blocks can make ``inline_chars`` larger
    # than their compact wire form, while nested list delimiters can make
    # ``text`` larger than the MCP SDK's flattened content sequence. Their minimum
    # is therefore a safe wire-size lower bound for every supported shape. Most
    # genuinely large results exceed a compact candidate by this bound alone,
    # avoiding a second, potentially many-times-larger serialization of the
    # complete payload merely to compare lengths.
    inline_wire_lower_bound = min(inline_chars, len(text))
    inline_wire_chars: int | None = None

    def _candidate_is_smaller(candidate: CallToolResult) -> bool:
        nonlocal inline_wire_chars
        candidate_wire_chars = _call_tool_result_wire_chars(candidate)
        if candidate_wire_chars < inline_wire_lower_bound:
            return True
        if inline_wire_chars is None:
            inline_wire_chars = _inline_result_wire_chars(prepared_result)
        return candidate_wire_chars < inline_wire_chars

    size_bytes, payload_hash = _utf8_size_and_sha256(text)
    if size_bytes > store.max_bytes:
        uncacheable = _uncacheable_result(
            tool_name=tool_name,
            target=target,
            text=text,
            size_bytes=size_bytes,
            mime_type=mime_type,
            result_type=result_type,
            item_count=item_count,
            cache_max_bytes=store.max_bytes,
        )
        # A deliberately tiny threshold/cache must not turn a short result into
        # a larger error envelope.  Real oversized payloads still take the
        # compact error path and never leak their full contents inline.
        if not _candidate_is_smaller(uncacheable):
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
        size_bytes=size_bytes,
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
    if not _candidate_is_smaller(provisional_result):
        return inline_result

    entry = store._add_precomputed(
        tool=tool_name,
        target=target,
        text=text,
        size_bytes=size_bytes,
        payload_hash=payload_hash,
        mime_type=mime_type,
        result_type=result_type,
        item_count=item_count,
    )
    if entry is None:
        uncacheable = _uncacheable_result(
            tool_name=tool_name,
            target=target,
            text=text,
            size_bytes=size_bytes,
            mime_type=mime_type,
            result_type=result_type,
            item_count=item_count,
            cache_max_bytes=store.max_bytes,
        )
        if not _candidate_is_smaller(uncacheable):
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
    then repeat a non-idempotent call. Fall back to the latest wire-equivalent
    result (including any already-converted stateful helpers) and log only the
    exception class; exception messages can contain result data and must not
    leak payloads into server logs.
    """
    fallback = _CompactionFallback(result)
    try:
        return _maybe_compact_tool_result(
            tool_name=tool_name,
            target=target,
            result=result,
            config=config,
            store=store,
            fallback=fallback,
        )
    except Exception as exc:
        logger.warning(
            "Large-result presentation failed for tool %s (%s); returning a wire-equivalent completed result",
            tool_name,
            type(exc).__name__,
        )
        return fallback.value


__all__ = ["maybe_compact_tool_result"]
