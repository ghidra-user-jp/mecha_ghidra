"""Bound large anticipated failures without changing their failure status."""

from __future__ import annotations

import logging
from typing import Any

from mcp.types import CallToolResult, ResourceLink, TextContent

from .config import ToolPresentationConfig
from .result_compaction import _call_tool_result_wire_chars, _json_text
from .result_store import RESULT_RESOURCE_PREFIX, ResultResourceStore, _normalize_json_surrogates

logger = logging.getLogger(__name__)
_STATUS_FIELDS = frozenset(
    {
        "code",
        "retryable",
        "transaction_outcome",
        "execution_state",
        "operation_succeeded",
        "operation_completed",
        "partial_success",
        "result_unavailable",
        "runtime_degraded",
    }
)


def _error_preview(value: Any, limit: int, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "… [see stored error]"
    if isinstance(value, dict):
        # Script status, diagnostic counters and field names remain available.
        if depth >= 8:
            return "[see stored error]"
        items = sorted(value.items(), key=lambda item: item[0] not in _STATUS_FIELDS)
        result = {
            str(k)[:128]: v
            if k in _STATUS_FIELDS and isinstance(v, (str, bool, int))
            else _error_preview(v, limit, depth + 1)
            for k, v in items[:32]
        }
        if len(items) > 32:
            result["additional_fields_omitted"] = True
        return result
    if isinstance(value, (list, tuple)):
        if depth >= 8:
            return "[see stored error]"
        return [_error_preview(v, limit, depth + 1) for v in value[:8]]
    return value


def present_tool_error(
    *,
    tool: str,
    target: str,
    error: dict[str, Any],
    original: CallToolResult,
    config: ToolPresentationConfig,
    store: ResultResourceStore,
) -> CallToolResult:
    if config.large_result_mode == "inline":
        return original
    try:
        if (
            sum(len(c.text) for c in original.content if isinstance(c, TextContent))
            <= config.large_result_threshold_chars
        ):
            return original
        normalized, _ = _normalize_json_surrogates(error)
        text = _json_text({"error": normalized})
        budget = max(config.large_result_threshold_chars, 2048)

        def response(preview_limit: int, result_id: str | None) -> CallToolResult:
            metadata = {"error": _error_preview(normalized, preview_limit), "truncated": True}
            content = []
            if result_id is not None:
                uri = f"{RESULT_RESOURCE_PREFIX}{result_id}"
                metadata.update(result_id=result_id, resource_uri=uri)
                metadata["read_hint"] = f"read_result(result_id='{result_id}') contains the full error."
                content.append(
                    ResourceLink(
                        type="resource_link", name="Full error diagnostics", uri=uri, mime_type="application/json"
                    )
                )
            else:
                metadata.update(result_unavailable=True, read_hint="Full diagnostics exceed the result cache budget.")
            return CallToolResult(
                is_error=True,
                structured_content=metadata,
                content=[TextContent(type="text", text=_json_text(metadata)), *content],
            )

        limit = min(512, config.large_result_preview_chars // 4)
        candidate = response(limit, "0" * 16)
        while _call_tool_result_wire_chars(candidate) > budget and limit:
            limit //= 2
            candidate = response(limit, "0" * 16)
        if _call_tool_result_wire_chars(candidate) > budget or (
            _call_tool_result_wire_chars(candidate) >= _call_tool_result_wire_chars(original)
        ):
            return original
        entry = store.add(
            tool=tool, target=target, text=text, mime_type="application/json", result_type="error", item_count=None
        )
        return response(limit, entry.result_id if entry is not None else None)
    except Exception as exc:
        # A presentation problem must never turn a failed mutation into success.
        logger.warning("Error presentation failed (%s); preserving original error", type(exc).__name__)
        return original
