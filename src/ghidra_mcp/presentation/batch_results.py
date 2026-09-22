"""One response budget and one cache entry for a completed batch."""

import json

from mcp.types import TextContent

from .result_compaction import _bounded_json_string, _json_text, structured_result
from .result_store import _normalize_json_surrogates


def present_batch_result(result, *, target, max_output_chars, config, store):
    result, _ = _normalize_json_surrogates(result)

    def response(text):
        return structured_result(
            json.loads(text),
            content=[TextContent(type="text", text=text)],
            is_error=result["status"] == "error",
        )

    text = _json_text(result)

    def response_size(payload):
        # The contract bounds the response JSON text (the text block, which
        # structuredContent duplicates), not the whole serialized MCP envelope.
        return len(_json_text(payload))

    if len(text) <= max_output_chars:
        return response(text)
    if config.large_result_mode != "resource":
        raise ValueError(
            "batch_read response exceeds max_output_chars; narrow fields/page limits or enable resource mode"
        )

    entry = store.add(
        tool="batch_read",
        target=target,
        text=text,
        mime_type="application/json",
        result_type="dict",
        item_count=len(result["items"]),
    )
    metadata = {key: result[key] for key in ("status", "succeeded_count", "failed_count", "not_run_count")}
    for key in ("program", "revision"):
        value = result[key]
        metadata[key] = None if value is None else _bounded_json_string(value, max_json_chars=192)[0]
        if metadata[key] != value:
            metadata["metadata_truncated"] = True
    metadata["truncated"] = True
    if entry is not None:
        metadata.update(
            result_id=entry.result_id,
            resource_uri=entry.uri,
            retrieval={"tool": "read_result", "mode": "json", "path": "/items"},
        )
    else:
        metadata.update(result_unavailable=True, reason="RESULT_TOO_LARGE")

    # Statuses must survive compaction even when an early successful item is
    # enormous. Full projected data and errors live in this single stored batch.
    summaries = []
    for index, item in enumerate(result["items"]):
        summary = {"id": item["id"], "status": item["status"], "offset_items": index}
        if entry is not None and item["status"] == "ok" and isinstance(item["data"], str):
            summary["text_path"] = "/items/%d/data" % index
        if item["status"] == "error":
            summary["error_code"] = item["error"]["code"]
        if item["status"] == "not_run":
            summary["reason"] = item["reason"]
        summaries.append(summary)
    payload = {**metadata, "items": summaries}
    size = response_size(payload)
    if size > max_output_chars:
        # Even a 20-item status manifest may not fit the smallest requested
        # budget. Counts remain inline; one indexed read recovers all statuses.
        payload["items"] = []
        payload["item_summaries_omitted"] = True
        if entry is not None:
            payload["retrieval"].update(fields=["id", "tool", "status"], limit_items=len(result["items"]))
    else:
        # Prefer complete small results over arbitrary string truncation. Each
        # item is considered once; aggregate fitting includes escaped JSON cost.
        for index, item in enumerate(result["items"]):
            previous = payload["items"][index]
            payload["items"][index] = item
            if response_size(payload) > max_output_chars:
                payload["items"][index] = previous
    return response(_json_text(payload))
