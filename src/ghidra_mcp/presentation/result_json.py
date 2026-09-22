"""Lazy character indexes for JSON arrays; decode only requested items."""

from __future__ import annotations

import json
import re
from array import array
from dataclasses import replace
from typing import Any

_WHITESPACE = re.compile(r"\s*")
_DECODER = json.JSONDecoder()
_TEXT_PATH = re.compile(r"/items/(0|[1-9][0-9]{0,5})/data\Z")
_MAX_TEXT_ITEM_CHARS = 8 * 1024 * 1024


def select_text_result(store, entry, path):
    """A bounded temporary view of one decoded string; no second stored JSON tree."""
    if not path:
        return entry
    match = _TEXT_PATH.fullmatch(path)
    if match is None:
        raise ValueError("Text path must be /items/<index>/data")
    if entry.mime_type != "application/json":
        raise ValueError("Text path requires an application/json result")
    index = store.json_index(entry, "/items")
    item_index = int(match.group(1))
    if item_index >= len(index) // 2:
        raise ValueError("Text path item does not exist")
    start, end = index[item_index * 2 : item_index * 2 + 2]
    if end - start > _MAX_TEXT_ITEM_CHARS:
        raise ValueError("Selected item exceeds the text decode budget; read the raw JSON with path='' instead")
    item = json.loads(entry.text[start:end])
    text = item.get("data") if isinstance(item, dict) else None
    if not isinstance(text, str):
        raise ValueError("Selected data is not a JSON string")
    return replace(
        entry, text=text, size_chars=len(text), mime_type="text/plain", result_type="string", item_count=None
    )


def _space(text: str, pos: int) -> int:
    return _WHITESPACE.match(text, pos).end()


def _decode(text: str, pos: int) -> tuple[Any, int]:
    """One JSON value starting exactly at ``pos``; the stdlib scanner rejects malformed text."""
    try:
        return _DECODER.raw_decode(text, pos)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at character {exc.pos}: {exc.msg}") from exc


def build_array_index(text: str, path: str, *, max_bytes: int | None = None) -> array:
    """Index a root array or /items using O(items) offsets, not a second AST."""
    if path not in {"", "/items"}:
        raise ValueError('JSON path must be "" (root array) or "/items"')
    pos = _space(text, 0)
    if path:
        if pos >= len(text) or text[pos] != "{":
            raise ValueError("/items requires an object result")
        pos = _space(text, pos + 1)
        while pos < len(text) and text[pos] != "}":
            key, end = _decode(text, pos)
            if not isinstance(key, str):
                raise ValueError("Invalid JSON object")
            pos = _space(text, end)
            if text[pos : pos + 1] != ":":
                raise ValueError("Invalid JSON object")
            pos = _space(text, pos + 1)
            if key == "items":
                break
            _, end = _decode(text, pos)
            pos = _space(text, end)
            if text[pos : pos + 1] != ",":
                raise ValueError("Result has no /items array")
            pos = _space(text, pos + 1)
        else:
            raise ValueError("Result has no /items array")
    if text[pos : pos + 1] != "[":
        raise ValueError("Selected JSON value is not an array")
    spans = array("Q")
    pos = _space(text, pos + 1)
    if text[pos : pos + 1] != "]":
        while True:
            _, end = _decode(text, pos)
            spans.extend((pos, end))
            if max_bytes is not None and spans.__sizeof__() > max_bytes:
                raise ValueError("JSON index exceeds the result cache budget; use mode=text")
            pos = _space(text, end)
            if text[pos : pos + 1] == "]":
                break
            if text[pos : pos + 1] != ",":
                raise ValueError("Invalid JSON array")
            pos = _space(text, pos + 1)
    pos = _space(text, pos + 1)
    # A root array must end the document; /items must be followed by the rest
    # of its object.  Anything else (for example "[1]]") is malformed JSON.
    if text[pos : pos + 1] not in ({""} if not path else {",", "}"}):
        raise ValueError("Invalid JSON after the array")
    return spans


def read_json_items(
    store,
    entry,
    *,
    path: str,
    offset: int,
    limit: int,
    fields: list[str] | None,
    budget: int,
    json_text,
    response_size=None,
) -> dict[str, Any]:
    if entry.mime_type != "application/json":
        raise ValueError("JSON mode requires an application/json result")
    response_size = response_size or (lambda value: len(json_text(value, indent=2)))
    index = store.json_index(entry, path)
    total = len(index) // 2
    offset = min(offset, total)
    selected = []

    def payload(items):
        next_offset = offset + len(items)
        return {
            "result_id": entry.result_id,
            "mode": "json",
            "path": path,
            "offset_items": offset,
            "total_items": total,
            "items": items,
            "has_more": next_offset < total,
            "next_offset_items": next_offset if next_offset < total else None,
        }

    # A conservative cost for indentation and changing footer integers lets
    # each row be encoded once, rather than re-encoding every growing prefix.
    estimated_chars = response_size(payload([])) + 32
    for item_index in range(offset, min(total, offset + limit)):
        a, b = index[item_index * 2 : item_index * 2 + 2]
        row = json.loads(entry.text[a:b])
        if fields is not None:
            if not isinstance(row, dict):
                raise ValueError("fields can only project object items")
            row = {key: row[key] for key in fields if key in row}
        selected.append(row)
        encoded = json_text(row, indent=2)
        estimated_chars += 3 * len(encoded) + 12 * (encoded.count("\n") + 1) + 2
        # Bound decoded objects retained in this request; never decode the entire array.
        if estimated_chars > budget and response_size(payload(selected)) > budget:
            selected.pop()
            if not selected:
                # Advance past the oversized item so a client that follows
                # next_offset_items never loops on the same offset; its raw
                # span stays readable through mode=text.
                skipped = offset + 1
                return {
                    **payload([]),
                    "has_more": skipped < total,
                    "next_offset_items": skipped if skipped < total else None,
                    "item_too_large": True,
                    "offset_chars": a,
                    "item_chars": b - a,
                    "read_hint": (
                        "This item was skipped: select fewer fields, or read it using mode=text and offset_chars."
                    ),
                }
            break
    return payload(selected)
