"""In-memory LRU store for large MCP tool results."""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import regex
from pydantic_core import to_json

logger = logging.getLogger(__name__)


RESULT_RESOURCE_PREFIX = "ghidra://results/"
_UTF8_CHUNK_CHARS = 65_536
_SURROGATE_RE = regex.compile(r"[\ud800-\udfff]")


def _utf8_size_and_sha256(text: str) -> tuple[int, str]:
    """Measure and hash UTF-8 text without a payload-sized bytes copy."""

    digest = hashlib.sha256()
    size_bytes = 0
    if len(text) <= _UTF8_CHUNK_CHARS:
        chunks = (text.encode("utf-8", errors="replace"),)
    else:
        chunks = (
            text[offset : offset + _UTF8_CHUNK_CHARS].encode(
                "utf-8",
                errors="replace",
            )
            for offset in range(0, len(text), _UTF8_CHUNK_CHARS)
        )
    for chunk in chunks:
        digest.update(chunk)
        size_bytes += len(chunk)
    return size_bytes, digest.hexdigest()


def _normalize_surrogate_text(value: str) -> str:
    if _SURROGATE_RE.search(value) is None:
        return value
    normalized: list[str] = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF and index + 1 < len(value):
            low = ord(value[index + 1])
            if 0xDC00 <= low <= 0xDFFF:
                normalized.append(chr(0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)))
                index += 2
                continue
        if 0xD800 <= codepoint <= 0xDFFF:
            normalized.append("\ufffd")
        else:
            normalized.append(value[index])
        index += 1
    return "".join(normalized)


def _normalize_json_surrogates(value: Any) -> tuple[Any, bool]:
    """Replace unpaired surrogate code points in JSON container strings."""

    if isinstance(value, str):
        normalized = _normalize_surrogate_text(value)
        return normalized, normalized is not value
    if isinstance(value, list):
        changed = False
        items = []
        for item in value:
            normalized, item_changed = _normalize_json_surrogates(item)
            items.append(normalized)
            changed = changed or item_changed
        return (items, True) if changed else (value, False)
    if isinstance(value, tuple):
        changed = False
        items = []
        for item in value:
            normalized, item_changed = _normalize_json_surrogates(item)
            items.append(normalized)
            changed = changed or item_changed
        return (tuple(items), True) if changed else (value, False)
    if isinstance(value, dict):
        changed = type(value) is not dict
        normalized_items: list[tuple[Any, Any]] = []
        for key in dict.keys(value):
            normalized_key, key_changed = _normalize_json_surrogates(key)
            normalized_value, value_changed = _normalize_json_surrogates(dict.__getitem__(value, key))
            normalized_items.append((normalized_key, normalized_value))
            changed = changed or key_changed or value_changed
        return (dict(normalized_items), True) if changed else (value, False)
    return value, False


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
        # mcp 2.x runs synchronous tools in worker threads, so several tool
        # calls, resource reads, and search requests can touch this LRU at the
        # same time. Keep each identity-check/insert/evict and get/move atomic.
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
        text = _normalize_surrogate_text(text)
        size_bytes, payload_hash = _utf8_size_and_sha256(text)
        return self._add_precomputed(
            tool=tool,
            target=target,
            text=text,
            size_bytes=size_bytes,
            payload_hash=payload_hash,
            mime_type=mime_type,
            result_type=result_type,
            item_count=item_count,
        )

    def _add_precomputed(
        self,
        *,
        tool: str,
        target: str,
        text: str,
        size_bytes: int,
        payload_hash: str,
        mime_type: str,
        result_type: str,
        item_count: int | None,
    ) -> StoredToolResult | None:
        """Add a result using precomputed streaming UTF-8 metadata."""
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
            "size_bytes": size_bytes,
            "tool": tool,
            "target": target,
            "result_type": result_type,
            "item_count": item_count,
        }
        cache_size_bytes = size_bytes + len(to_json(metadata, fallback=str))
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
                size_bytes=size_bytes,
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
                len(self._entries) > self._max_entries or self._total_bytes > self._max_bytes
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
            raise KeyError("Invalid result id. Expected exactly 16 lowercase hexadecimal characters.")
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


__all__ = ["RESULT_RESOURCE_PREFIX", "ResultResourceStore", "StoredToolResult"]
