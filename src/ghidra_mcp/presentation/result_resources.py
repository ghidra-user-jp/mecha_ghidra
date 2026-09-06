"""Large-result handling for MCP tool responses.

The implementation is split by responsibility:

- :mod:`ghidra_mcp.presentation.result_store` keeps the LRU store of payloads,
- :mod:`ghidra_mcp.presentation.result_compaction` decides when a result is
  replaced by a preview plus resource link and builds that envelope,
- :mod:`ghidra_mcp.presentation.result_tools` serves ``read_result`` /
  ``search_result`` and the ``ghidra://results/{result_id}`` template.

This module re-exports the public surface (and the helpers the test suite
exercises directly) so existing imports keep working.  ``regex`` is exported
too because tests patch the shared engine module through this name.
"""

from __future__ import annotations

import regex

from ghidra_mcp.presentation.result_compaction import (
    _bounded_json_string,
    _build_compacted_result,
    _call_tool_result_wire_chars,
    _CompactionFallback,
    _delivered_inline_size,
    _inline_result_wire_chars,
    _is_normalized_empty_list_result,
    _json_text,
    _maybe_compact_tool_result,
    _prepare_result_for_compaction,
    _presentation_failure_result,
    _preview_for_budget,
    _preview_slice,
    _serialize_result,
    _uncacheable_result,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.result_store import (
    RESULT_RESOURCE_PREFIX,
    ResultResourceStore,
    StoredToolResult,
    _normalize_json_surrogates,
    _normalize_surrogate_text,
    _utf8_size_and_sha256,
)
from ghidra_mcp.presentation.result_tools import (
    _MIN_RESULT_TOOL_RESPONSE_CHARS,
    _SEARCH_CONTEXT_MAX_CHARS,
    _SEARCH_MATCH_DISPLAY_MAX_CHARS,
    _SEARCH_MAX_MATCHES_CAP,
    _SEARCH_MAX_PATTERN_CHARS,
    _SEARCH_SCAN_CAP,
    _SEARCH_TIMEOUT_SECONDS,
    _fit_read_result_chunk,
    _get_entry,
    _read_result_payload,
    _search_stored_result,
    _validate_search_pattern,
    register_result_resources,
    register_result_tools,
)

__all__ = [
    "RESULT_RESOURCE_PREFIX",
    "ResultResourceStore",
    "StoredToolResult",
    "_MIN_RESULT_TOOL_RESPONSE_CHARS",
    "_SEARCH_CONTEXT_MAX_CHARS",
    "_SEARCH_MATCH_DISPLAY_MAX_CHARS",
    "_SEARCH_MAX_MATCHES_CAP",
    "_SEARCH_MAX_PATTERN_CHARS",
    "_SEARCH_SCAN_CAP",
    "_SEARCH_TIMEOUT_SECONDS",
    "_CompactionFallback",
    "_bounded_json_string",
    "_build_compacted_result",
    "_call_tool_result_wire_chars",
    "_delivered_inline_size",
    "_fit_read_result_chunk",
    "_get_entry",
    "_inline_result_wire_chars",
    "_is_normalized_empty_list_result",
    "_json_text",
    "_maybe_compact_tool_result",
    "_normalize_json_surrogates",
    "_normalize_surrogate_text",
    "_prepare_result_for_compaction",
    "_presentation_failure_result",
    "_preview_for_budget",
    "_preview_slice",
    "_read_result_payload",
    "_search_stored_result",
    "_serialize_result",
    "_uncacheable_result",
    "_utf8_size_and_sha256",
    "_validate_search_pattern",
    "maybe_compact_tool_result",
    "regex",
    "register_result_resources",
    "register_result_tools",
]
