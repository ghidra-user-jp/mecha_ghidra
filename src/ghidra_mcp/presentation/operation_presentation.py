"""What job records keep of an outcome: small values as they are, large ones as result-store references."""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent

from .config import ToolPresentationConfig
from .result_compaction import _json_text, maybe_compact_tool_result
from .result_errors import present_tool_error
from .result_store import ResultResourceStore

# How a stored error says where its full text is.
_RETRIEVAL_KEYS = ("truncated", "result_id", "resource_uri", "read_hint", "result_unavailable")


def structured_value(result: CallToolResult) -> Any:
    """The JSON a record keeps for a completed call: the logical value, or the retrieval notice.

    A core command's reply also names its ``source``; the record keeps the value alone.
    """
    content = result.structured_content
    if isinstance(content, dict) and "result" in content and set(content) <= {"result", "source"}:
        return content["result"]
    return content


def structured_error(result: CallToolResult) -> dict[str, Any]:
    """The error object a record keeps for a failed call, with the retrieval fields of a stored one."""
    content = result.structured_content if isinstance(result.structured_content, dict) else {}
    error = content.get("error")
    if not isinstance(error, dict):
        text = next((item.text for item in result.content if isinstance(item, TextContent)), None)
        error = {"message": text or "The tool call failed"}
    return {**error, **{key: content[key] for key in _RETRIEVAL_KEYS if key in content}}


def present_operation_outcome(
    kind: str,
    target: str,
    result: Any,
    error: dict[str, Any] | None,
    *,
    config: ToolPresentationConfig,
    store: ResultResourceStore,
) -> tuple[Any, dict[str, Any] | None]:
    """Move a job's oversized result or error to the result store, as a tool call's would be."""
    if result is not None:
        presented = maybe_compact_tool_result(tool_name=kind, target=target, result=result, config=config, store=store)
        if isinstance(presented, CallToolResult):
            result = structured_value(presented)
    if error is not None:
        original = CallToolResult(
            is_error=True,
            structured_content={"error": error},
            content=[TextContent(type="text", text=_json_text({"error": error}))],
        )
        presented = present_tool_error(
            tool=kind, target=target, error=error, original=original, config=config, store=store
        )
        if presented is not original:
            error = structured_error(presented)
    return result, error


__all__ = ["present_operation_outcome", "structured_error", "structured_value"]
