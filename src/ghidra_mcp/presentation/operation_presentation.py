"""What job records keep of an outcome: small values as they are, large ones as result-store references."""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent

from .config import ToolPresentationConfig
from .result_compaction import maybe_compact_tool_result
from .result_errors import present_tool_error
from .result_store import ResultResourceStore
from .tool_binding import error_envelope

# How a stored error says where its full text is.
_RETRIEVAL_KEYS = ("truncated", "result_id", "resource_uri", "read_hint", "result_unavailable")


def _is_result_envelope(content: Any) -> bool:
    return isinstance(content, dict) and "result" in content and set(content) <= {"result", "source"}


def structured_value(result: CallToolResult) -> Any:
    """The JSON a record keeps for a completed call: the logical value, or the retrieval notice.

    A core command's reply also names its ``source``, beside the value or in
    the notice that stands for a stored one (``mcp_server._with_source``); the
    record keeps it beside the value (``structured_source``).
    """
    content = result.structured_content
    if _is_result_envelope(content):
        return content["result"]
    if isinstance(content, dict) and "source" in content:
        return {key: value for key, value in content.items() if key != "source"}
    return content


def structured_source(result: CallToolResult) -> dict[str, Any] | None:
    """The program state a reply names (``source``), or None."""
    content = result.structured_content
    return content.get("source") if isinstance(content, dict) and not result.is_error else None


def structured_error(result: CallToolResult) -> dict[str, Any]:
    """The error object a record keeps for a failed call, with the retrieval fields of a stored one."""
    content = result.structured_content if isinstance(result.structured_content, dict) else {}
    error = content.get("error")
    if not isinstance(error, dict):
        if "result" in content:
            # A tool that reports its failure in the result (batch_read when no
            # read succeeded) keeps that result, each item's error included.
            error = {"message": "The call failed; result is what it returned", "result": content["result"]}
        else:
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
        original = error_envelope(error)
        presented = present_tool_error(
            tool=kind, target=target, error=error, original=original, config=config, store=store
        )
        if presented is not original:
            error = structured_error(presented)
    return result, error


__all__ = ["present_operation_outcome", "structured_error", "structured_source", "structured_value"]
