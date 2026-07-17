"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.doc_resources import register_tool_doc_resources
from ghidra_mcp.presentation.result_resources import (
    ResultResourceStore,
    maybe_compact_tool_result,
    register_result_resources,
    register_result_tools,
)
from ghidra_mcp.presentation.tool_registry import ToolRegistry


@dataclass(slots=True)
class MCPServerRuntime:
    mcp: FastMCP
    tools: dict[str, Callable[..., Any]]
    specs: dict[str, ToolSpec]
    presentation_config: ToolPresentationConfig
    result_store: ResultResourceStore


def _server_instructions(config: ToolPresentationConfig) -> str:
    parts = [
        "GhidraMCP headless reverse-engineering server.",
        (
            "Detailed per-tool documentation is available as MCP resources: "
            "ghidra://docs/tools (index) and ghidra://docs/tools/{tool_name}."
        ),
    ]
    if config.large_result_mode == "resource":
        parts.append(
            f"Tool results longer than {config.large_result_threshold_chars} characters are "
            "returned as a preview plus a result_id when that reduces response size. Page "
            "through stored payloads with read_result, or locate specific content with "
            "search_result (regex), instead of re-reading whole payloads. Clients with MCP "
            "resource support can also read them at ghidra://results/{result_id}. A result "
            "entry larger than the entire cache returns a successful RESULT_TOO_LARGE "
            "result-unavailable notice without the full content when that notice is smaller; "
            "otherwise the smaller inline result is preserved. Tool execution has already "
            "completed when this notice appears, so do not automatically retry side-effecting "
            "calls."
        )
    return "\n".join(parts)


def create_mcp_server(
    *,
    specs: dict[str, ToolSpec],
    registry_provider: Callable[[], Any],
    dispatcher_provider: Callable[[], Callable[..., Any]],
    presentation_config: ToolPresentationConfig | None = None,
) -> MCPServerRuntime:
    effective_config = presentation_config or ToolPresentationConfig()
    mcp = FastMCP("GhidraMCP Headless", instructions=_server_instructions(effective_config))
    result_store = ResultResourceStore(
        max_entries=effective_config.result_cache_max_entries,
        max_bytes=effective_config.result_cache_max_bytes,
    )
    register_tool_doc_resources(mcp, specs=specs)
    if effective_config.large_result_mode == "resource":
        register_result_resources(mcp, store=result_store)
        register_result_tools(mcp, store=result_store, config=effective_config)

    def _dispatch_with_presentation(
        spec_name: str,
        raw_args: dict[str, Any] | None,
        target: str,
        *,
        registry,
    ) -> Any:
        dispatcher = dispatcher_provider()
        result = dispatcher(
            spec_name,
            raw_args,
            target,
            registry=registry,
        )
        return maybe_compact_tool_result(
            tool_name=spec_name,
            target=target,
            result=result,
            config=effective_config,
            store=result_store,
        )

    tools = ToolRegistry.register_all(
        mcp,
        specs,
        lambda: _dispatch_with_presentation,
        registry_provider,
        presentation_config=effective_config,
    )
    runtime = MCPServerRuntime(
        mcp=mcp,
        tools=tools,
        specs=dict(specs),
        presentation_config=effective_config,
        result_store=result_store,
    )
    return runtime


__all__ = ["MCPServerRuntime", "create_mcp_server"]
