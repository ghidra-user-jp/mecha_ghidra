"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Literal

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceNotFoundError

from ghidra_mcp.contracts.tool_spec import ToolSpec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.doc_resources import register_tool_doc_resources
from ghidra_mcp.presentation.result_resources import (
    RESULT_RESOURCE_PREFIX,
    ResultResourceStore,
    maybe_compact_tool_result,
    register_result_resources,
    register_result_tools,
)
from ghidra_mcp.presentation.tool_registry import ToolRegistry

ServerLogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_SERVER_LOG_LEVELS: frozenset[str] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def normalize_server_log_level(level: str | None) -> ServerLogLevel:
    """Map a free-form ``--log-level`` value onto the SDK's accepted literals."""

    normalized = (level or "INFO").strip().upper()
    if normalized == "WARN":
        normalized = "WARNING"
    if normalized == "FATAL":
        normalized = "CRITICAL"
    if normalized not in _SERVER_LOG_LEVELS:
        return "INFO"
    return normalized  # type: ignore[return-value]


class GhidraMCPServer(MCPServer):
    """``MCPServer`` that serves stored large results with their own MIME type.

    SDK resource templates carry one static MIME type, while stored results are
    C, JSON, or plain text.  Overriding the public ``read_resource`` hook keeps
    the per-entry MIME type without reaching into SDK internals, so the template
    itself can be registered through the public ``resource`` decorator.
    """

    def __init__(
        self,
        *args: Any,
        result_store: ResultResourceStore | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._ghidra_result_store = result_store

    async def read_resource(self, uri: Any, context: Any = None) -> Iterable[ReadResourceContents] | Any:
        store = self._ghidra_result_store
        uri_text = str(uri)
        if store is not None and uri_text.startswith(RESULT_RESOURCE_PREFIX):
            result_id = uri_text[len(RESULT_RESOURCE_PREFIX) :]
            try:
                entry = store.get(result_id)
            except KeyError as exc:
                message = str(exc.args[0]) if exc.args else str(exc)
                raise ResourceNotFoundError(message) from exc
            return [ReadResourceContents(content=entry.text, mime_type=entry.mime_type)]
        return await super().read_resource(uri, context)


@dataclass(slots=True)
class MCPServerRuntime:
    mcp: MCPServer
    tools: dict[str, Callable[..., Any]]
    specs: Mapping[str, ToolSpec]
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
    specs: Mapping[str, ToolSpec],
    registry_provider: Callable[[], Any],
    dispatcher_provider: Callable[[], Callable[..., Any]],
    presentation_config: ToolPresentationConfig | None = None,
    server_log_level: str | None = None,
) -> MCPServerRuntime:
    effective_config = presentation_config or ToolPresentationConfig()
    effective_specs: dict[str, ToolSpec] = {}
    for supplied_name, spec in tuple(specs.items()):
        if supplied_name != spec.name:
            raise ValueError(f"Tool spec mapping key must match spec.name: {supplied_name!r} != {spec.name!r}")
        effective_specs[spec.name] = spec
    result_store = ResultResourceStore(
        max_entries=effective_config.result_cache_max_entries,
        max_bytes=effective_config.result_cache_max_bytes,
    )
    resource_mode = effective_config.large_result_mode == "resource"

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

    tools, tool_objects = ToolRegistry.build(
        effective_specs,
        lambda: _dispatch_with_presentation,
        registry_provider,
        presentation_config=effective_config,
    )
    # Tools are handed to the constructor as ready ``Tool`` objects: that is the
    # public way to publish a tool without a description (``add_tool`` would
    # substitute an empty string), and it keeps the registration order stable.
    mcp = GhidraMCPServer(
        "GhidraMCP Headless",
        instructions=_server_instructions(effective_config),
        log_level=normalize_server_log_level(server_log_level),
        tools=tool_objects,
        result_store=result_store if resource_mode else None,
    )
    register_tool_doc_resources(mcp, specs=effective_specs)
    if resource_mode:
        register_result_resources(mcp, store=result_store)
        register_result_tools(mcp, store=result_store, config=effective_config)
    return MCPServerRuntime(
        mcp=mcp,
        tools=tools,
        specs=MappingProxyType(effective_specs),
        presentation_config=effective_config,
        result_store=result_store,
    )


__all__ = [
    "GhidraMCPServer",
    "MCPServerRuntime",
    "ServerLogLevel",
    "create_mcp_server",
    "normalize_server_log_level",
]
