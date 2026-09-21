"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

import importlib.metadata
import inspect
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from types import MappingProxyType
from typing import Any, Callable, Literal

import anyio
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from jsonschema.exceptions import ValidationError as SchemaValidationError
from mcp import MCPError
from mcp.server import Server
from mcp.types import (
    INVALID_PARAMS,
    ListResourcesResult,
    ListResourceTemplatesResult,
    ListToolsResult,
    ReadResourceResult,
    Resource,
    ResourceTemplate,
    TextResourceContents,
)
from pydantic import ValidationError

from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolSafetyTag, ToolSpec
from ghidra_mcp.presentation.batch_results import present_batch_result
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.doc_resources import tool_docs_detail, tool_docs_index
from ghidra_mcp.presentation.result_compaction import _json_text, _presentation_failure_result
from ghidra_mcp.presentation.result_errors import present_tool_error
from ghidra_mcp.presentation.result_resources import (
    RESULT_RESOURCE_PREFIX,
    ResultResourceStore,
    build_result_tools,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.server_instructions import build_server_instructions
from ghidra_mcp.presentation.tool_binding import ToolBinding, complete_tool_result, error_result
from ghidra_mcp.presentation.tool_dispatcher import _validate_raw_args
from ghidra_mcp.presentation.tool_errors import ToolError
from ghidra_mcp.presentation.tool_registry import ToolRegistry, as_anticipated_tool_failure, public_arguments_model

logger = logging.getLogger(__name__)

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


_FALLBACK_PACKAGE_VERSION = "0.0.0"


def package_version(distribution: str = "mecha_ghidra") -> str:
    """Installed distribution version, or a placeholder for source-tree runs."""

    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return _FALLBACK_PACKAGE_VERSION


def _check_tool_schemas(binding: ToolBinding) -> None:
    """Fail fast on a malformed published contract instead of at first call."""

    name = binding.definition.name
    for kind, schema in (("input", binding.definition.input_schema), ("output", binding.definition.output_schema)):
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise ValueError(f"Tool {name!r} publishes an invalid {kind} schema: {exc.message}") from exc


@dataclass(frozen=True)
class ResourcePayload:
    content: str
    mime_type: str


class GhidraMCPServer(Server):
    """Application handlers registered through the SDK's public low-level API."""

    def __init__(self, *, bindings, specs, result_store, instructions):
        self.bindings = {binding.definition.name: binding for binding in bindings}
        self.specs = specs
        self.result_store = result_store
        for binding in self.bindings.values():
            _check_tool_schemas(binding)
        self.output_validators = {
            name: Draft202012Validator(binding.definition.output_schema) for name, binding in self.bindings.items()
        }
        super().__init__(
            "mecha_ghidra",
            version=package_version(),
            instructions=instructions,
            on_list_tools=self.handle_list_tools,
            on_call_tool=self.handle_call_tool,
            on_list_resources=self.handle_list_resources,
            on_list_resource_templates=self.handle_list_resource_templates,
            on_read_resource=self.handle_read_resource,
        )

    async def list_tools(self):
        return [binding.definition for binding in self.bindings.values()]

    async def handle_list_tools(self, _context, _params):
        return ListToolsResult(tools=await self.list_tools())

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        binding = self.bindings.get(name)
        if binding is None:
            raise ToolError(f"Unknown or unpublished tool: {name}")
        try:
            parsed = binding.arguments.model_validate(arguments or {})
        except ValidationError as exc:
            raise ToolError(f"{name} input validation failed: {exc}") from exc
        kwargs = parsed.model_dump()
        if inspect.iscoroutinefunction(binding.function):
            value = await binding.function(**kwargs)
        else:
            value = await anyio.to_thread.run_sync(partial(binding.function, **kwargs))
        result = complete_tool_result(value, compact_json=binding.compact_json)
        # The low-level SDK does not validate outputs. Enforce the advertised
        # contract here after presentation, including compaction/error variants.
        try:
            self.output_validators[name].validate(result.structured_content)
        except SchemaValidationError:
            logger.exception("Invalid structured output for tool %s", name)
            if result.is_error:
                return error_result(f"Error executing tool {name}")
            # Execution has already completed. Do not turn a presentation failure
            # into a retryable mutation error or discard its completion status.
            return _presentation_failure_result(name, kwargs.get("target", "default"))
        return result

    async def handle_call_tool(self, _context, params):
        try:
            return await self.call_tool(params.name, params.arguments)
        except ToolError as exc:
            return error_result(str(exc))
        except Exception:
            logger.exception("Unexpected failure in tool %s", params.name)
            return error_result(f"Error executing tool {params.name}")

    async def list_resource_templates(self):
        templates = [
            ResourceTemplate(
                uri_template="ghidra://docs/tools/{tool_name}",
                name="ghidra_tool_doc",
                description="Detailed documentation for one exposed Ghidra MCP tool.",
                mime_type="application/json",
            )
        ]
        if self.result_store is not None:
            templates.append(
                ResourceTemplate(
                    uri_template="ghidra://results/{result_id}",
                    name="ghidra_tool_result",
                    description="Full payload for a truncated Ghidra MCP tool result.",
                )
            )
        return templates

    async def handle_list_resources(self, _context, _params):
        return ListResourcesResult(
            resources=[
                Resource(
                    uri="ghidra://docs/tools",
                    name="ghidra_tool_docs",
                    description="Index of currently exposed Ghidra MCP tools.",
                    mime_type="application/json",
                )
            ]
        )

    async def handle_list_resource_templates(self, _context, _params):
        return ListResourceTemplatesResult(resource_templates=await self.list_resource_templates())

    async def read_resource(self, uri):
        uri = str(uri)
        if uri == "ghidra://docs/tools":
            return [
                ResourcePayload(content=_json_text(tool_docs_index(self.specs), indent=2), mime_type="application/json")
            ]
        if uri.startswith("ghidra://docs/tools/"):
            name = uri.removeprefix("ghidra://docs/tools/")
            if name in self.specs:
                return [
                    ResourcePayload(
                        content=_json_text(tool_docs_detail(self.specs[name]), indent=2), mime_type="application/json"
                    )
                ]
        if self.result_store is not None and uri.startswith(RESULT_RESOURCE_PREFIX):
            try:
                entry = self.result_store.get(uri.removeprefix(RESULT_RESOURCE_PREFIX))
                return [ResourcePayload(content=entry.text, mime_type=entry.mime_type)]
            except KeyError as exc:
                raise ValueError(str(exc.args[0])) from exc
        raise ValueError(f"Unknown or unpublished resource: {uri}")

    async def handle_read_resource(self, _context, params):
        try:
            contents = await self.read_resource(params.uri)
        except ValueError as exc:
            raise MCPError(code=INVALID_PARAMS, message=str(exc), data={"uri": params.uri}) from exc
        return ReadResourceResult(
            contents=[
                TextResourceContents(uri=params.uri, text=item.content, mime_type=item.mime_type) for item in contents
            ]
        )


@dataclass(slots=True)
class MCPServerRuntime:
    mcp: GhidraMCPServer
    tools: dict[str, Callable[..., Any]]
    specs: Mapping[str, ToolSpec]
    presentation_config: ToolPresentationConfig
    result_store: ResultResourceStore


def create_mcp_server(
    *,
    specs: Mapping[str, ToolSpec],
    registry_provider: Callable[[], Any],
    dispatcher_provider: Callable[[], Callable[..., Any]],
    presentation_config: ToolPresentationConfig | None = None,
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
        max_memory_bytes=effective_config.result_cache_max_memory_bytes,
    )
    resource_mode = effective_config.large_result_mode == "resource"

    def _dispatch_with_presentation(
        spec_name: str,
        raw_args: dict[str, Any] | None,
        target: str,
        *,
        registry,
    ) -> Any:
        spec = effective_specs[spec_name]
        if spec.presenter == "batch":
            raw_args = _validate_raw_args(spec_name, spec.input_model, raw_args)
            for request in raw_args["requests"]:
                child = effective_specs.get(request["tool"])
                if (
                    child is None
                    or child.safety_tag != ToolSafetyTag.READ_ONLY
                    or child.executor_kind != ExecutorKind.CORE_COMMAND
                ):
                    raise ValueError("batch_read tool is not enabled for reads: %s" % request["tool"])
        dispatcher = dispatcher_provider()
        result = dispatcher(
            spec_name,
            raw_args,
            target,
            registry=registry,
        )
        if spec.presenter == "batch":
            return present_batch_result(
                result,
                target=target,
                max_output_chars=raw_args["max_output_chars"],
                config=effective_config,
                store=result_store,
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
    bindings = [
        ToolBinding(
            tool,
            as_anticipated_tool_failure(
                tools[tool.name],
                partial(present_tool_error, tool=tool.name, config=effective_config, store=result_store),
            ),
            public_arguments_model(effective_specs[tool.name]),
        )
        for tool in tool_objects
    ]
    if resource_mode:
        bindings.extend(build_result_tools(store=result_store, config=effective_config))
    mcp = GhidraMCPServer(
        bindings=bindings,
        specs=effective_specs,
        instructions=build_server_instructions(specs=effective_specs, config=effective_config),
        result_store=result_store if resource_mode else None,
    )
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
    "package_version",
]
