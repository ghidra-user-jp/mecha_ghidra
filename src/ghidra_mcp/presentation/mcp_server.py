"""MCP server bootstrap for the presentation layer."""

from __future__ import annotations

import functools
import hashlib
import importlib.metadata
import inspect
import json
import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from types import MappingProxyType
from typing import Any, Callable, Literal

import anyio
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError
from mcp import MCPError
from mcp.server import Server
from mcp.types import (
    INVALID_PARAMS,
    CallToolResult,
    ListResourcesResult,
    ListResourceTemplatesResult,
    ListToolsResult,
    ReadResourceResult,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
)
from pydantic import ValidationError

from ghidra_mcp.application.services.operations import PENDING_STATES
from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolSafetyTag, ToolSpec, validate_tool_selection
from ghidra_mcp.domain import DomainError, ErrorCode, get_lock_timeout_seconds
from ghidra_mcp.presentation.batch_results import present_batch_result
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.deferred_calls import DeferredCalls, DeferredReply, deferred_reply
from ghidra_mcp.presentation.doc_resources import tool_docs_detail, tool_docs_index
from ghidra_mcp.presentation.error_mapper import map_exception
from ghidra_mcp.presentation.result_compaction import _json_text, _presentation_failure_result
from ghidra_mcp.presentation.result_errors import present_tool_error
from ghidra_mcp.presentation.result_resources import (
    RESULT_RESOURCE_PREFIX,
    ResultResourceStore,
    build_result_tools,
    maybe_compact_tool_result,
)
from ghidra_mcp.presentation.server_instructions import build_server_instructions
from ghidra_mcp.presentation.startup import StartupGate, startup_error_result
from ghidra_mcp.presentation.tool_binding import ToolBinding, complete_tool_result, error_result
from ghidra_mcp.presentation.tool_dispatcher import _validate_raw_args
from ghidra_mcp.presentation.tool_errors import ToolError
from ghidra_mcp.presentation.tool_registry import (
    ToolRegistry,
    anticipated_error_result,
    as_anticipated_tool_failure,
    public_arguments_model,
)

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


@dataclass(frozen=True)
class ResourcePayload:
    content: str
    mime_type: str


class GhidraMCPServer(Server):
    """Application handlers registered through the SDK's public low-level API.

    Tools named in ``deferrable`` run through ``deferred_calls``: one still
    running after its wait replies with a job record from ``operations_provider``.
    ``prepare_thread`` runs on a tool call's worker thread before the call; the
    CLI uses it to attach the thread to the JVM under its own name.  With a
    ``startup_gate``, ``tools/call`` first waits for Ghidra to finish starting
    in the background; every other request is answered at once.  The published
    schemas are checked by the test suite, not here: checking them took most of
    the server's construction time.
    """

    def __init__(
        self,
        *,
        bindings,
        specs,
        result_store,
        instructions,
        operations_provider: Callable[[], Any] | None = None,
        deferrable: frozenset[str] = frozenset(),
        deferred_calls: DeferredCalls | None = None,
        prepare_thread: Callable[[], None] | None = None,
        startup_gate: StartupGate | None = None,
    ):
        self.bindings = {binding.definition.name: binding for binding in bindings}
        self.specs = specs
        self.result_store = result_store
        self.operations_provider = operations_provider
        self.deferrable = deferrable
        # Tools whose request_id makes a resend return the first call's reply.
        self.replaying = frozenset(name for name, spec in specs.items() if spec.replays_requests)
        self.prepare_thread = prepare_thread
        self.deferred_calls = deferred_calls or DeferredCalls(prepare_thread=prepare_thread)
        self.startup_gate = startup_gate
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
            raise ToolError(f"{name} input validation failed: {exc}", code=ErrorCode.VALIDATION_ERROR) from exc
        kwargs = parsed.model_dump()
        waited = 0.0
        if self.startup_gate is not None:
            try:
                waited = await self.startup_gate.wait(get_lock_timeout_seconds())
            except DomainError as exc:
                return self.complete_result(name, kwargs, startup_error_result(exc))
            if waited and "wait_seconds" in kwargs:
                # Time spent waiting for Ghidra counts against the job wait, so a
                # reply still comes within the usual bound.
                kwargs["wait_seconds"] = max(0, int(kwargs["wait_seconds"] - waited))
        operations = self.operations_provider() if self.operations_provider is not None else None
        if name in self.replaying and kwargs.get("request_id") is not None and operations is not None:
            return await self._call_once(name, binding, kwargs, operations, waited)
        if inspect.iscoroutinefunction(binding.function):
            value = await binding.function(**kwargs)
        elif name in self.deferrable and operations is not None:
            value = await self.deferred_calls.run(
                name,
                binding.function,
                kwargs,
                operations=operations,
                complete=partial(self.complete_result, name, kwargs),
                already_waited=waited,
            )
            if isinstance(value, DeferredReply):
                self._check_output(name, value.result)
                return value.result
        else:
            value = await anyio.to_thread.run_sync(partial(_prepared, self.prepare_thread, binding.function, kwargs))
        return self.complete_result(name, kwargs, value)

    async def _call_once(self, name: str, binding, kwargs: dict[str, Any], operations, waited: float):
        """Run a call sent with a request_id at most once; a resend gets the first call's reply.

        The record exists before the call runs (``OperationManager.claim_call``),
        and the call's thread stores the reply in it however the call ends.  A
        resend that finds the call still running waits for it like a new call,
        then replies ``deferred`` with the same record.
        """
        request_id = kwargs.pop("request_id")
        target = kwargs.get("target") or ""
        try:
            record, fresh = operations.claim_call(
                name, target, request_id=request_id, fingerprint=_call_fingerprint(name, kwargs)
            )
        except DomainError as exc:
            return self.complete_result(name, kwargs, anticipated_error_result(map_exception(exc)))
        if not fresh:
            return await self._replay(name, target, record["operation_id"], operations, waited)
        value = await self.deferred_calls.run(
            name,
            binding.function,
            kwargs,
            operations=operations,
            complete=partial(self.complete_result, name, kwargs),
            already_waited=waited,
            claimed=record,
            defer=name in self.deferrable,
        )
        if isinstance(value, DeferredReply):
            self._check_output(name, value.result)
            return value.result
        return self.complete_result(name, kwargs, value)

    async def _replay(self, name: str, target: str, operation_id: str, operations, waited: float):
        """The reply a resend gets: the first call's, once that call has finished."""
        wait = max(0.0, self.deferred_calls.defer_after - waited) if name in self.deferrable else math.inf
        with anyio.move_on_after(wait):
            while operations.is_pending(operation_id):
                await anyio.sleep(_OPERATION_WAIT_POLL_SECONDS)
        try:
            record = operations.get(operation_id=operation_id)
        except DomainError as exc:
            return self.complete_result(name, {"target": target}, anticipated_error_result(map_exception(exc)))
        if record["state"] in PENDING_STATES:
            reply = deferred_reply(name, target, record, self.deferred_calls.defer_after)
            self._check_output(name, reply)
            return reply
        reply = operations.reply_for(operation_id)
        if reply is None:
            return error_result(
                f"{name} already ran for this request_id, but its reply is no longer kept "
                "(result_discarded); inspect the program instead of sending the call again"
            )
        replayed = _replayed(CallToolResult.model_validate(reply))
        self._check_output(name, replayed)
        return replayed

    def complete_result(self, name: str, kwargs: dict[str, Any], value: Any):
        """The CallToolResult a finished call returns; a deferred call's thread records the same."""
        source = None
        if isinstance(value, _Sourced):
            value, source = value.value, value.source
        result = complete_tool_result(value, compact_json=self.bindings[name].compact_json)
        if source is not None:
            result = _with_source(result, {"target": kwargs.get("target") or "", **source})
        # The low-level SDK does not validate outputs. Enforce the advertised
        # contract here after presentation, including compaction/error variants.
        if not self._check_output(name, result):
            if result.is_error:
                return error_result(f"Error executing tool {name}")
            # Execution has already completed. Do not turn a presentation failure
            # into a retryable mutation error or discard its completion status.
            return _presentation_failure_result(name, kwargs.get("target", "default"))
        return result

    def _check_output(self, name: str, result) -> bool:
        try:
            self.output_validators[name].validate(result.structured_content)
        except SchemaValidationError:
            logger.exception("Invalid structured output for tool %s", name)
            return False
        return True

    async def handle_call_tool(self, _context, params):
        try:
            return await self.call_tool(params.name, params.arguments)
        except ToolError as exc:
            return error_result(str(exc), code=exc.code)
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
    prepare_thread: Callable[[], None] | None = None,
    startup_gate: StartupGate | None = None,
    command_source: Callable[[], dict[str, Any] | None] | None = None,
) -> MCPServerRuntime:
    """Build the MCP server for ``specs``.

    ``command_source`` reads, on the thread that ran it, the program and
    revision the last core command left; with it, a core command tool's reply
    names that ``source``.
    """
    effective_config = presentation_config or ToolPresentationConfig()
    effective_specs: dict[str, ToolSpec] = {}
    for supplied_name, spec in tuple(specs.items()):
        if supplied_name != spec.name:
            raise ValueError(f"Tool spec mapping key must match spec.name: {supplied_name!r} != {spec.name!r}")
        effective_specs[spec.name] = spec
    validate_tool_selection(effective_specs)
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
        if spec.presenter == "operation":
            # Bounded job records stay inline and are never replaced by a
            # stored-result reference, whatever the compaction limits.
            return result
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
    bindings = []
    admission_limiter = anyio.CapacityLimiter(2)
    for tool in tool_objects:
        entry = as_anticipated_tool_failure(
            tools[tool.name],
            partial(present_tool_error, tool=tool.name, config=effective_config, store=result_store),
        )
        if effective_specs[tool.name].presenter == "operation":
            entry = _operation_binding(entry, tool.name, registry_provider, admission_limiter, prepare_thread)
        elif command_source is not None and effective_specs[tool.name].reports_source:
            entry = _sourced(entry, command_source)
        bindings.append(
            ToolBinding(
                tool,
                entry,
                public_arguments_model(effective_specs[tool.name]),
            )
        )
    if resource_mode:
        bindings.extend(build_result_tools(store=result_store, config=effective_config))
    # A deferred reply names a job record that only get_operation reads.
    deferrable = (
        frozenset(name for name, spec in effective_specs.items() if spec.deferrable)
        if "get_operation" in effective_specs
        else frozenset()
    )
    mcp = GhidraMCPServer(
        bindings=bindings,
        specs=effective_specs,
        instructions=build_server_instructions(specs=effective_specs, config=effective_config),
        result_store=result_store if resource_mode else None,
        operations_provider=lambda: getattr(registry_provider(), "operations", None),
        deferrable=deferrable,
        prepare_thread=prepare_thread,
        startup_gate=startup_gate,
    )
    return MCPServerRuntime(
        mcp=mcp,
        tools=tools,
        specs=MappingProxyType(effective_specs),
        presentation_config=effective_config,
        result_store=result_store,
    )


# How often a waiting call re-reads the in-memory job record.
_OPERATION_WAIT_POLL_SECONDS = 0.1
# Job record tools that answer from memory, on the event loop. cancel_operation
# may cancel a Java monitor: the CLI attaches the loop's thread to the JVM while
# Ghidra starts, before any script can run, so the call attaches no new JVM
# thread that a running script would take for its own.
_INLINE_OPERATION_TOOLS = frozenset({"get_operation", "cancel_operation"})


@dataclass(frozen=True, slots=True)
class _Sourced:
    """A core command tool's reply value, with the program state the command left (see _sourced)."""

    value: Any
    source: dict[str, Any] | None


def _sourced(entry: Callable[..., Any], command_source: Callable[[], dict[str, Any] | None]) -> Callable[..., Any]:
    """Run a core command tool and note where its result came from, on the thread that ran it."""

    @functools.wraps(entry)
    def call(**kwargs: Any) -> _Sourced:
        value = entry(**kwargs)
        # The command ran on this thread just now, under its target's locks;
        # a failed one left no source.
        try:
            source = command_source()
        except Exception:
            source = None
        return _Sourced(value, source)

    return call


def _with_source(result: CallToolResult, source: dict[str, Any]) -> CallToolResult:
    """Add ``source`` beside the result; also as text, for clients that show the model only text."""
    if result.is_error or not isinstance(result.structured_content, dict):
        return result
    content = list(result.content)
    if set(result.structured_content) == {"result"}:
        # A stored-result notice keeps its two blocks; its metadata carries the source.
        content.append(TextContent(type="text", text=_json_text({"source": source})))
    return result.model_copy(
        update={"structured_content": {**result.structured_content, "source": source}, "content": content}
    )


def _replayed(result: CallToolResult) -> CallToolResult:
    """The first call's reply, marked ``replayed`` (also as text) so the caller knows nothing ran again."""
    if not isinstance(result.structured_content, dict):
        return result
    return result.model_copy(
        update={
            "structured_content": {**result.structured_content, "replayed": True},
            "content": [*result.content, TextContent(type="text", text=_json_text({"replayed": True}))],
        }
    )


def _call_fingerprint(name: str, kwargs: Mapping[str, Any]) -> str:
    """SHA-256 of a call's canonical arguments, compared when its request_id comes again."""
    encoded = json.dumps({"tool": name, **kwargs}, sort_keys=True, default=str, ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _prepared(prepare: Callable[[], None] | None, function: Callable[..., Any], kwargs: dict[str, Any]) -> Any:
    if prepare is not None:
        prepare()
    return function(**kwargs)


def _operation_binding(entry, name, registry_provider, admission_limiter, prepare_thread=None) -> Callable[..., Any]:
    """Async entry for the background-job tools.

    New admission may resolve paths on slow storage, so it runs on its own
    small thread limiter; lookups, cancellations and replays of an accepted
    request_id run inline. The server-side wait happens here, on the event
    loop, without holding a thread: the synchronous entry is always called
    with wait_seconds=0. The job itself is owned by the job worker.
    """

    async def control(**kwargs):
        wait_seconds = kwargs.get("wait_seconds") or 0
        # cancel_operation takes no wait.
        immediate = {**kwargs, "wait_seconds": 0} if "wait_seconds" in kwargs else dict(kwargs)
        manager = getattr(registry_provider(), "operations", None)
        if name not in _INLINE_OPERATION_TOOLS and (
            manager is None or not manager.has_request(kwargs.get("request_id"))
        ):
            # Shielded: once the request arrived, admission finishes even if the
            # client gives up, so the job is either accepted or refused, never
            # half-way; a lost reply is recovered by resending or by request_id.
            with anyio.CancelScope(shield=True):
                value = await anyio.to_thread.run_sync(
                    partial(_prepared, prepare_thread, entry, immediate), limiter=admission_limiter
                )
        else:
            value = entry(**immediate)
        if manager is None or wait_seconds <= 0 or not isinstance(value, dict):
            return value
        if value.get("state") not in PENDING_STATES:
            return value
        operation_id = value["operation_id"]
        with anyio.move_on_after(wait_seconds):
            while manager.is_pending(operation_id):
                await anyio.sleep(_OPERATION_WAIT_POLL_SECONDS)
        try:
            latest = manager.wait_for(operation_id, 0)
        except DomainError:
            return value
        if "replayed" in value:
            latest["replayed"] = value["replayed"]
        return latest

    return control


__all__ = [
    "GhidraMCPServer",
    "MCPServerRuntime",
    "ServerLogLevel",
    "create_mcp_server",
    "normalize_server_log_level",
    "package_version",
]
