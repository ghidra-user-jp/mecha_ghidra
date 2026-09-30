"""The primitives the official MCP conformance suite expects a server under test to offer.

The suite calls tools, resources and prompts by fixed names (``test_simple_text``, ``test://static-text``,
``test_simple_prompt``, and so on).  They exist only in the test server that ``server.py`` builds from the real
server class: the product never publishes them, and no command-line option turns them on.

Not built, on purpose: what the 2026-07-28 revision deprecates (sampling, roots and logging, SEP-2577).  The
scenarios that need them stay in the expected-failures baselines, each with its reason.

Everything is registered through the low-level server's public API (``add_request_handler``, ``middleware``), on
top of the handlers the product already installed.
"""

from __future__ import annotations

import base64
import io
import json
import re
import wave
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp import MCPError
from mcp.server import Server
from mcp.server.request_state import RequestStateBoundary, RequestStateSecurity
from mcp_types import (
    INVALID_PARAMS,
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    AudioContent,
    BlobResourceContents,
    CallToolRequestParams,
    CallToolResult,
    ClientCapabilities,
    CompleteRequestParams,
    CompleteResult,
    Completion,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    EmbeddedResource,
    GetPromptRequestParams,
    GetPromptResult,
    ImageContent,
    InputRequiredResult,
    ListPromptsResult,
    MissingRequiredClientCapabilityErrorData,
    PaginatedRequestParams,
    Prompt,
    PromptArgument,
    PromptMessage,
    ReadResourceRequestParams,
    ReadResourceResult,
    Resource,
    ResourceTemplate,
    SamplingCapability,
    TextContent,
    TextResourceContents,
    Tool,
)

Handler = Callable[[Any, Any], Awaitable[Any]]

# The smallest valid PNG (one red pixel), and a silent WAV built here, so neither is an opaque blob.
PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="


def _wav_base64() -> str:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(b"\x00\x00" * 80)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


WAV_BASE64 = _wav_base64()
STATIC_TEXT_URI = "test://static-text"
STATIC_BINARY_URI = "test://static-binary"
TEMPLATE_URI = re.compile(r"^test://template/(?P<id>[^/]+)/data$")


def _text(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)])


def _elicitation(message: str, field: str, kind: str) -> ElicitRequest:
    schema = {"type": "object", "properties": {field: {"type": kind}}, "required": [field]}
    return ElicitRequest(params=ElicitRequestFormParams(message=message, requested_schema=schema))


def _accepted(responses: dict | None, key: str) -> dict | None:
    """The content of an accepted elicitation answer under ``key``, or None (missing, declined, or another kind)."""
    answer = (responses or {}).get(key)
    if isinstance(answer, ElicitResult) and answer.action == "accept":
        return answer.content or {}
    return None


def _declared(ctx: Any, capability: str) -> bool:
    capabilities = ctx.session.client_capabilities
    return capabilities is not None and getattr(capabilities, capability, None) is not None


# ---- tools ----------------------------------------------------------------------------------------------------


async def _simple_text(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    return _text("This is a simple text response for testing.")


async def _image(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    return CallToolResult(content=[ImageContent(type="image", data=PNG_BASE64, mime_type="image/png")])


async def _audio(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    return CallToolResult(content=[AudioContent(type="audio", data=WAV_BASE64, mime_type="audio/wav")])


async def _embedded_resource(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    resource = TextResourceContents(
        uri="test://embedded-resource", mime_type="text/plain", text="This is an embedded resource content."
    )
    return CallToolResult(content=[EmbeddedResource(type="resource", resource=resource)])


async def _mixed_content(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    resource = TextResourceContents(
        uri="test://mixed-content-resource", mime_type="application/json", text='{"test":"data","value":123}'
    )
    return CallToolResult(
        content=[
            TextContent(type="text", text="Multiple content types test:"),
            ImageContent(type="image", data=PNG_BASE64, mime_type="image/png"),
            EmbeddedResource(type="resource", resource=resource),
        ]
    )


async def _error(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text="This tool intentionally returns an error for testing")], is_error=True
    )


async def _missing_capability(ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    """The suite's probe for a call that needs a capability the client did not declare (-32021).

    It names ``sampling``, as the suite expects; nothing here asks the client to sample.
    """
    if not _declared(ctx, "sampling"):
        data = MissingRequiredClientCapabilityErrorData(
            required_capabilities=ClientCapabilities(sampling=SamplingCapability())
        )
        raise MCPError(
            code=MISSING_REQUIRED_CLIENT_CAPABILITY,
            message="The client did not declare the sampling capability this call requires",
            data=data.model_dump(by_alias=True, mode="json", exclude_none=True),
        )
    return _text("The client declared the sampling capability.")


async def _streaming_elicitation(ctx: Any, _params: CallToolRequestParams) -> Any:
    """Asks for input the only way the 2026-07-28 revision allows: in the result, never as a request of its own."""
    if _declared(ctx, "elicitation"):
        return InputRequiredResult(input_requests={"ask": _elicitation("Which option?", "option", "string")})
    return _text("The client declared no elicitation capability.")


async def _logging(_ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    return _text("No log message is sent unless the request sets a log level.")


async def _with_progress(ctx: Any, _params: CallToolRequestParams) -> CallToolResult:
    """Three reports for a client that sent a progressToken; without one the same calls send nothing."""
    for progress, message in ((0, "Starting"), (50, "Halfway"), (100, "Complete")):
        await ctx.session.report_progress(progress, 100, message)
    return _text("Progress test completed.")


# ---- tools: input required (SEP-2322) -------------------------------------------------------------------------


async def _input_elicitation(_ctx: Any, params: CallToolRequestParams) -> Any:
    answer = _accepted(params.input_responses, "user_name")
    if answer is None:  # first round, or an answer that is missing or for another key: ask again
        return InputRequiredResult(input_requests={"user_name": _elicitation("What is your name?", "name", "string")})
    return _text(f"Hello, {answer.get('name', '')}!")


async def _input_request_state(_ctx: Any, params: CallToolRequestParams) -> Any:
    # The boundary middleware seals the state on the way out and hands back the plaintext it minted.
    if params.request_state == "confirm-pending" and _accepted(params.input_responses, "confirm") is not None:
        return _text("Confirmation received: state-ok")
    return InputRequiredResult(
        input_requests={"confirm": _elicitation("Please confirm", "ok", "boolean")},
        request_state="confirm-pending",
    )


async def _input_multi_round(_ctx: Any, params: CallToolRequestParams) -> Any:
    if params.request_state == "round-2" and _accepted(params.input_responses, "step2") is not None:
        return _text("All steps done.")
    if params.request_state == "round-1" and _accepted(params.input_responses, "step1") is not None:
        return InputRequiredResult(
            input_requests={"step2": _elicitation("Step 2: What is your favorite color?", "color", "string")},
            request_state="round-2",
        )
    return InputRequiredResult(
        input_requests={"step1": _elicitation("Step 1: What is your name?", "name", "string")},
        request_state="round-1",
    )


async def _input_tampered_state(_ctx: Any, params: CallToolRequestParams) -> Any:
    if params.request_state == "untampered":
        return _text("The state was intact.")
    return InputRequiredResult(
        input_requests={"go": _elicitation("Continue?", "ok", "boolean")}, request_state="untampered"
    )


async def _input_capabilities(ctx: Any, _params: CallToolRequestParams) -> Any:
    """Asks only for what the client declared; of the kinds this server knows, that is elicitation."""
    if _declared(ctx, "elicitation"):
        return InputRequiredResult(input_requests={"who": _elicitation("What is your name?", "name", "string")})
    return _text("The client declared nothing this server asks for.")


def _object_schema() -> dict[str, Any]:
    return {"type": "object", "properties": {}}


# SEP-1613 and SEP-2106: a listing must keep these JSON Schema 2020-12 keywords as they are.
JSON_SCHEMA_2020_12 = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "$defs": {
        "address": {
            "$anchor": "addressDef",
            "type": "object",
            "properties": {"street": {"type": "string"}, "city": {"type": "string"}},
        }
    },
    "properties": {
        "name": {"type": "string"},
        "address": {"$ref": "#/$defs/address"},
        "contactMethod": {"type": "string", "enum": ["phone", "email"]},
        "phone": {"type": "string"},
        "email": {"type": "string"},
    },
    "allOf": [{"anyOf": [{"required": ["phone"]}, {"required": ["email"]}]}],
    "if": {"properties": {"contactMethod": {"const": "phone"}}, "required": ["contactMethod"]},
    "then": {"required": ["phone"]},
    "else": {"required": ["email"]},
    "additionalProperties": False,
}

# SEP-2243: a parameter annotated x-mcp-header is also sent as an Mcp-Param-Region header, and the two must agree.
CUSTOM_HEADER_SCHEMA = {
    "type": "object",
    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
    "required": ["region"],
}


async def _custom_headers(_ctx: Any, params: CallToolRequestParams) -> CallToolResult:
    return _text(f"region: {(params.arguments or {}).get('region', '')}")


@dataclass(frozen=True)
class FixtureTool:
    name: str
    description: str
    handler: Handler
    input_schema: dict[str, Any] | None = None

    @property
    def tool(self) -> Tool:
        return Tool(name=self.name, description=self.description, input_schema=self.input_schema or _object_schema())


FIXTURE_TOOLS = (
    FixtureTool("test_simple_text", "Returns a simple text result.", _simple_text),
    FixtureTool("test_image_content", "Returns an image.", _image),
    FixtureTool("test_audio_content", "Returns audio.", _audio),
    FixtureTool("test_embedded_resource", "Returns an embedded resource.", _embedded_resource),
    FixtureTool("test_multiple_content_types", "Returns text, an image and an embedded resource.", _mixed_content),
    FixtureTool("test_error_handling", "Always returns an error result.", _error),
    FixtureTool(
        "test_missing_capability", "Needs a client capability the suite leaves undeclared.", _missing_capability
    ),
    FixtureTool("test_streaming_elicitation", "Asks for input through the result.", _streaming_elicitation),
    FixtureTool("test_logging_tool", "Sends no log message.", _logging),
    FixtureTool("test_tool_with_progress", "Reports progress in three steps.", _with_progress),
    FixtureTool("test_input_required_result_elicitation", "Asks for a name.", _input_elicitation),
    FixtureTool(
        "test_input_required_result_request_state", "Asks for a confirmation and keeps state.", _input_request_state
    ),
    FixtureTool("test_input_required_result_multi_round", "Asks in two rounds.", _input_multi_round),
    FixtureTool("test_input_required_result_tampered_state", "Keeps integrity-protected state.", _input_tampered_state),
    FixtureTool("test_input_required_result_capabilities", "Asks for what the client declared.", _input_capabilities),
    FixtureTool(
        "test_custom_headers",
        "Takes a parameter that is also an Mcp-Param header.",
        _custom_headers,
        CUSTOM_HEADER_SCHEMA,
    ),
    FixtureTool(
        "json_schema_2020_12_tool", "Tool with JSON Schema 2020-12 features", _simple_text, JSON_SCHEMA_2020_12
    ),
)
_TOOL_HANDLERS = {fixture.name: fixture.handler for fixture in FIXTURE_TOOLS}

# ---- resources ------------------------------------------------------------------------------------------------

FIXTURE_RESOURCES = (
    Resource(name="static-text", uri=STATIC_TEXT_URI, description="A static text resource.", mime_type="text/plain"),
    Resource(
        name="static-binary", uri=STATIC_BINARY_URI, description="A static binary resource.", mime_type="image/png"
    ),
)
FIXTURE_TEMPLATES = (
    ResourceTemplate(
        name="template-data",
        uri_template="test://template/{id}/data",
        description="Data for an id.",
        mime_type="application/json",
    ),
)


def _read_fixture_resource(uri: str) -> ReadResourceResult | None:
    if uri == STATIC_TEXT_URI:
        text = TextResourceContents(
            uri=uri, mime_type="text/plain", text="This is the content of the static text resource."
        )
        return ReadResourceResult(contents=[text])
    if uri == STATIC_BINARY_URI:
        return ReadResourceResult(contents=[BlobResourceContents(uri=uri, mime_type="image/png", blob=PNG_BASE64)])
    match = TEMPLATE_URI.match(uri)
    if match is not None:
        identifier = match.group("id")
        body = json.dumps(
            {"id": identifier, "templateTest": True, "data": f"Data for ID: {identifier}"}, separators=(",", ":")
        )
        return ReadResourceResult(contents=[TextResourceContents(uri=uri, mime_type="application/json", text=body)])
    return None


# ---- prompts --------------------------------------------------------------------------------------------------

FIXTURE_PROMPTS = (
    Prompt(name="test_simple_prompt", description="A prompt without arguments."),
    Prompt(
        name="test_prompt_with_arguments",
        description="A prompt with two required arguments.",
        arguments=[
            PromptArgument(name="arg1", description="First test argument", required=True),
            PromptArgument(name="arg2", description="Second test argument", required=True),
        ],
    ),
    Prompt(
        name="test_prompt_with_embedded_resource",
        description="A prompt that embeds a resource.",
        arguments=[PromptArgument(name="resourceUri", description="URI of the resource to embed", required=True)],
    ),
    Prompt(name="test_prompt_with_image", description="A prompt with an image."),
    Prompt(name="test_input_required_result_prompt", description="A prompt that asks for input first."),
)


def _user(content: Any) -> PromptMessage:
    return PromptMessage(role="user", content=content)


def _required(arguments: dict[str, str] | None, *names: str) -> dict[str, str]:
    given = arguments or {}
    missing = [name for name in names if name not in given]
    if missing:
        raise MCPError(code=INVALID_PARAMS, message=f"Missing required prompt arguments: {', '.join(missing)}")
    return given


async def _get_prompt(_ctx: Any, params: GetPromptRequestParams) -> Any:
    name = params.name
    if name == "test_simple_prompt":
        return GetPromptResult(messages=[_user(TextContent(type="text", text="This is a simple prompt for testing."))])
    if name == "test_prompt_with_arguments":
        given = _required(params.arguments, "arg1", "arg2")
        text = f"Prompt with arguments: arg1='{given['arg1']}', arg2='{given['arg2']}'"
        return GetPromptResult(messages=[_user(TextContent(type="text", text=text))])
    if name == "test_prompt_with_embedded_resource":
        given = _required(params.arguments, "resourceUri")
        resource = TextResourceContents(
            uri=given["resourceUri"], mime_type="text/plain", text="Embedded resource content for testing."
        )
        return GetPromptResult(
            messages=[
                _user(EmbeddedResource(type="resource", resource=resource)),
                _user(TextContent(type="text", text="Please process the embedded resource above.")),
            ]
        )
    if name == "test_prompt_with_image":
        return GetPromptResult(
            messages=[
                _user(ImageContent(type="image", data=PNG_BASE64, mime_type="image/png")),
                _user(TextContent(type="text", text="Please analyze the image above.")),
            ]
        )
    if name == "test_input_required_result_prompt":
        answer = _accepted(params.input_responses, "user_context")
        if answer is None:
            request = _elicitation("What context should the prompt use?", "context", "string")
            return InputRequiredResult(input_requests={"user_context": request})
        text = f"Prompt using the context: {answer.get('context', '')}"
        return GetPromptResult(messages=[_user(TextContent(type="text", text=text))])
    raise MCPError(code=INVALID_PARAMS, message=f"Unknown prompt: {name}")


async def _list_prompts(_ctx: Any, _params: PaginatedRequestParams | None) -> ListPromptsResult:
    return ListPromptsResult(prompts=list(FIXTURE_PROMPTS))


async def _complete(_ctx: Any, _params: CompleteRequestParams) -> CompleteResult:
    """The capability must be declared and the endpoint must answer; the suite accepts no suggestions."""
    return CompleteResult(completion=Completion(values=[], total=0, has_more=False))


# ---- wiring ---------------------------------------------------------------------------------------------------


def _extend(server: Server, method: str, extend: Callable[[Handler, Any, Any], Awaitable[Any]]) -> None:
    """Put ``extend`` in front of the handler the product registered for ``method``."""
    entry = server.get_request_handler(method)
    assert entry is not None, f"the server registers no {method} handler"
    original = entry.handler

    async def handler(ctx: Any, params: Any) -> Any:
        return await extend(original, ctx, params)

    server.add_request_handler(method, entry.params_type, handler)


async def _tools_list(original: Handler, ctx: Any, params: Any) -> Any:
    result = await original(ctx, params)
    return result.model_copy(update={"tools": [*result.tools, *(fixture.tool for fixture in FIXTURE_TOOLS)]})


async def _tools_call(original: Handler, ctx: Any, params: CallToolRequestParams) -> Any:
    handler = _TOOL_HANDLERS.get(params.name)
    return await (handler or original)(ctx, params)


async def _resources_list(original: Handler, ctx: Any, params: Any) -> Any:
    result = await original(ctx, params)
    return result.model_copy(update={"resources": [*result.resources, *FIXTURE_RESOURCES]})


async def _templates_list(original: Handler, ctx: Any, params: Any) -> Any:
    result = await original(ctx, params)
    return result.model_copy(update={"resource_templates": [*result.resource_templates, *FIXTURE_TEMPLATES]})


async def _resources_read(original: Handler, ctx: Any, params: ReadResourceRequestParams) -> Any:
    fixture = _read_fixture_resource(str(params.uri))
    return fixture if fixture is not None else await original(ctx, params)


def install_fixtures(server: Server) -> None:
    """Add the suite's fixtures to ``server``, which the product built (``create_mcp_server(...).mcp``)."""
    _extend(server, "tools/list", _tools_list)
    _extend(server, "tools/call", _tools_call)
    _extend(server, "resources/list", _resources_list)
    _extend(server, "resources/templates/list", _templates_list)
    _extend(server, "resources/read", _resources_read)
    server.add_request_handler("prompts/list", PaginatedRequestParams, _list_prompts)
    server.add_request_handler("prompts/get", GetPromptRequestParams, _get_prompt)
    server.add_request_handler("completion/complete", CompleteRequestParams, _complete)
    # requestState is attacker-controlled: seal it on the way out, verify it on the way in (-32602 when altered).
    server.middleware.append(RequestStateBoundary(RequestStateSecurity.ephemeral(), default_audience=server.name))
