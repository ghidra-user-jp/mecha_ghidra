"""A core command tool's reply names the program state its result came from."""

from __future__ import annotations

import asyncio
import json

from mcp.types import CallToolResult, TextContent

from ghidra_mcp.contracts.tool_spec import get_all_tool_specs, get_tool_spec
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.operation_presentation import structured_value
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import spec_wire_output_schema

SOURCE = {"program": "/hello.bin", "revision": "5d41402a:7"}


class Registry:
    def __init__(self, value="int main(void) { return 0; }") -> None:
        self.value = value
        self.failure: Exception | None = None

    def call(self, command, params, target):
        if self.failure is not None:
            raise self.failure
        return self.value


def _server(registry, *, command_source=lambda: dict(SOURCE)):
    return create_mcp_server(
        specs={name: get_tool_spec(name) for name in ("decompile_function", "get_operation")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatch_tool,
        command_source=command_source,
    ).mcp


def _call(mcp, **arguments):
    return asyncio.run(mcp.call_tool("decompile_function", {"target": "t", "address": "0x1000", **arguments}))


def test_a_core_read_names_its_target_program_and_revision():
    reply = _call(_server(Registry()))

    source = {"target": "t", **SOURCE}
    assert not reply.is_error
    assert reply.structured_content == {"result": "int main(void) { return 0; }", "source": source}
    # Clients that show the model only text still see it.
    assert json.loads(reply.content[-1].text) == {"source": source}


def test_a_stored_result_notice_carries_the_source_in_its_metadata():
    reply = _call(_server(Registry(value="x" * 50_000)))

    assert reply.structured_content["truncated"] is True
    assert reply.structured_content["source"] == {"target": "t", **SOURCE}
    # The notice keeps its text and resource link blocks.
    assert len(reply.content) == 2


def test_a_failed_call_and_a_server_without_a_source_reader_name_none():
    registry = Registry()
    registry.failure = DomainError(code=ErrorCode.PROGRAM_NOT_FOUND, message="no program")
    failed = _call(_server(registry))
    assert failed.is_error and "source" not in failed.structured_content

    plain = _call(_server(Registry(), command_source=None))
    assert plain.structured_content == {"result": "int main(void) { return 0; }"}


def test_only_core_command_tools_publish_a_source():
    specs = get_all_tool_specs()
    decompile = spec_wire_output_schema(specs["decompile_function"])
    envelope = next(variant for variant in decompile["anyOf"] if "result" in variant.get("properties", {}))
    assert "source" in envelope["properties"]
    operation = spec_wire_output_schema(specs["get_operation"])
    assert all("source" not in variant.get("properties", {}) for variant in operation["anyOf"])


def test_a_job_record_keeps_the_value_without_the_source():
    reply = CallToolResult(
        content=[TextContent(type="text", text="{}")],
        structured_content={"result": {"ok": True}, "source": {"target": "t", **SOURCE}},
    )
    assert structured_value(reply) == {"ok": True}
