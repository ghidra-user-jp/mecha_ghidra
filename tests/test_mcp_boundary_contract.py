"""Validate raw MCP requests, not only the inner Python dispatcher."""

import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolRequestParams

from ghidra_mcp.contracts.tool_spec import get_all_tool_specs
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_registry import public_input_schema


def server(registry):
    return create_mcp_server(
        specs=get_all_tool_specs(), registry_provider=lambda: registry, dispatcher_provider=lambda: dispatch_tool
    ).mcp


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("list_functions", {"limit": "2"}),
        ("list_functions", {"limit": 0}),
        ("list_functions", {"limit": 10001}),
        ("get_bytes", {"address": "0x1000", "size": 1048577}),
        ("remove_struct_members", {"struct_name": "S", "member_names": ["magic"]}),
        ("remove_struct_members", {"struct_name": "S", "members": '["magic"]'}),
    ],
)
def test_invalid_sdk_arguments_never_reach_executor(name, arguments):
    class Registry:
        def call(self, *_args):
            pytest.fail("invalid request reached executor")

    with pytest.raises(ToolError):
        asyncio.run(server(Registry()).call_tool(name, arguments))


def test_registered_schemas_match_public_contract():
    registered = {tool.name: tool for tool in asyncio.run(server(None).list_tools())}
    for name, spec in get_all_tool_specs().items():
        assert registered[name].input_schema == public_input_schema(spec)


def test_partial_success_survives_sdk_request_handler():
    details = {"operation_completed": True, "partial_success": True, "operation_result": {"version": 7}}

    class Registry:
        def commit_project_program(self, *_args, **_kwargs):
            raise DomainError(ErrorCode.REOPEN_FAILED, "reopen failed", "Inspect state before retrying", False, details)

    result = asyncio.run(
        server(Registry())._handle_call_tool(
            None, CallToolRequestParams(name="commit_project_program", arguments={"target": "t", "message": "m"})
        )
    )
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == "REOPEN_FAILED"
    assert error["retryable"] is False
    assert error["details"] == details
    assert json.loads(result.content[0].text) == result.structured_content
