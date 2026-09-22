"""Validate raw MCP requests, not only the inner Python dispatcher."""

import asyncio
import json

import pytest
from mcp.types import CallToolRequestParams

from ghidra_mcp.contracts.tool_spec import get_all_tool_specs
from ghidra_mcp.domain import DomainError, ErrorCode
from ghidra_mcp.presentation.mcp_server import create_mcp_server
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool
from ghidra_mcp.presentation.tool_errors import ToolError
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
        ("apply_edits", {"edits": []}),
        ("apply_edits", {"edits": [{"kind": "run_script", "script": "x"}]}),
        ("apply_edits", {"edits": [{"kind": "rename_function", "address": "0x1000", "newName": "main"}]}),
        ("apply_edits", {"edits": [{"kind": "rename_function", "address": "0x1000"}]}),
        (
            "apply_edits",
            {"edits": [{"kind": "rename_function", "address": "0x1000", "new_name": "main", "create_namespace": True}]},
        ),
        (
            "apply_edits",
            {"edits": [{"kind": "set_comment", "address": "0x1000", "comment": "c", "comment_type": "bad"}]},
        ),
        (
            "apply_edits",
            {"edits": [{"kind": "set_global_data_type", "address": "0x1000", "data_type": "int", "length": "4"}]},
        ),
        ("get_xrefs", {"address": "0x1000", "direction": "incoming"}),
        ("get_call_edges", {"address": "0x1000", "limit": 0}),
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


@pytest.mark.parametrize("name", ["bsim_query", "bsim_apply_matches"])
def test_bsim_significance_above_one_reaches_executor(name):
    calls = []

    class Registry:
        def bsim_query(self, target, **params):
            calls.append((target, params))
            return {"status": "ok"}

        bsim_apply_matches = bsim_query

    arguments = {"target": "t", "significance_threshold": 2.5}
    if name == "bsim_query":
        arguments["scope"] = "program"
    asyncio.run(server(Registry()).call_tool(name, arguments))
    assert calls[0][0] == "t"
    assert calls[0][1]["significance_threshold"] == 2.5
    schema = public_input_schema(get_all_tool_specs()[name])["properties"]["significance_threshold"]
    assert "maximum" not in schema


@pytest.mark.parametrize("name", ["bsim_query", "bsim_apply_matches"])
@pytest.mark.parametrize("threshold", [-0.1, float("inf"), float("nan")])
def test_bsim_significance_rejects_negative_or_nonfinite_values(name, threshold):
    class Registry:
        def bsim_query(self, *_args, **_kwargs):
            pytest.fail("invalid significance reached executor")

        bsim_apply_matches = bsim_query

    arguments = {"target": "t", "significance_threshold": threshold}
    if name == "bsim_query":
        arguments["scope"] = "program"
    with pytest.raises(ToolError):
        asyncio.run(server(Registry()).call_tool(name, arguments))


def test_compact_schema_preserves_a_property_named_title_and_literal_objects():
    from ghidra_mcp.presentation.tool_registry import _without_schema_titles

    schema = {
        "title": "Generated",
        "properties": {"title": {"type": "string", "title": "Title"}},
        "const": {"title": "literal"},
        "default": {"title": "default"},
    }
    compact = _without_schema_titles(schema)
    assert "title" not in compact
    assert compact["properties"] == {"title": {"type": "string"}}
    assert compact["const"] == schema["const"] and compact["default"] == schema["default"]


def test_partial_success_survives_sdk_request_handler():
    details = {"operation_completed": True, "partial_success": True, "operation_result": {"version": 7}}

    class Registry:
        def commit_project_program(self, *_args, **_kwargs):
            raise DomainError(ErrorCode.REOPEN_FAILED, "reopen failed", "Inspect state before retrying", False, details)

    result = asyncio.run(
        server(Registry()).handle_call_tool(
            None, CallToolRequestParams(name="commit_project_program", arguments={"target": "t", "message": "m"})
        )
    )
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == "REOPEN_FAILED"
    assert error["retryable"] is False
    assert error["details"] == details
    assert json.loads(result.content[0].text) == result.structured_content
