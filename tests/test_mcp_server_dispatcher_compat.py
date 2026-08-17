from __future__ import annotations

import asyncio
import json

import pytest
from mcp.types import CallToolResult

from ghidra_mcp.contracts.tool_spec import get_tool_spec
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.mcp_server import create_mcp_server


def _runtime_with_dispatcher(dispatcher, *, config: ToolPresentationConfig):
    registry = object()
    runtime = create_mcp_server(
        specs={"decompile_function": get_tool_spec("decompile_function")},
        registry_provider=lambda: registry,
        dispatcher_provider=lambda: dispatcher,
        presentation_config=config,
    )
    return runtime, registry


def test_create_mcp_server_preserves_legacy_dispatcher_signature():
    calls = []

    def legacy_dispatcher(name, args, target, *, registry):
        calls.append((name, args, target, registry))
        return "small result"

    runtime, registry = _runtime_with_dispatcher(
        legacy_dispatcher,
        config=ToolPresentationConfig(
            large_result_threshold_chars=100,
            large_result_preview_chars=50,
        ),
    )

    result = runtime.tools["decompile_function"](name="main", target="fw")

    assert result == "small result"
    assert calls == [
        (
            "decompile_function",
            {"name": "main"},
            "fw",
            registry,
        )
    ]


def test_server_boundary_compacts_legacy_dispatcher_result():
    full_result = (
        "int main(void) {\n"
        + ("  return 0;\n" * 20)
        + "}\n/* "
        + ("x" * 2000)
        + " */\n"
    )

    def legacy_dispatcher(name, args, target, *, registry):  # noqa: ARG001
        return full_result

    runtime, _ = _runtime_with_dispatcher(
        legacy_dispatcher,
        config=ToolPresentationConfig(
            large_result_threshold_chars=40,
            large_result_preview_chars=25,
        ),
    )

    result = runtime.tools["decompile_function"](name="main", target="fw")

    assert isinstance(result, CallToolResult)
    assert result.structuredContent is not None
    result_id = result.structuredContent["result_id"]
    assert runtime.result_store.read_text(result_id) == full_result


def test_create_mcp_server_snapshots_specs_for_tools_and_docs():
    specs = {"decompile_function": get_tool_spec("decompile_function")}
    runtime = create_mcp_server(
        specs=specs,
        registry_provider=object,
        dispatcher_provider=lambda: lambda *_args, **_kwargs: None,
    )

    specs.clear()
    specs["list_functions"] = get_tool_spec("list_functions")

    tools = asyncio.run(runtime.mcp.list_tools())
    docs = json.loads(
        asyncio.run(runtime.mcp.read_resource("ghidra://docs/tools"))[0].content
    )
    assert [tool.name for tool in tools if tool.name not in {"read_result", "search_result"}] == [
        "decompile_function"
    ]
    assert list(runtime.specs) == ["decompile_function"]
    assert [item["name"] for item in docs["tools"]] == ["decompile_function"]


def test_create_mcp_server_rejects_mismatched_spec_mapping_key():
    with pytest.raises(ValueError, match="mapping key must match spec.name"):
        create_mcp_server(
            specs={"wrong_name": get_tool_spec("decompile_function")},
            registry_provider=object,
            dispatcher_provider=lambda: lambda *_args, **_kwargs: None,
        )


def test_create_mcp_server_exposes_read_only_spec_snapshot():
    runtime = create_mcp_server(
        specs={"decompile_function": get_tool_spec("decompile_function")},
        registry_provider=object,
        dispatcher_provider=lambda: lambda *_args, **_kwargs: None,
    )

    with pytest.raises(TypeError):
        runtime.specs["list_functions"] = get_tool_spec("list_functions")  # type: ignore[index]
