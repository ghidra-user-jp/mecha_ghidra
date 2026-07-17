from __future__ import annotations

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
