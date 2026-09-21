from __future__ import annotations

import pytest
from mcp.types import CallToolResult

from cli_support import ToolHarness
from ghidra_mcp import cli

# Tool callables bound to a swappable registry (see tests/cli_support.py).
cli_tools = ToolHarness()


@pytest.mark.parametrize(
    ("tool_name", "call", "expected_args"),
    [
        (
            "list_functions",
            lambda: cli_tools.list_functions(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_functions",
            lambda: cli_tools.list_functions(filter="main", only_default_names=True, offset=3, limit=7, target="fw"),
            {"filter": "main", "only_default_names": True, "offset": 3, "limit": 7},
        ),
        (
            "list_namespaces",
            lambda: cli_tools.list_namespaces(classes_only=True, offset=3, limit=7, target="fw"),
            {"classes_only": True, "offset": 3, "limit": 7},
        ),
        (
            "get_function",
            lambda: cli_tools.get_function(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "decompile_function",
            lambda: cli_tools.decompile_function(name="main", target="fw"),
            {"name": "main"},
        ),
        (
            "decompile_function",
            lambda: cli_tools.decompile_function(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "list_segments",
            lambda: cli_tools.list_segments(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_imports",
            lambda: cli_tools.list_imports(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_exports",
            lambda: cli_tools.list_exports(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_namespaces",
            lambda: cli_tools.list_namespaces(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_data_items",
            lambda: cli_tools.list_data_items(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_strings",
            lambda: cli_tools.list_strings(offset=3, limit=7, filter="main", target="fw"),
            {"offset": 3, "limit": 7, "filter": "main"},
        ),
        (
            "get_data_by_label",
            lambda: cli_tools.get_data_by_label(label="main", target="fw"),
            {"label": "main"},
        ),
        (
            "get_bytes",
            lambda: cli_tools.get_bytes(address="0x401000", size=32, target="fw"),
            {"address": "0x401000", "size": 32},
        ),
        (
            "search_bytes",
            lambda: cli_tools.search_bytes(pattern="9090", offset=3, limit=7, target="fw"),
            {"bytes": "9090", "offset": 3, "limit": 7},
        ),
        (
            "list_data_types",
            lambda: cli_tools.list_data_types(offset=1, limit=5, filter="S", category="/c", target="fw"),
            {"offset": 1, "limit": 5, "filter": "S", "category": "/c"},
        ),
        (
            "list_bookmarks",
            lambda: cli_tools.list_bookmarks(
                offset=1, limit=5, address="0x401000", type="Info", category="Analysis", target="fw"
            ),
            {"offset": 1, "limit": 5, "address": "0x401000", "type": "Info", "category": "Analysis"},
        ),
    ],
)
def test_function_listing_slice_uses_dispatcher(monkeypatch, tool_name, call, expected_args):
    called = {}

    def fake_dispatch(spec_name, raw_args, target, *, registry, core_executor=None):
        called["spec_name"] = spec_name
        called["raw_args"] = dict(raw_args)
        called["target"] = target
        called["registry"] = registry
        called["core_executor"] = core_executor
        return {"status": "ok"}

    monkeypatch.setattr(cli, "dispatch_tool", fake_dispatch)

    result = call()

    assert result == {"status": "ok"}
    assert called["spec_name"] == tool_name
    assert called["raw_args"] == expected_args
    assert called["target"] == "fw"
    assert called["registry"] is cli_tools.registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli_tools.list_functions(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_functions(filter="main", offset=0, limit=10, target="fw"),
        lambda: cli_tools.get_function(address="0x401000", target="fw"),
        lambda: cli_tools.decompile_function(name="main", target="fw"),
        lambda: cli_tools.decompile_function(address="0x401000", target="fw"),
        lambda: cli_tools.list_segments(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_imports(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_exports(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_namespaces(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_namespaces(classes_only=True, offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_data_items(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_strings(offset=0, limit=10, filter="main", target="fw"),
        lambda: cli_tools.get_data_by_label(label="main", target="fw"),
        lambda: cli_tools.get_bytes(address="0x401000", size=16, target="fw"),
        lambda: cli_tools.search_bytes(pattern="9090", offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_data_types(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_bookmarks(offset=0, limit=10, target="fw"),
    ],
)
def test_function_listing_slice_empty_result_keeps_compatibility(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            return []

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    result = call()

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli_tools.list_functions(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_namespaces(classes_only=True, offset=0, limit=10, target="fw"),
        lambda: cli_tools.get_function(address="0x401000", target="fw"),
        lambda: cli_tools.decompile_function(name="main", target="fw"),
        lambda: cli_tools.decompile_function(address="0x401000", target="fw"),
        lambda: cli_tools.list_segments(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_imports(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_exports(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_namespaces(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_data_items(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_strings(offset=0, limit=10, filter="main", target="fw"),
        lambda: cli_tools.get_data_by_label(label="main", target="fw"),
        lambda: cli_tools.get_bytes(address="0x401000", size=16, target="fw"),
        lambda: cli_tools.search_bytes(pattern="9090", offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_data_types(offset=0, limit=10, target="fw"),
        lambda: cli_tools.list_bookmarks(offset=0, limit=10, target="fw"),
    ],
)
def test_function_listing_slice_error_message_is_unchanged(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            raise RuntimeError(f"Session '{target}' is not initialized")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Session 'fw' is not initialized"):
        call()
