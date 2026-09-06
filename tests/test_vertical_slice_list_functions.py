from __future__ import annotations

import pytest
from mcp.types import CallToolResult

from ghidra_mcp import cli


@pytest.mark.parametrize(
    ("tool_name", "call", "expected_args"),
    [
        (
            "list_functions",
            lambda: cli.list_functions(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_functions",
            lambda: cli.list_functions(filter="main", only_default_names=True, offset=3, limit=7, target="fw"),
            {"filter": "main", "only_default_names": True, "offset": 3, "limit": 7},
        ),
        (
            "list_namespaces",
            lambda: cli.list_namespaces(classes_only=True, offset=3, limit=7, target="fw"),
            {"classes_only": True, "offset": 3, "limit": 7},
        ),
        (
            "get_function",
            lambda: cli.get_function(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "decompile_function",
            lambda: cli.decompile_function(name="main", target="fw"),
            {"name": "main"},
        ),
        (
            "decompile_function",
            lambda: cli.decompile_function(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "disassemble_function",
            lambda: cli.disassemble_function(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "disassemble_range",
            lambda: cli.disassemble_range(
                start_address="0x401000",
                end_address="0x401020",
                limit=8,
                target="fw",
            ),
            {"start_address": "0x401000", "end_address": "0x401020", "limit": 8},
        ),
        (
            "get_callee",
            lambda: cli.get_callee(address="0x401000", target="fw"),
            {"address": "0x401000"},
        ),
        (
            "get_xrefs_to",
            lambda: cli.get_xrefs_to(address="0x401000", offset=3, limit=7, target="fw"),
            {"address": "0x401000", "offset": 3, "limit": 7},
        ),
        (
            "get_xrefs_from",
            lambda: cli.get_xrefs_from(address="0x401000", offset=3, limit=7, target="fw"),
            {"address": "0x401000", "offset": 3, "limit": 7},
        ),
        (
            "get_function_xrefs",
            lambda: cli.get_function_xrefs(name="main", offset=3, limit=7, target="fw"),
            {"name": "main", "offset": 3, "limit": 7},
        ),
        (
            "get_function_xrefs",
            lambda: cli.get_function_xrefs(address="0x401000", offset=3, limit=7, target="fw"),
            {"address": "0x401000", "offset": 3, "limit": 7},
        ),
        (
            "list_segments",
            lambda: cli.list_segments(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_imports",
            lambda: cli.list_imports(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_exports",
            lambda: cli.list_exports(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_namespaces",
            lambda: cli.list_namespaces(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_data_items",
            lambda: cli.list_data_items(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_strings",
            lambda: cli.list_strings(offset=3, limit=7, filter="main", target="fw"),
            {"offset": 3, "limit": 7, "filter": "main"},
        ),
        (
            "get_data_by_label",
            lambda: cli.get_data_by_label(label="main", target="fw"),
            {"label": "main"},
        ),
        (
            "get_bytes",
            lambda: cli.get_bytes(address="0x401000", size=32, target="fw"),
            {"address": "0x401000", "size": 32},
        ),
        (
            "search_bytes",
            lambda: cli.search_bytes(pattern="9090", offset=3, limit=7, target="fw"),
            {"bytes": "9090", "offset": 3, "limit": 7},
        ),
        (
            "get_struct",
            lambda: cli.get_struct(name="S", category="/c", target="fw"),
            {"name": "S", "category": "/c"},
        ),
        (
            "get_enum",
            lambda: cli.get_enum(name="E", category="/c", target="fw"),
            {"name": "E", "category": "/c"},
        ),
        (
            "list_data_types",
            lambda: cli.list_data_types(offset=1, limit=5, filter="S", category="/c", target="fw"),
            {"offset": 1, "limit": 5, "filter": "S", "category": "/c"},
        ),
        (
            "list_bookmarks",
            lambda: cli.list_bookmarks(
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
    assert called["registry"] is cli._registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli.list_functions(offset=0, limit=10, target="fw"),
        lambda: cli.list_functions(filter="main", offset=0, limit=10, target="fw"),
        lambda: cli.get_function(address="0x401000", target="fw"),
        lambda: cli.decompile_function(name="main", target="fw"),
        lambda: cli.decompile_function(address="0x401000", target="fw"),
        lambda: cli.disassemble_function(address="0x401000", target="fw"),
        lambda: cli.disassemble_range(start_address="0x401000", length=16, limit=10, target="fw"),
        lambda: cli.get_callee(address="0x401000", target="fw"),
        lambda: cli.get_xrefs_to(address="0x401000", offset=0, limit=10, target="fw"),
        lambda: cli.get_xrefs_from(address="0x401000", offset=0, limit=10, target="fw"),
        lambda: cli.get_function_xrefs(name="main", offset=0, limit=10, target="fw"),
        lambda: cli.list_segments(offset=0, limit=10, target="fw"),
        lambda: cli.list_imports(offset=0, limit=10, target="fw"),
        lambda: cli.list_exports(offset=0, limit=10, target="fw"),
        lambda: cli.list_namespaces(offset=0, limit=10, target="fw"),
        lambda: cli.list_namespaces(classes_only=True, offset=0, limit=10, target="fw"),
        lambda: cli.list_data_items(offset=0, limit=10, target="fw"),
        lambda: cli.list_strings(offset=0, limit=10, filter="main", target="fw"),
        lambda: cli.get_data_by_label(label="main", target="fw"),
        lambda: cli.get_bytes(address="0x401000", size=16, target="fw"),
        lambda: cli.search_bytes(pattern="9090", offset=0, limit=10, target="fw"),
        lambda: cli.get_struct(name="S", category="/c", target="fw"),
        lambda: cli.get_enum(name="E", category="/c", target="fw"),
        lambda: cli.list_data_types(offset=0, limit=10, target="fw"),
        lambda: cli.list_bookmarks(offset=0, limit=10, target="fw"),
    ],
)
def test_function_listing_slice_empty_result_keeps_compatibility(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            return []

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    result = call()

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli.list_functions(offset=0, limit=10, target="fw"),
        lambda: cli.list_namespaces(classes_only=True, offset=0, limit=10, target="fw"),
        lambda: cli.get_function(address="0x401000", target="fw"),
        lambda: cli.decompile_function(name="main", target="fw"),
        lambda: cli.decompile_function(address="0x401000", target="fw"),
        lambda: cli.disassemble_function(address="0x401000", target="fw"),
        lambda: cli.disassemble_range(start_address="0x401000", length=16, limit=10, target="fw"),
        lambda: cli.get_callee(address="0x401000", target="fw"),
        lambda: cli.get_xrefs_to(address="0x401000", offset=0, limit=10, target="fw"),
        lambda: cli.get_xrefs_from(address="0x401000", offset=0, limit=10, target="fw"),
        lambda: cli.get_function_xrefs(name="main", offset=0, limit=10, target="fw"),
        lambda: cli.list_segments(offset=0, limit=10, target="fw"),
        lambda: cli.list_imports(offset=0, limit=10, target="fw"),
        lambda: cli.list_exports(offset=0, limit=10, target="fw"),
        lambda: cli.list_namespaces(offset=0, limit=10, target="fw"),
        lambda: cli.list_data_items(offset=0, limit=10, target="fw"),
        lambda: cli.list_strings(offset=0, limit=10, filter="main", target="fw"),
        lambda: cli.get_data_by_label(label="main", target="fw"),
        lambda: cli.get_bytes(address="0x401000", size=16, target="fw"),
        lambda: cli.search_bytes(pattern="9090", offset=0, limit=10, target="fw"),
        lambda: cli.get_struct(name="S", category="/c", target="fw"),
        lambda: cli.get_enum(name="E", category="/c", target="fw"),
        lambda: cli.list_data_types(offset=0, limit=10, target="fw"),
        lambda: cli.list_bookmarks(offset=0, limit=10, target="fw"),
    ],
)
def test_function_listing_slice_error_message_is_unchanged(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            raise RuntimeError(f"Session '{target}' is not initialized")

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Session 'fw' is not initialized"):
        call()
