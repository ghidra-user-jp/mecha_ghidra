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
            "list_methods",
            lambda: cli.list_methods(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "list_classes",
            lambda: cli.list_classes(offset=3, limit=7, target="fw"),
            {"offset": 3, "limit": 7},
        ),
        (
            "search_functions_by_name",
            lambda: cli.search_functions_by_name(query="main", offset=3, limit=7, target="fw"),
            {"query": "main", "offset": 3, "limit": 7},
        ),
        (
            "get_function_by_address",
            lambda: cli.get_function_by_address(address="0x401000", target="fw"),
            {"address": "0x401000"},
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
        lambda: cli.list_methods(offset=0, limit=10, target="fw"),
        lambda: cli.list_classes(offset=0, limit=10, target="fw"),
        lambda: cli.search_functions_by_name(query="main", offset=0, limit=10, target="fw"),
        lambda: cli.get_function_by_address(address="0x401000", target="fw"),
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
        lambda: cli.list_methods(offset=0, limit=10, target="fw"),
        lambda: cli.list_classes(offset=0, limit=10, target="fw"),
        lambda: cli.search_functions_by_name(query="main", offset=0, limit=10, target="fw"),
        lambda: cli.get_function_by_address(address="0x401000", target="fw"),
    ],
)
def test_function_listing_slice_error_message_is_unchanged(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            raise RuntimeError(f"セッション '{target}' は初期化されていません")

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="セッション 'fw' は初期化されていません"):
        call()


def test_search_functions_by_name_query_guard_message_is_unchanged():
    with pytest.raises(ValueError, match="queryが必要です"):
        cli.search_functions_by_name(query="", offset=0, limit=10, target="fw")
