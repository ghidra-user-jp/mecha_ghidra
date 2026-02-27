from __future__ import annotations

import pytest
from mcp.types import CallToolResult

from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


class DummyRegistry:
    def __init__(self) -> None:
        self.core_calls = []
        self.registry_calls = []

    def call(self, command, params, target):
        self.core_calls.append((command, dict(params), target))
        if command == "list_functions":
            return [{"name": "main", "entry": "0x401000"}]
        return {"status": "ok"}

    def list_targets(self):
        self.registry_calls.append(("list_targets", {}))
        return []

    def register_target(self, target, **kwargs):
        self.registry_calls.append(("register_target", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}


class DummyCoreExecutor:
    def execute(self, command, params, key):
        return [{"name": command, "entry": key, "params": dict(params)}]


def test_dispatch_tool_raises_for_unknown_spec():
    registry = DummyRegistry()

    with pytest.raises(KeyError, match="未対応のツール仕様"):
        dispatch_tool("unknown_tool", {}, "default", registry=registry)


def test_dispatch_tool_validation_error():
    registry = DummyRegistry()

    with pytest.raises(ValueError, match="入力検証に失敗"):
        dispatch_tool("list_functions", {"offset": "bad"}, "default", registry=registry)


def test_dispatch_tool_validation_error_for_search_query_type():
    registry = DummyRegistry()

    with pytest.raises(ValueError, match="入力検証に失敗"):
        dispatch_tool(
            "search_functions_by_name",
            {"query": 123, "offset": 0, "limit": 5},
            "default",
            registry=registry,
        )


def test_dispatch_tool_validation_error_for_missing_address():
    registry = DummyRegistry()

    with pytest.raises(ValueError, match="入力検証に失敗"):
        dispatch_tool("get_function_by_address", {}, "default", registry=registry)


def test_dispatch_tool_normalizes_empty_list_result():
    registry = DummyRegistry()

    result = dispatch_tool("list_targets", {}, "ignored", registry=registry)

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"


def test_dispatch_tool_routes_target_to_core_command():
    registry = DummyRegistry()

    result = dispatch_tool(
        "list_functions",
        {"offset": 0, "limit": 10},
        "firmware",
        registry=registry,
    )

    assert result == [{"name": "main", "entry": "0x401000"}]
    assert registry.core_calls == [("list_functions", {"offset": 0, "limit": 10}, "firmware")]


def test_dispatch_tool_routes_target_to_registry_method():
    registry = DummyRegistry()

    result = dispatch_tool(
        "register_target",
        {"project_location": "/tmp/sample.gpr", "project_name": "sample"},
        "fw",
        registry=registry,
    )

    assert result == {"status": "ok", "target": "fw"}
    assert registry.registry_calls == [
        (
            "register_target",
            {
                "target": "fw",
                "project_location": "/tmp/sample.gpr",
                "project_name": "sample",
            },
        )
    ]


def test_dispatch_tool_can_fallback_to_core_executor_without_registry_call():
    class RegistryWithoutCoreCall:
        pass

    result = dispatch_tool(
        "list_functions",
        {"offset": 1, "limit": 2},
        "fw",
        registry=RegistryWithoutCoreCall(),
        core_executor=DummyCoreExecutor(),
    )

    assert result == [
        {
            "name": "list_functions",
            "entry": "fw",
            "params": {"offset": 1, "limit": 2},
        }
    ]
