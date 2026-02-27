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


@pytest.mark.parametrize(
    ("spec_name", "raw_args"),
    [
        ("search_functions_by_name", {"offset": 0, "limit": 5}),
        ("get_function_by_address", {}),
        ("decompile_function", {}),
        ("decompile_function_by_address", {}),
        ("disassemble_function", {}),
        ("get_callee", {}),
        ("get_xrefs_to", {"offset": 0, "limit": 10}),
        ("get_xrefs_from", {"offset": 0, "limit": 10}),
        ("get_function_xrefs", {"offset": 0, "limit": 10}),
        ("get_data_by_label", {}),
        ("get_bytes", {"size": 8}),
        ("search_bytes", {"offset": 0, "limit": 10}),
        ("get_struct", {}),
        ("get_enum", {}),
        ("rename_function", {"oldName": "old_only"}),
        ("rename_function_by_address", {"function_address": "0x1"}),
        ("rename_data", {"address": "0x1"}),
        ("rename_variable", {"functionName": "main", "oldName": "old"}),
        ("set_decompiler_comment", {"address": "0x1"}),
        ("set_disassembly_comment", {"address": "0x1"}),
        ("set_function_prototype", {"function_address": "0x1"}),
        ("set_local_variable_type", {"function_address": "0x1", "variable_name": "v"}),
        ("create_struct", {}),
        ("add_struct_members", {"struct_name": "S"}),
        ("clear_struct", {}),
        ("create_enum", {}),
        ("add_enum_values", {"enum_name": "E"}),
        ("remove_enum_values", {"enum_name": "E"}),
        ("create_class", {}),
        ("add_class_members", {"class_name": "C"}),
        ("remove_class_members", {"class_name": "C"}),
        ("remove_struct_members", {"struct_name": "S"}),
        ("set_global_data_type", {"address": "0x1"}),
        ("set_bytes", {"address": "0x1"}),
        ("add_bookmark", {"address": "0x1", "category": "cat", "comment": "memo"}),
    ],
)
def test_dispatch_tool_validation_error_for_missing_required_fields(spec_name, raw_args):
    registry = DummyRegistry()

    with pytest.raises(ValueError, match="入力検証に失敗"):
        dispatch_tool(spec_name, raw_args, "default", registry=registry)


@pytest.mark.parametrize(
    ("spec_name", "raw_args"),
    [
        ("search_functions_by_name", {"query": 123, "offset": 0, "limit": 5}),
        ("get_function_by_address", {"address": 123}),
        ("decompile_function", {"name": 123}),
        ("decompile_function_by_address", {"address": 123}),
        ("disassemble_function", {"address": 123}),
        ("get_callee", {"address": 123}),
        ("get_xrefs_to", {"address": "0x1", "offset": "x", "limit": 10}),
        ("get_xrefs_from", {"address": "0x1", "offset": 0, "limit": "x"}),
        ("get_function_xrefs", {"name": "main", "offset": "x", "limit": 10}),
        ("list_segments", {"offset": "x", "limit": 10}),
        ("list_imports", {"offset": 0, "limit": "x"}),
        ("list_exports", {"offset": "x", "limit": 10}),
        ("list_namespaces", {"offset": 0, "limit": "x"}),
        ("list_data_items", {"offset": "x", "limit": 10}),
        ("list_strings", {"offset": 0, "limit": "x", "filter": None}),
        ("get_data_by_label", {"label": 123}),
        ("get_bytes", {"address": "0x1", "size": "x"}),
        ("search_bytes", {"bytes": 123, "offset": 0, "limit": 10}),
        ("get_struct", {"name": 123, "category": None}),
        ("get_enum", {"name": 123, "category": None}),
        ("rename_function", {"oldName": "old", "newName": 1}),
        ("rename_function_by_address", {"function_address": 1, "new_name": "new"}),
        ("rename_data", {"address": 1, "newName": "new"}),
        ("rename_variable", {"functionName": "main", "oldName": "old", "newName": 1}),
        ("set_decompiler_comment", {"address": "0x1", "comment": 1}),
        ("set_disassembly_comment", {"address": "0x1", "comment": 1}),
        ("set_function_prototype", {"function_address": "0x1", "prototype": 1}),
        ("set_local_variable_type", {"function_address": "0x1", "variable_name": "v", "new_type": 1}),
        ("create_struct", {"name": "S", "size": "x"}),
        ("add_struct_members", {"struct_name": "S", "members": "bad"}),
        ("clear_struct", {"struct_name": 1}),
        ("create_enum", {"name": "E", "values": "bad"}),
        ("add_enum_values", {"enum_name": "E", "values": "bad"}),
        ("remove_enum_values", {"enum_name": "E", "values": "bad"}),
        ("create_class", {"name": "C", "members": "bad"}),
        ("add_class_members", {"class_name": "C", "members": "bad"}),
        ("remove_class_members", {"class_name": "C", "members": "bad"}),
        ("remove_struct_members", {"struct_name": "S", "members": "bad"}),
        ("set_global_data_type", {"address": "0x1", "data_type": "int", "length": "x"}),
        ("set_bytes", {"address": "0x1", "bytes": 1}),
        ("add_bookmark", {"address": "0x1", "category": "cat", "comment": "memo", "type": 1}),
    ],
)
def test_dispatch_tool_validation_error_for_type_mismatch(spec_name, raw_args):
    registry = DummyRegistry()

    with pytest.raises(ValueError, match="入力検証に失敗"):
        dispatch_tool(spec_name, raw_args, "default", registry=registry)


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
