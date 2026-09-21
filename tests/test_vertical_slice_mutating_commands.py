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
            "set_function_prototype",
            lambda: cli_tools.set_function_prototype(function_name="main", prototype="int main(void)", target="fw"),
            {"function_name": "main", "prototype": "int main(void)"},
        ),
        (
            "set_function_prototype",
            lambda: cli_tools.set_function_prototype(
                function_address="0x401000",
                prototype="int main(void)",
                target="fw",
            ),
            {"function_address": "0x401000", "prototype": "int main(void)"},
        ),
        (
            "set_local_variable_type",
            lambda: cli_tools.set_local_variable_type(
                function_address="0x401000",
                variable_name="param_1",
                new_type="int",
                target="fw",
            ),
            {"function_address": "0x401000", "variable_name": "param_1", "new_type": "int"},
        ),
        (
            "create_function",
            lambda: cli_tools.create_function(address="0x401100", name="manual_fn", target="fw"),
            {"address": "0x401100", "name": "manual_fn"},
        ),
        (
            "delete_function",
            lambda: cli_tools.delete_function(address="0x401100", target="fw"),
            {"address": "0x401100"},
        ),
        (
            "analyze_program",
            lambda: cli_tools.analyze_program(target="fw"),
            {},
        ),
        (
            "analyze_program",
            lambda: cli_tools.analyze_program(force=True, target="fw"),
            {"force": True},
        ),
        (
            "create_struct",
            lambda: cli_tools.create_struct(
                name="S",
                category="/types",
                size=4,
                members=[{"name": "a", "type": "int"}],
                target="fw",
            ),
            {
                "name": "S",
                "size": 4,
                "category": "/types",
                "members": [{"name": "a", "type": "int"}],
            },
        ),
        (
            "add_struct_members",
            lambda: cli_tools.add_struct_members(
                struct_name="S",
                members=[{"name": "b", "type": "char"}],
                category="/types",
                target="fw",
            ),
            {
                "struct_name": "S",
                "members": [{"name": "b", "type": "char"}],
                "category": "/types",
            },
        ),
        (
            "remove_struct_members",
            lambda: cli_tools.remove_struct_members(struct_name="S", clear_all=True, category="/types", target="fw"),
            {"struct_name": "S", "clear_all": True, "category": "/types"},
        ),
        (
            "delete_data_type",
            lambda: cli_tools.delete_data_type(name="S", category="/types", target="fw"),
            {"name": "S", "category": "/types"},
        ),
        (
            "rename_data_type",
            lambda: cli_tools.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
            {"name": "OldType", "new_name": "NewType", "category": "/types"},
        ),
        (
            "remove_struct_members",
            lambda: cli_tools.remove_struct_members(
                struct_name="S",
                members=["b"],
                category="/types",
                target="fw",
            ),
            {"struct_name": "S", "members": ["b"], "clear_all": False, "category": "/types"},
        ),
        (
            "set_global_data_type",
            lambda: cli_tools.set_global_data_type(
                address="0x403000",
                data_type="int",
                length=4,
                clear_mode="CLEAR_ALL_DEFAULT_CONFLICT_DATA",
                target="fw",
            ),
            {
                "address": "0x403000",
                "data_type": "int",
                "length": 4,
                "clear_mode": "CLEAR_ALL_DEFAULT_CONFLICT_DATA",
            },
        ),
        (
            "set_bytes",
            lambda: cli_tools.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
            {"address": "0x401000", "bytes": "90"},
        ),
        (
            "add_bookmark",
            lambda: cli_tools.add_bookmark(
                address="0x401000",
                category="Analysis",
                comment="note",
                type="Info",
                target="fw",
            ),
            {
                "address": "0x401000",
                "category": "Analysis",
                "comment": "note",
                "type": "Info",
            },
        ),
        (
            "delete_bookmark",
            lambda: cli_tools.delete_bookmark(
                address="0x401000",
                category="Analysis",
                comment="note",
                type="Info",
                target="fw",
            ),
            {
                "address": "0x401000",
                "category": "Analysis",
                "comment": "note",
                "type": "Info",
            },
        ),
    ],
)
def test_mutating_slice_uses_dispatcher(monkeypatch, tool_name, call, expected_args):
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
        lambda: cli_tools.set_function_prototype(function_address="0x401000", prototype="int main(void)", target="fw"),
        lambda: cli_tools.set_local_variable_type(
            function_address="0x401000", variable_name="param_1", new_type="int", target="fw"
        ),
        lambda: cli_tools.create_function(address="0x401100", name="manual_fn", target="fw"),
        lambda: cli_tools.delete_function(address="0x401100", target="fw"),
        lambda: cli_tools.analyze_program(target="fw"),
        lambda: cli_tools.analyze_program(force=True, target="fw"),
        lambda: cli_tools.create_struct(
            name="S", category="/types", size=4, members=[{"name": "a", "type": "int"}], target="fw"
        ),
        lambda: cli_tools.add_struct_members(
            struct_name="S", members=[{"name": "b", "type": "char"}], category="/types", target="fw"
        ),
        lambda: cli_tools.remove_struct_members(struct_name="S", category="/types", target="fw"),
        lambda: cli_tools.delete_data_type(name="S", category="/types", target="fw"),
        lambda: cli_tools.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
        lambda: cli_tools.remove_struct_members(struct_name="S", members=["b"], category="/types", target="fw"),
        lambda: cli_tools.set_global_data_type(
            address="0x403000",
            data_type="int",
            length=4,
            clear_mode="CLEAR_ALL_DEFAULT_CONFLICT_DATA",
            target="fw",
        ),
        lambda: cli_tools.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
        lambda: cli_tools.add_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            target="fw",
        ),
        lambda: cli_tools.delete_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            target="fw",
        ),
    ],
)
def test_mutating_slice_empty_result_keeps_compatibility(monkeypatch, call):
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
        lambda: cli_tools.set_function_prototype(function_address="0x401000", prototype="int main(void)", target="fw"),
        lambda: cli_tools.set_local_variable_type(
            function_address="0x401000", variable_name="param_1", new_type="int", target="fw"
        ),
        lambda: cli_tools.create_function(address="0x401100", name="manual_fn", target="fw"),
        lambda: cli_tools.delete_function(address="0x401100", target="fw"),
        lambda: cli_tools.analyze_program(target="fw"),
        lambda: cli_tools.analyze_program(force=True, target="fw"),
        lambda: cli_tools.create_struct(
            name="S", category="/types", size=4, members=[{"name": "a", "type": "int"}], target="fw"
        ),
        lambda: cli_tools.add_struct_members(
            struct_name="S", members=[{"name": "b", "type": "char"}], category="/types", target="fw"
        ),
        lambda: cli_tools.remove_struct_members(struct_name="S", category="/types", target="fw"),
        lambda: cli_tools.delete_data_type(name="S", category="/types", target="fw"),
        lambda: cli_tools.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
        lambda: cli_tools.remove_struct_members(struct_name="S", members=["b"], category="/types", target="fw"),
        lambda: cli_tools.set_global_data_type(
            address="0x403000",
            data_type="int",
            length=4,
            clear_mode="CLEAR_ALL_DEFAULT_CONFLICT_DATA",
            target="fw",
        ),
        lambda: cli_tools.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
        lambda: cli_tools.add_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            target="fw",
        ),
        lambda: cli_tools.delete_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            target="fw",
        ),
    ],
)
def test_mutating_slice_error_message_is_unchanged(monkeypatch, call):
    class DummyRegistry:
        def call(self, command, params, target):
            raise RuntimeError(f"Session '{target}' is not initialized")

    monkeypatch.setattr(cli_tools, "registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Session 'fw' is not initialized"):
        call()
