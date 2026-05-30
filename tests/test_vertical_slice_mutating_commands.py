from __future__ import annotations

import pytest
from mcp.types import CallToolResult

from ghidra_mcp import cli


@pytest.mark.parametrize(
    ("tool_name", "call", "expected_args"),
    [
        (
            "rename_function",
            lambda: cli.rename_function(old_name="old_fn", new_name="new_fn", target="fw"),
            {"oldName": "old_fn", "newName": "new_fn"},
        ),
        (
            "rename_function_by_address",
            lambda: cli.rename_function_by_address(
                function_address="0x401000",
                new_name="new_fn",
                target="fw",
            ),
            {"function_address": "0x401000", "new_name": "new_fn"},
        ),
        (
            "rename_data",
            lambda: cli.rename_data(address="0x402000", new_name="new_data", target="fw"),
            {"address": "0x402000", "newName": "new_data"},
        ),
        (
            "rename_variable",
            lambda: cli.rename_variable(
                function_name="main",
                old_name="old_var",
                new_name="new_var",
                target="fw",
            ),
            {"functionName": "main", "oldName": "old_var", "newName": "new_var"},
        ),
        (
            "set_decompiler_comment",
            lambda: cli.set_decompiler_comment(address="0x401000", comment="memo", target="fw"),
            {"address": "0x401000", "comment": "memo"},
        ),
        (
            "set_disassembly_comment",
            lambda: cli.set_disassembly_comment(address="0x401000", comment="memo", target="fw"),
            {"address": "0x401000", "comment": "memo"},
        ),
        (
            "set_function_prototype",
            lambda: cli.set_function_prototype(
                function_address="0x401000",
                prototype="int main(void)",
                target="fw",
            ),
            {"function_address": "0x401000", "prototype": "int main(void)"},
        ),
        (
            "set_local_variable_type",
            lambda: cli.set_local_variable_type(
                function_address="0x401000",
                variable_name="param_1",
                new_type="int",
                target="fw",
            ),
            {"function_address": "0x401000", "variable_name": "param_1", "new_type": "int"},
        ),
        (
            "create_function",
            lambda: cli.create_function(address="0x401100", name="manual_fn", target="fw"),
            {"address": "0x401100", "name": "manual_fn"},
        ),
        (
            "delete_function",
            lambda: cli.delete_function(address="0x401100", target="fw"),
            {"address": "0x401100"},
        ),
        (
            "analyze_program",
            lambda: cli.analyze_program(target="fw"),
            {},
        ),
        (
            "reanalyze_program",
            lambda: cli.reanalyze_program(target="fw"),
            {},
        ),
        (
            "create_struct",
            lambda: cli.create_struct(
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
            lambda: cli.add_struct_members(
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
            "clear_struct",
            lambda: cli.clear_struct(struct_name="S", category="/types", target="fw"),
            {"struct_name": "S", "category": "/types"},
        ),
        (
            "delete_struct",
            lambda: cli.delete_struct(struct_name="S", category="/types", target="fw"),
            {"struct_name": "S", "category": "/types"},
        ),
        (
            "rename_data_type",
            lambda: cli.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
            {"name": "OldType", "new_name": "NewType", "category": "/types"},
        ),
        (
            "remove_struct_members",
            lambda: cli.remove_struct_members(
                struct_name="S",
                members=["b"],
                category="/types",
                target="fw",
            ),
            {"struct_name": "S", "members": ["b"], "category": "/types"},
        ),
        (
            "set_global_data_type",
            lambda: cli.set_global_data_type(
                address="0x403000",
                data_type="int",
                length=4,
                clear_mode="clear_all_default_conflicts",
                target="fw",
            ),
            {
                "address": "0x403000",
                "data_type": "int",
                "length": 4,
                "clear_mode": "clear_all_default_conflicts",
            },
        ),
        (
            "set_bytes",
            lambda: cli.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
            {"address": "0x401000", "bytes": "90"},
        ),
        (
            "add_bookmark",
            lambda: cli.add_bookmark(
                address="0x401000",
                category="Analysis",
                comment="note",
                type="Info",
                format="json",
                target="fw",
            ),
            {
                "address": "0x401000",
                "category": "Analysis",
                "comment": "note",
                "type": "Info",
                "format": "json",
            },
        ),
        (
            "delete_bookmark",
            lambda: cli.delete_bookmark(
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
    assert called["registry"] is cli._registry
    assert called["core_executor"] is None


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli.rename_function(old_name="old_fn", new_name="new_fn", target="fw"),
        lambda: cli.rename_function_by_address(function_address="0x401000", new_name="new_fn", target="fw"),
        lambda: cli.rename_data(address="0x402000", new_name="new_data", target="fw"),
        lambda: cli.rename_variable(function_name="main", old_name="old_var", new_name="new_var", target="fw"),
        lambda: cli.set_decompiler_comment(address="0x401000", comment="memo", target="fw"),
        lambda: cli.set_disassembly_comment(address="0x401000", comment="memo", target="fw"),
        lambda: cli.set_function_prototype(function_address="0x401000", prototype="int main(void)", target="fw"),
        lambda: cli.set_local_variable_type(
            function_address="0x401000", variable_name="param_1", new_type="int", target="fw"
        ),
        lambda: cli.create_function(address="0x401100", name="manual_fn", target="fw"),
        lambda: cli.delete_function(address="0x401100", target="fw"),
        lambda: cli.analyze_program(target="fw"),
        lambda: cli.reanalyze_program(target="fw"),
        lambda: cli.create_struct(name="S", category="/types", size=4, members=[{"name": "a", "type": "int"}], target="fw"),
        lambda: cli.add_struct_members(struct_name="S", members=[{"name": "b", "type": "char"}], category="/types", target="fw"),
        lambda: cli.clear_struct(struct_name="S", category="/types", target="fw"),
        lambda: cli.delete_struct(struct_name="S", category="/types", target="fw"),
        lambda: cli.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
        lambda: cli.remove_struct_members(struct_name="S", members=["b"], category="/types", target="fw"),
        lambda: cli.set_global_data_type(
            address="0x403000",
            data_type="int",
            length=4,
            clear_mode="clear_all_default_conflicts",
            target="fw",
        ),
        lambda: cli.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
        lambda: cli.add_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            format="json",
            target="fw",
        ),
        lambda: cli.delete_bookmark(
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

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    result = call()

    assert isinstance(result, CallToolResult)
    assert result.content[0].text == "[]"


@pytest.mark.parametrize(
    "call",
    [
        lambda: cli.rename_function(old_name="old_fn", new_name="new_fn", target="fw"),
        lambda: cli.rename_function_by_address(function_address="0x401000", new_name="new_fn", target="fw"),
        lambda: cli.rename_data(address="0x402000", new_name="new_data", target="fw"),
        lambda: cli.rename_variable(function_name="main", old_name="old_var", new_name="new_var", target="fw"),
        lambda: cli.set_decompiler_comment(address="0x401000", comment="memo", target="fw"),
        lambda: cli.set_disassembly_comment(address="0x401000", comment="memo", target="fw"),
        lambda: cli.set_function_prototype(function_address="0x401000", prototype="int main(void)", target="fw"),
        lambda: cli.set_local_variable_type(
            function_address="0x401000", variable_name="param_1", new_type="int", target="fw"
        ),
        lambda: cli.create_function(address="0x401100", name="manual_fn", target="fw"),
        lambda: cli.delete_function(address="0x401100", target="fw"),
        lambda: cli.analyze_program(target="fw"),
        lambda: cli.reanalyze_program(target="fw"),
        lambda: cli.create_struct(name="S", category="/types", size=4, members=[{"name": "a", "type": "int"}], target="fw"),
        lambda: cli.add_struct_members(struct_name="S", members=[{"name": "b", "type": "char"}], category="/types", target="fw"),
        lambda: cli.clear_struct(struct_name="S", category="/types", target="fw"),
        lambda: cli.delete_struct(struct_name="S", category="/types", target="fw"),
        lambda: cli.rename_data_type(name="OldType", new_name="NewType", category="/types", target="fw"),
        lambda: cli.remove_struct_members(struct_name="S", members=["b"], category="/types", target="fw"),
        lambda: cli.set_global_data_type(
            address="0x403000",
            data_type="int",
            length=4,
            clear_mode="clear_all_default_conflicts",
            target="fw",
        ),
        lambda: cli.set_bytes(address="0x401000", bytes_hex="90", target="fw"),
        lambda: cli.add_bookmark(
            address="0x401000",
            category="Analysis",
            comment="note",
            type="Info",
            format="json",
            target="fw",
        ),
        lambda: cli.delete_bookmark(
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

    monkeypatch.setattr(cli, "_registry", DummyRegistry())

    with pytest.raises(RuntimeError, match="Session 'fw' is not initialized"):
        call()
