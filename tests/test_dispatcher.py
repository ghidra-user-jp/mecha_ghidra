from __future__ import annotations

import pytest
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict

import ghidra_mcp.presentation.tool_dispatcher as tool_dispatcher_module
from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolExposure, ToolSpec
from ghidra_mcp.contracts.tool_models import create_typed_input_model
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

    def list_programs(self, target):
        self.registry_calls.append(("list_programs", {"target": target}))
        return []

    def register_target(self, target, **kwargs):
        self.registry_calls.append(("register_target", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def load_program(self, target, **kwargs):
        self.registry_calls.append(("load_program", {"target": target, **kwargs}))
        return kwargs["domain_path"]

    def import_program(self, target, **kwargs):
        self.registry_calls.append(("import_program", {"target": target, **kwargs}))
        return "/imported.bin"

    def create_session(self, target, **kwargs):
        self.registry_calls.append(("create_session", {"target": target, **kwargs}))
        return object()

    def close_session(self, target, **kwargs):
        self.registry_calls.append(("close_session", {"target": target, **kwargs}))
        return None

    def get_project_sync_status(self, target, **kwargs):
        self.registry_calls.append(("get_project_sync_status", {"target": target, **kwargs}))
        return {"target": target, "program": kwargs.get("domain_path")}

    def checkout_project_program(self, target, **kwargs):
        self.registry_calls.append(("checkout_project_program", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def add_project_program_to_version_control(self, target, **kwargs):
        self.registry_calls.append(("add_project_program_to_version_control", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def commit_project_program(self, target, **kwargs):
        self.registry_calls.append(("commit_project_program", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def pull_project_program(self, target, **kwargs):
        self.registry_calls.append(("pull_project_program", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def undo_checkout_project_program(self, target, **kwargs):
        self.registry_calls.append(("undo_checkout_project_program", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def terminate_project_program_checkout(self, target, **kwargs):
        self.registry_calls.append(("terminate_project_program_checkout", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def reload_project_program(self, target, **kwargs):
        self.registry_calls.append(("reload_project_program", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def get_version_history(self, target, **kwargs):
        self.registry_calls.append(("get_version_history", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}

    def get_version_diff(self, target, **kwargs):
        self.registry_calls.append(("get_version_diff", {"target": target, **kwargs}))
        return {"status": "ok", "target": target}


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
        ("register_target", {"project_name": "sample"}),
        ("load_project_program", {}),
        ("import_program", {}),
        ("create_session", {"project_location": "/tmp/sample.gpr"}),
        ("add_project_program_to_version_control", {"keep_checked_out": False}),
        ("commit_project_program", {"keep_checked_out": False, "auto_checkout": True}),
        ("terminate_project_program_checkout", {"domain_path": "/sample"}),
        ("get_version_diff", {"to_version": 2}),
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
        ("register_target", {"project_location": 1, "project_name": None}),
        ("load_project_program", {"domain_path": 1}),
        ("import_program", {"binary_path": 1}),
        ("create_session", {"project_location": "/tmp/sample.gpr", "domain_path": 1}),
        ("get_project_sync_status", {"domain_path": 1}),
        ("checkout_project_program", {"exclusive": "yes", "domain_path": None}),
        ("add_project_program_to_version_control", {"comment": 1, "keep_checked_out": False}),
        ("commit_project_program", {"message": 1, "keep_checked_out": False, "auto_checkout": True}),
        ("pull_project_program", {"on_local_changes": 1, "domain_path": None}),
        ("undo_checkout_project_program", {"discard_local_changes": "x", "domain_path": None}),
        ("terminate_project_program_checkout", {"checkout_id": "x", "domain_path": None}),
        ("reload_project_program", {"domain_path": 1}),
        ("get_version_history", {"limit": "x", "domain_path": None}),
        ("get_version_diff", {"from_version": "x", "to_version": 2, "range_limit": 1}),
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


def test_dispatch_tool_applies_status_program_result_adapter():
    registry = DummyRegistry()

    result = dispatch_tool(
        "load_project_program",
        {"domain_path": "/folder/app"},
        "fw",
        registry=registry,
    )

    assert result == {"status": "ok", "target": "fw", "program": "/folder/app"}


def test_dispatch_tool_applies_status_target_result_adapter():
    registry = DummyRegistry()

    result = dispatch_tool(
        "create_session",
        {"project_location": "/tmp/sample.gpr", "domain_path": "/folder/app"},
        "fw",
        registry=registry,
    )

    assert result == {"status": "ok", "target": "fw"}


def test_dispatch_tool_applies_error_adapter_for_create_session():
    class FailingRegistry(DummyRegistry):
        def create_session(self, target, **kwargs):  # noqa: ARG002
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="セッション 'fw' の作成に失敗しました: boom"):
        dispatch_tool(
            "create_session",
            {"project_location": "/tmp/sample.gpr", "domain_path": "/folder/app"},
            "fw",
            registry=FailingRegistry(),
        )


def test_dispatch_tool_applies_error_adapter_for_close_session():
    class FailingRegistry(DummyRegistry):
        def close_session(self, target, **kwargs):  # noqa: ARG002
            raise RuntimeError("close boom")

    with pytest.raises(RuntimeError, match="セッション 'fw' のクローズに失敗しました: close boom"):
        dispatch_tool(
            "close_session",
            {},
            "fw",
            registry=FailingRegistry(),
        )


def test_dispatch_tool_applies_error_adapter_for_close_remove():
    class FailingRegistry(DummyRegistry):
        def close_session(self, target, **kwargs):  # noqa: ARG002
            assert kwargs == {"remove_program": True}
            raise RuntimeError("remove boom")

    with pytest.raises(RuntimeError, match="セッション 'fw' のクローズ/削除に失敗しました: remove boom"):
        dispatch_tool(
            "close_session_and_remove_program",
            {},
            "fw",
            registry=FailingRegistry(),
        )


def test_dispatch_tool_raises_when_registry_has_no_core_call():
    class RegistryWithoutCoreCall:
        pass

    with pytest.raises(RuntimeError, match="CORE_EXECUTOR_UNAVAILABLE"):
        dispatch_tool(
            "list_functions",
            {"offset": 1, "limit": 2},
            "fw",
            registry=RegistryWithoutCoreCall(),
        )


def test_dispatch_tool_validates_output_before_result_adapter(monkeypatch):
    class OutputMustBeDict(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)
        payload: dict[str, str]

    class Registry:
        def load_program(self, target, **kwargs):  # noqa: ARG002
            return "/folder/app"

    spec = ToolSpec(
        name="dummy_load",
        exposure=ToolExposure.ALWAYS,
        executor_kind=ExecutorKind.REGISTRY_METHOD,
        command_or_method="load_program",
        input_model=create_typed_input_model("DummyInput", {"domain_path": (str, ...)}),
        output_model=OutputMustBeDict,
        include_target=True,
        result_adapter="status_program_ok",
    )

    monkeypatch.setattr(tool_dispatcher_module, "get_tool_spec", lambda _name: spec)

    with pytest.raises(ValueError, match="dummy_load の出力検証に失敗"):
        tool_dispatcher_module.dispatch_tool(
            "dummy_load",
            {"domain_path": "/folder/app"},
            "fw",
            registry=Registry(),
        )
