from __future__ import annotations

import types
from typing import Any, get_args, get_origin

import pytest

from ghidra_mcp import cli
from ghidra_mcp.application.usecases.datatypes import DATATYPE_COMMANDS
from ghidra_mcp.application.usecases.functions import FUNCTION_COMMANDS
from ghidra_mcp.application.usecases.memory import MEMORY_COMMANDS
from ghidra_mcp.application.usecases.symbols import SYMBOL_COMMANDS
from ghidra_mcp.contracts.tool_spec import ExecutorKind, get_all_tool_specs, get_tool_spec
from ghidra_mcp.presentation.tool_dispatcher import dispatch_tool


_LIST_CORE_COMMANDS = {
    "list_methods",
    "list_functions",
    "list_classes",
    "search_functions_by_name",
    "disassemble_function",
    "get_callee",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_function_xrefs",
    "list_segments",
    "list_imports",
    "list_exports",
    "list_namespaces",
    "list_data_items",
    "list_strings",
    "get_data_by_label",
    "search_bytes",
}
_CORE_COMMANDS = set(FUNCTION_COMMANDS) | set(MEMORY_COMMANDS) | set(SYMBOL_COMMANDS) | set(DATATYPE_COMMANDS)


class RecordingCoreService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    def call(self, command: str, params: dict[str, Any], target: str):
        self.calls.append((command, dict(params), target))
        if command in _LIST_CORE_COMMANDS:
            return []
        if command in {"decompile_function", "decompile_function_by_address"}:
            return "void main(void) {}"
        if command == "get_bytes":
            return "90"
        if command in _CORE_COMMANDS:
            return {"command": command, "target": target}
        return {"command": command, "target": target}


class RecordingService:
    def __init__(self, label: str) -> None:
        self.label = label
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str):
        def _method(*args: Any, **kwargs: Any):
            self.calls.append((name, args, dict(kwargs)))
            if name in {"list_targets", "list_programs"}:
                return []
            if name in {"load_program", "import_program"}:
                return "/program"
            if name == "create_session":
                target = args[0]
                project_location = args[1]
                return {
                    "target": target,
                    "project_location": project_location,
                    "project_name": kwargs.get("project_name"),
                    "domain_path": kwargs.get("domain_path"),
                }
            if name == "close_session":
                target = args[0]
                return {
                    "closed": True,
                    "target": target,
                    "remove_program": bool(kwargs.get("remove_program", False)),
                }
            return {"service": self.label, "method": name}

        return _method


def _sample_for_field(name: str, annotation: Any) -> Any:
    origin = get_origin(annotation)

    if origin in {list, tuple, set}:
        inner = get_args(annotation)[0] if get_args(annotation) else Any
        if inner is str:
            return ["item"]
        inner_origin = get_origin(inner)
        if inner is dict or inner_origin is dict:
            return [{"name": "field", "type": "int"}]
        return [_sample_for_field(name, inner)]

    if origin is dict:
        return {"name": "field", "type": "int"}

    union_args = [arg for arg in get_args(annotation) if arg is not type(None)]  # noqa: E721
    if union_args:
        return _sample_for_field(name, union_args[0])

    if annotation is bool:
        return True
    if annotation is int:
        if name == "from_version":
            return 1
        if name == "to_version":
            return 2
        if name == "checkout_id":
            return 7
        return 3

    if annotation is str:
        if name in {"address", "function_address"}:
            return "0x401000"
        if name == "project_location":
            return "/tmp/sample.gpr"
        if name == "domain_path":
            return "/main"
        if name == "binary_path":
            return "/tmp/sample.exe"
        if name == "on_local_changes":
            return "abort"
        if name == "clear_mode":
            return "clear_all_default_conflicts"
        if name in {"data_type", "new_type"}:
            return "int"
        if name in {"type"}:
            return "Info"
        if name in {"format"}:
            return "json"
        if name in {"bytes"}:
            return "90"
        if name in {"message", "comment"}:
            return "msg"
        return "value"

    if annotation is dict:
        return {"key": "value"}

    return "value"


def _required_raw_args(spec_name: str) -> dict[str, Any]:
    spec = get_tool_spec(spec_name)
    raw: dict[str, Any] = {}
    for key, field in spec.input_model.model_fields.items():
        if field.is_required():
            raw[key] = _sample_for_field(key, field.annotation)
    return raw


@pytest.mark.parametrize("tool_name", sorted(get_all_tool_specs(include_shared_sync=True).keys()))
def test_service_registry_adapter_routes_all_tools(tool_name: str):
    spec = get_tool_spec(tool_name)
    target_name = "fw"
    raw_args = _required_raw_args(tool_name)

    core = RecordingCoreService()
    target = RecordingService("target")
    sync = RecordingService("sync")
    adapter = cli.ServiceRegistryAdapter(
        core_command_service=core,
        target_service=target,
        sync_service=sync,
    )

    dispatch_tool(tool_name, raw_args, target_name, registry=adapter)

    validated = spec.input_model.model_validate(raw_args).model_dump(exclude_none=True)

    if spec.executor_kind == ExecutorKind.CORE_COMMAND:
        assert core.calls == [(spec.command_or_method, validated, target_name)]
        assert target.calls == []
        assert sync.calls == []
        return

    expected_kwargs = {**validated, **spec.static_kwargs}

    if spec.executor_kind == ExecutorKind.REGISTRY_METHOD:
        assert core.calls == []
        assert sync.calls == []
        assert len(target.calls) == 1
        method_name, args, kwargs = target.calls[0]
        assert method_name == spec.command_or_method
        if spec.include_target:
            assert args
            assert args[0] == target_name
        else:
            assert args == ()
        for key, value in expected_kwargs.items():
            if key in kwargs:
                assert kwargs[key] == value
            else:
                assert value in args
        return

    assert spec.executor_kind == ExecutorKind.SHARED_SYNC_METHOD
    assert core.calls == []
    assert target.calls == []
    assert len(sync.calls) == 1
    method_name, args, kwargs = sync.calls[0]
    assert method_name == spec.command_or_method
    assert args
    assert args[0] == target_name
    for key, value in expected_kwargs.items():
        if key in kwargs:
            assert kwargs[key] == value
        else:
            assert value in args


def test_service_registry_adapter_create_session_requires_domain_path():
    core = RecordingCoreService()
    target = RecordingService("target")
    sync = RecordingService("sync")
    adapter = cli.ServiceRegistryAdapter(
        core_command_service=core,
        target_service=target,
        sync_service=sync,
    )

    with pytest.raises(ValueError, match="domain_path を指定してください"):
        adapter.create_session("fw", "/tmp/sample.gpr", project_name="sample")


def test_service_registry_adapter_forwards_close_remove_flag():
    core = RecordingCoreService()
    target = RecordingService("target")
    sync = RecordingService("sync")
    adapter = cli.ServiceRegistryAdapter(
        core_command_service=core,
        target_service=target,
        sync_service=sync,
    )

    dispatch_tool("close_session_and_remove_program", {}, "fw", registry=adapter)

    assert target.calls == [("close_session", ("fw",), {"remove_program": True})]


def test_service_registry_adapter_passes_domain_path_none_for_shared_sync_defaults():
    core = RecordingCoreService()
    target = RecordingService("target")
    sync = RecordingService("sync")
    adapter = cli.ServiceRegistryAdapter(
        core_command_service=core,
        target_service=target,
        sync_service=sync,
    )

    dispatch_tool("get_project_sync_status", {}, "fw", registry=adapter)

    assert sync.calls == [("get_project_sync_status", ("fw",), {"domain_path": None})]
