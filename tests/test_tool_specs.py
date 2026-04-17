from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import ghidra_mcp.contracts.tool_models as tool_models
from ghidra_mcp.contracts.tool_spec import ExecutorKind, ToolExposure, get_all_tool_specs
from ghidra_headless.handlers.core_command_registry import COMMAND_DEP_KEYS, COMMAND_NAMES
from ghidra_mcp.presentation import cli as presentation_cli
from ghidra_mcp.presentation.tool_registry import build_tool_functions, register_shared_sync_tools

ROOT = Path(__file__).resolve().parents[1]
TOOL_SPEC_PATH = ROOT / "src" / "ghidra_mcp" / "contracts" / "tool_spec.py"


def test_tool_specs_cover_all_public_tools():
    specs = get_all_tool_specs(include_shared_sync=True)
    assert set(specs) == set(presentation_cli.PUBLIC_TOOL_FUNCTIONS)


def test_core_command_spec_keys_are_consumed_by_handlers():
    supported = set(COMMAND_NAMES)
    dep_keys_by_command = {name: set(keys) for name, keys in COMMAND_DEP_KEYS.items()}

    specs = get_all_tool_specs(include_shared_sync=True)
    mismatches: list[str] = []

    for spec in specs.values():
        if spec.executor_kind != ExecutorKind.CORE_COMMAND:
            continue
        command = spec.command_or_method
        assert command in supported
        expected_keys = dep_keys_by_command.get(command, set())
        unknown_keys = sorted(
            key for key in spec.input_model.model_fields.keys() if key not in expected_keys
        )
        if unknown_keys:
            mismatches.append(f"{command} has unused keys: {', '.join(unknown_keys)}")

    assert not mismatches, "\n".join(mismatches)


def test_shared_sync_specs_are_gated_by_exposure():
    specs = get_all_tool_specs(include_shared_sync=True)
    shared_sync_names = {
        name
        for name, spec in specs.items()
        if spec.exposure == ToolExposure.SHARED_SYNC
    }

    assert shared_sync_names == {
        "get_project_sync_status",
        "get_version_history",
        "get_version_diff",
        "checkout_project_program",
        "add_project_program_to_version_control",
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "reload_project_program",
    }


def test_shared_sync_specs_match_registration_function():
    specs = get_all_tool_specs(include_shared_sync=True)
    tools = build_tool_functions(
        specs=specs,
        dispatcher_provider=lambda: presentation_cli.dispatch_tool,
        registry_provider=lambda: presentation_cli._registry,
    )

    registered: list[str] = []

    class DummyMCP:
        def add_tool(self, fn, description=None):  # noqa: ARG002
            registered.append(fn.__name__)

    register_shared_sync_tools(DummyMCP(), tools=tools)

    shared_sync_names = [name for name, spec in specs.items() if spec.exposure == ToolExposure.SHARED_SYNC]
    assert registered == shared_sync_names


def test_typed_input_models_for_function_listing_slice():
    specs = get_all_tool_specs(include_shared_sync=True)

    def _assert_fields(tool_name: str, expected_fields: dict[str, tuple[type, object]]):
        model = specs[tool_name].input_model
        fields = model.model_fields
        assert set(fields.keys()) == set(expected_fields.keys())
        for key, (expected_type, expected_default) in expected_fields.items():
            assert fields[key].annotation == expected_type
            if expected_default is ...:
                assert fields[key].is_required()
            else:
                assert fields[key].default == expected_default

    _assert_fields(
        "list_methods",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_functions",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_classes",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "search_functions_by_name",
        {
            "query": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "get_function_by_address",
        {
            "address": (str, ...),
        },
    )
    _assert_fields(
        "decompile_function",
        {
            "name": (str, ...),
        },
    )
    _assert_fields(
        "decompile_function_by_address",
        {
            "address": (str, ...),
        },
    )
    _assert_fields(
        "disassemble_function",
        {
            "address": (str, ...),
        },
    )
    _assert_fields(
        "get_callee",
        {
            "address": (str, ...),
        },
    )
    _assert_fields(
        "get_xrefs_to",
        {
            "address": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "get_xrefs_from",
        {
            "address": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "get_function_xrefs",
        {
            "name": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_segments",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_imports",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_exports",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_namespaces",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_data_items",
        {
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "list_strings",
        {
            "offset": (int, 0),
            "limit": (int, 2000),
            "filter": (str | None, None),
        },
    )
    _assert_fields(
        "get_data_by_label",
        {
            "label": (str, ...),
        },
    )
    _assert_fields(
        "get_bytes",
        {
            "address": (str, ...),
            "size": (int, 16),
        },
    )
    _assert_fields(
        "search_bytes",
        {
            "bytes": (str, ...),
            "offset": (int, 0),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "get_struct",
        {
            "name": (str, ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "get_enum",
        {
            "name": (str, ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "rename_function",
        {
            "oldName": (str, ...),
            "newName": (str, ...),
        },
    )
    _assert_fields(
        "rename_function_by_address",
        {
            "function_address": (str, ...),
            "new_name": (str, ...),
        },
    )
    _assert_fields(
        "rename_data",
        {
            "address": (str, ...),
            "newName": (str, ...),
        },
    )
    _assert_fields(
        "rename_variable",
        {
            "functionName": (str, ...),
            "oldName": (str, ...),
            "newName": (str, ...),
        },
    )
    _assert_fields(
        "set_decompiler_comment",
        {
            "address": (str, ...),
            "comment": (str, ...),
        },
    )
    _assert_fields(
        "set_disassembly_comment",
        {
            "address": (str, ...),
            "comment": (str, ...),
        },
    )
    _assert_fields(
        "set_function_prototype",
        {
            "function_address": (str, ...),
            "prototype": (str, ...),
        },
    )
    _assert_fields(
        "set_local_variable_type",
        {
            "function_address": (str, ...),
            "variable_name": (str, ...),
            "new_type": (str, ...),
        },
    )
    _assert_fields(
        "create_struct",
        {
            "name": (str, ...),
            "size": (int, 0),
            "category": (str | None, None),
            "members": (list[dict] | None, None),
        },
    )
    _assert_fields(
        "add_struct_members",
        {
            "struct_name": (str, ...),
            "members": (list[dict], ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "clear_struct",
        {
            "struct_name": (str, ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "create_enum",
        {
            "name": (str, ...),
            "size": (int, 4),
            "category": (str | None, None),
            "values": (list[dict] | None, None),
        },
    )
    _assert_fields(
        "add_enum_values",
        {
            "enum_name": (str, ...),
            "values": (list[dict], ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "remove_enum_values",
        {
            "enum_name": (str, ...),
            "values": (list[str], ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "create_class",
        {
            "name": (str, ...),
            "parent_namespace": (str | None, None),
            "members": (list[dict] | None, None),
        },
    )
    _assert_fields(
        "add_class_members",
        {
            "class_name": (str, ...),
            "members": (list[dict], ...),
            "parent_namespace": (str | None, None),
        },
    )
    _assert_fields(
        "remove_class_members",
        {
            "class_name": (str, ...),
            "members": (list[str], ...),
            "parent_namespace": (str | None, None),
        },
    )
    _assert_fields(
        "remove_struct_members",
        {
            "struct_name": (str, ...),
            "members": (list[str], ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "set_global_data_type",
        {
            "address": (str, ...),
            "data_type": (str, ...),
            "length": (int | None, None),
            "clear_mode": (str | None, None),
        },
    )
    _assert_fields(
        "set_bytes",
        {
            "address": (str, ...),
            "bytes": (str, ...),
        },
    )
    _assert_fields(
        "add_bookmark",
        {
            "address": (str, ...),
            "category": (str, ...),
            "comment": (str, ...),
            "type": (str, ...),
            "format": (str, "json"),
        },
    )
    _assert_fields("list_targets", {})
    _assert_fields("list_project_programs", {})
    _assert_fields(
        "register_target",
        {
            "project_location": (str, ...),
            "project_name": (str | None, None),
        },
    )
    _assert_fields(
        "load_project_program",
        {
            "domain_path": (str, ...),
        },
    )
    _assert_fields(
        "import_program",
        {
            "binary_path": (str, ...),
            "import_mode": (Literal["auto", "raw_binary"], "auto"),
            "language_id": (str | None, None),
            "compiler_spec_id": (str | None, None),
            "base_address": (str | None, None),
            "file_offset": (int | None, None),
            "length": (int | None, None),
            "block_name": (str | None, None),
            "overlay": (bool, False),
            "entry_address": (str | None, None),
            "entry_offset": (int | None, None),
            "analyze_imported": (bool | None, None),
        },
    )
    _assert_fields(
        "create_session",
        {
            "project_location": (str, ...),
            "domain_path": (str, ...),
            "project_name": (str | None, None),
        },
    )
    _assert_fields("close_session", {})
    _assert_fields("close_session_and_remove_program", {})
    _assert_fields(
        "get_project_sync_status",
        {
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "checkout_project_program",
        {
            "exclusive": (bool, False),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "add_project_program_to_version_control",
        {
            "comment": (str, ...),
            "keep_checked_out": (bool, False),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "commit_project_program",
        {
            "message": (str, ...),
            "keep_checked_out": (bool, False),
            "auto_checkout": (bool, True),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "pull_project_program",
        {
            "on_local_changes": (str, "abort"),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "undo_checkout_project_program",
        {
            "discard_local_changes": (bool, True),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "terminate_project_program_checkout",
        {
            "checkout_id": (int, ...),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "reload_project_program",
        {
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "get_version_history",
        {
            "limit": (int, 50),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "get_version_diff",
        {
            "from_version": (int, ...),
            "to_version": (int, ...),
            "range_limit": (int, 200),
            "domain_path": (str | None, None),
        },
    )


def test_registry_and_shared_sync_adapters_are_configured():
    specs = get_all_tool_specs(include_shared_sync=True)

    assert specs["load_project_program"].result_adapter == "status_program_ok"
    assert specs["import_program"].result_adapter == "status_program_ok"
    assert specs["create_session"].result_adapter == "status_target_ok"
    assert specs["create_session"].error_adapter == "create_session_error"
    assert specs["close_session"].result_adapter == "status_target_ok"
    assert specs["close_session"].error_adapter == "close_session_error"
    assert specs["close_session_and_remove_program"].result_adapter == "status_target_ok"
    assert specs["close_session_and_remove_program"].error_adapter == "close_remove_error"
    assert specs["close_session_and_remove_program"].static_kwargs == {"remove_program": True}


def test_specs_include_contract_driven_metadata():
    specs = get_all_tool_specs(include_shared_sync=True)

    assert specs["list_functions"].public_signature[-1] == "target"
    assert specs["register_target"].public_signature[0] == "target"
    assert specs["list_targets"].public_signature == ()
    assert specs["create_session"].error_policy == "legacy_compatible"
    assert hasattr(specs["create_session"], "output_model")


def test_all_output_models_are_strict_and_typed():
    specs = get_all_tool_specs(include_shared_sync=True)

    list_output_tools = {
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
        "list_targets",
        "list_project_programs",
    }
    scalar_output_tools = {
        "decompile_function": str,
        "decompile_function_by_address": str,
        "get_bytes": str,
        "load_project_program": str,
        "import_program": str,
    }
    direct_output_fields = {
        "create_session": {
            "target": (str, ...),
            "project_location": (str, ...),
            "project_name": (str | None, None),
            "domain_path": (str | None, None),
        },
        "close_session": {
            "closed": (bool, ...),
            "target": (str, ...),
            "remove_program": (bool, ...),
        },
        "close_session_and_remove_program": {
            "closed": (bool, ...),
            "target": (str, ...),
            "remove_program": (bool, ...),
        },
    }

    categorized = set(list_output_tools) | set(scalar_output_tools) | set(direct_output_fields)
    assert categorized <= set(specs)

    for name, spec in specs.items():
        model_fields = spec.output_model.model_fields
        assert model_fields
        for field in model_fields.values():
            assert field.annotation is not Any

        if name in direct_output_fields:
            expected = direct_output_fields[name]
            assert set(model_fields.keys()) == set(expected.keys())
            for key, (expected_type, expected_default) in expected.items():
                assert model_fields[key].annotation == expected_type
                if expected_default is ...:
                    assert model_fields[key].is_required()
                else:
                    assert model_fields[key].default == expected_default
            continue

        assert set(model_fields.keys()) == {"payload"}
        if name in list_output_tools:
            assert model_fields["payload"].annotation == list[object]
        elif name in scalar_output_tools:
            assert model_fields["payload"].annotation == (scalar_output_tools[name] | list[object])
        else:
            assert model_fields["payload"].annotation == (dict[str, object] | list[object])


def test_any_output_model_helper_is_removed():
    source = TOOL_SPEC_PATH.read_text(encoding="utf-8")
    assert "create_any_output_model" not in source
    assert not hasattr(tool_models, "create_any_output_model")


def test_all_specs_have_required_contract_fields():
    specs = get_all_tool_specs(include_shared_sync=True)

    for spec in specs.values():
        assert spec.output_model is not None
        assert spec.error_policy == "legacy_compatible"
        assert isinstance(spec.public_signature, tuple)

        fields = tuple(spec.input_model.model_fields.keys())
        if spec.executor_kind == ExecutorKind.CORE_COMMAND and spec.include_target:
            expected_signature = (*fields, "target")
        elif spec.include_target:
            expected_signature = ("target", *fields)
        else:
            expected_signature = fields
        assert spec.public_signature == expected_signature
