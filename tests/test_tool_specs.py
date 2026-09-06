from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

import ghidra_mcp.contracts.tool_models as tool_models
from ghidra_mcp.contracts.tool_spec import (
    ClearDataMode,
    CommentKind,
    CommitConflictAction,
    ConflictAction,
    ExecutorKind,
    ToolCategoryTag,
    ToolOperationLevel,
    ToolSafetyTag,
    filter_tool_specs,
    get_all_tool_specs,
    get_checkout_required_tool_names,
)
from ghidra_mcp.presentation import cli as presentation_cli
from ghidra_mcp.presentation.tool_registry import build_tool_functions, build_tool_objects, public_parameter_names

ROOT = Path(__file__).resolve().parents[1]
TOOL_SPEC_PATH = ROOT / "src" / "ghidra_mcp" / "contracts" / "tool_spec.py"


def test_tool_specs_cover_all_public_tools():
    specs = get_all_tool_specs()
    assert set(specs) == set(presentation_cli.PUBLIC_TOOL_FUNCTIONS)


def test_paginated_tool_schema_and_validation_are_bounded():
    spec = get_all_tool_specs()["list_functions"]
    schema = spec.input_model.model_json_schema()["properties"]

    assert schema["offset"]["minimum"] == 0
    assert schema["offset"]["maximum"] == 1_000_000
    assert schema["limit"]["minimum"] == 1
    assert schema["limit"]["maximum"] == 10_000

    for params in (
        {"offset": -1},
        {"offset": 1_000_001},
        {"limit": 0},
        {"limit": 10_001},
    ):
        with pytest.raises(ValidationError):
            spec.input_model.model_validate(params)


def test_version_diff_range_limit_is_bounded():
    spec = get_all_tool_specs()["get_version_diff"]
    schema = spec.input_model.model_json_schema()["properties"]["range_limit"]

    assert schema["minimum"] == 0
    assert schema["maximum"] == 10_000


def test_tool_specs_include_expected_tags():
    specs = get_all_tool_specs()

    assert specs["list_functions"].category_tag == ToolCategoryTag.FUNCTION_ANALYSIS
    assert specs["list_functions"].safety_tag == ToolSafetyTag.READ_ONLY
    assert specs["list_functions"].operation_level == ToolOperationLevel.STANDARD

    assert specs["rename_function"].category_tag == ToolCategoryTag.SYMBOL_COMMENT_EDIT
    assert specs["rename_function"].safety_tag == ToolSafetyTag.WRITE
    assert specs["rename_function"].operation_level == ToolOperationLevel.BASIC

    assert specs["import_program"].category_tag == ToolCategoryTag.CORE
    assert specs["import_program"].safety_tag == ToolSafetyTag.WRITE
    assert specs["import_program"].operation_level == ToolOperationLevel.ADVANCED

    assert specs["set_bytes"].category_tag == ToolCategoryTag.SYMBOL_COMMENT_EDIT
    assert specs["set_bytes"].safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE
    assert specs["set_bytes"].operation_level == ToolOperationLevel.ADVANCED

    assert specs["remove_struct_members"].category_tag == ToolCategoryTag.DATATYPE_OPS
    assert specs["remove_struct_members"].safety_tag == ToolSafetyTag.WRITE
    assert specs["remove_struct_members"].operation_level == ToolOperationLevel.STANDARD

    assert specs["delete_data_type"].category_tag == ToolCategoryTag.DATATYPE_OPS
    assert specs["delete_data_type"].safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE
    assert specs["set_comment"].category_tag == ToolCategoryTag.SYMBOL_COMMENT_EDIT
    assert specs["set_comment"].checkout_required is True

    assert specs["get_project_sync_status"].category_tag == ToolCategoryTag.SHARED_SYNC
    assert specs["get_project_sync_status"].safety_tag == ToolSafetyTag.READ_ONLY
    assert specs["get_project_sync_status"].operation_level == ToolOperationLevel.BASIC

    assert specs["undo_checkout_project_program"].category_tag == ToolCategoryTag.SHARED_SYNC
    assert specs["undo_checkout_project_program"].safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE
    assert specs["undo_checkout_project_program"].operation_level == ToolOperationLevel.STANDARD

    assert specs["bsim_query_target"].category_tag == ToolCategoryTag.BSIM
    assert specs["bsim_query_target"].safety_tag == ToolSafetyTag.READ_ONLY
    assert specs["bsim_query_target"].operation_level == ToolOperationLevel.STANDARD

    assert specs["bsim_register_target"].category_tag == ToolCategoryTag.BSIM
    assert specs["bsim_register_target"].safety_tag == ToolSafetyTag.WRITE
    assert specs["bsim_register_target"].operation_level == ToolOperationLevel.STANDARD


def test_shared_sync_specs_are_tagged_as_shared_sync_category():
    specs = get_all_tool_specs()
    shared_sync_names = {name for name, spec in specs.items() if spec.category_tag == ToolCategoryTag.SHARED_SYNC}

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
        "delete_shared_project_file",
    }


def test_bsim_specs_are_tagged_as_bsim_category():
    specs = get_all_tool_specs()
    bsim_names = {name for name, spec in specs.items() if spec.category_tag == ToolCategoryTag.BSIM}

    assert bsim_names == {
        "get_bsim_database_status",
        "bsim_add_executable_category",
        "list_bsim_executables",
        "get_bsim_executable",
        "bsim_update_executable_metadata",
        "bsim_query_target",
        "bsim_query_function",
        "bsim_load_matched_executable",
        "bsim_register_target",
        "bsim_apply_matches",
        "bsim_update_target_signatures",
        "bsim_delete_executable",
    }


def test_shared_sync_specs_register_via_generic_tool_registration():
    specs = filter_tool_specs(allow_categories=[ToolCategoryTag.SHARED_SYNC])
    tools = build_tool_functions(
        specs=specs,
        dispatcher_provider=lambda: presentation_cli.dispatch_tool,
        registry_provider=lambda: presentation_cli._registry,
    )

    tool_objects = build_tool_objects(tools=tools, specs=specs)
    annotations_by_name: dict[str, Any] = {tool.name: tool.annotations for tool in tool_objects}

    shared_sync_names = list(specs)
    assert [tool.name for tool in tool_objects] == shared_sync_names
    assert {name for name, annotations in annotations_by_name.items() if annotations.read_only_hint is True} == {
        "get_project_sync_status",
        "get_version_history",
        "get_version_diff",
    }
    assert {name for name, annotations in annotations_by_name.items() if annotations.destructive_hint is True} == {
        "commit_project_program",
        "pull_project_program",
        "undo_checkout_project_program",
        "terminate_project_program_checkout",
        "delete_shared_project_file",
    }


def test_typed_input_models_for_function_listing_slice():
    specs = get_all_tool_specs()

    def _plain(annotation):
        import functools
        import operator
        import types as _types
        import typing

        origin = typing.get_origin(annotation)
        if origin is typing.Annotated:
            return _plain(typing.get_args(annotation)[0])
        if origin in (typing.Union, _types.UnionType):
            return functools.reduce(operator.or_, [_plain(arg) for arg in typing.get_args(annotation)])
        return annotation

    def _assert_fields(tool_name: str, expected_fields: dict[str, tuple[type, object]]):
        model = specs[tool_name].input_model
        fields = model.model_fields
        assert set(fields.keys()) == set(expected_fields.keys())
        for key, (expected_type, expected_default) in expected_fields.items():
            # Bounds live in Annotated metadata; the base type is what matters here.
            assert _plain(fields[key].annotation) == _plain(expected_type), (tool_name, key)
            if expected_default is ...:
                assert fields[key].is_required()
            else:
                assert fields[key].default == expected_default

    _assert_fields(
        "list_functions",
        {
            "offset": (int, 0),
            "limit": (int, 100),
            "filter": (str | None, None),
            "only_default_names": (bool, False),
        },
    )
    _assert_fields(
        "get_function",
        {
            "address": (str | None, None),
            "name": (str | None, None),
        },
    )
    _assert_fields(
        "decompile_function",
        {
            "address": (str | None, None),
            "name": (str | None, None),
        },
    )
    _assert_fields(
        "disassemble_function",
        {
            "address": (str, ...),
        },
    )
    _assert_fields(
        "disassemble_range",
        {
            "start_address": (str, ...),
            "end_address": (str | None, None),
            "length": (int | None, None),
            "limit": (int, 200),
        },
    )
    _assert_fields(
        "create_function",
        {
            "address": (str, ...),
            "name": (str | None, None),
        },
    )
    _assert_fields(
        "delete_function",
        {
            "address": (str, ...),
        },
    )
    _assert_fields("analyze_program", {"force": (bool, False)})
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
            "address": (str | None, None),
            "name": (str | None, None),
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
            "classes_only": (bool, False),
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
            "address": (str | None, None),
            "oldName": (str | None, None),
            "newName": (str, ...),
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
            "oldName": (str, ...),
            "newName": (str, ...),
            "functionAddress": (str | None, None),
            "functionName": (str | None, None),
        },
    )
    _assert_fields(
        "set_comment",
        {
            "address": (str, ...),
            "comment": (str, ...),
            "kind": (CommentKind, ...),
        },
    )
    _assert_fields(
        "set_function_prototype",
        {
            "prototype": (str, ...),
            "function_address": (str | None, None),
            "function_name": (str | None, None),
        },
    )
    _assert_fields(
        "set_local_variable_type",
        {
            "variable_name": (str, ...),
            "new_type": (str, ...),
            "function_address": (str | None, None),
            "function_name": (str | None, None),
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
        "delete_data_type",
        {
            "name": (str, ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "list_data_types",
        {
            "offset": (int, 0),
            "limit": (int, 100),
            "filter": (str | None, None),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "rename_data_type",
        {
            "name": (str, ...),
            "new_name": (str, ...),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "remove_struct_members",
        {
            "struct_name": (str, ...),
            "members": (list[str | dict] | None, None),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "set_global_data_type",
        {
            "address": (str, ...),
            "data_type": (str, ...),
            "length": (int | None, None),
            "clear_mode": (ClearDataMode | None, None),
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
        },
    )
    _assert_fields(
        "list_bookmarks",
        {
            "offset": (int, 0),
            "limit": (int, 100),
            "address": (str | None, None),
            "type": (str | None, None),
            "category": (str | None, None),
        },
    )
    _assert_fields(
        "delete_bookmark",
        {
            "id": (int | None, None),
            "address": (str | None, None),
            "category": (str | None, None),
            "comment": (str | None, None),
            "type": (str | None, None),
        },
    )
    _assert_fields("list_targets", {})
    _assert_fields(
        "create_project",
        {
            "project_location": (str, ...),
            "project_name": (str | None, None),
            "overwrite": (bool, False),
        },
    )
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
            "version": (int | None, None),
        },
    )
    _assert_fields(
        "save_project_program",
        {
            "domain_path": (str | None, None),
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
            "exclusive": (bool | None, None),
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
            "on_conflict": (CommitConflictAction, "abort"),
            "domain_path": (str | None, None),
        },
    )
    _assert_fields(
        "pull_project_program",
        {
            "on_local_changes": (ConflictAction, "abort"),
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
        "delete_shared_project_file",
        {
            "domain_path": (str, ...),
            "confirm": (str, ...),
            "expected_latest_version": (int | None, None),
            "allow_private": (bool, False),
            "allow_non_atomic_versioned_delete": (bool, False),
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
            "include_details": (bool, False),
            "details_limit": (int, 20),
        },
    )
    _assert_fields(
        "get_bsim_database_status",
        {
            "bsim_url": (str | None, None),
        },
    )
    _assert_fields(
        "bsim_add_executable_category",
        {
            "bsim_url": (str | None, None),
            "category": (str, ...),
        },
    )
    _assert_fields(
        "list_bsim_executables",
        {
            "bsim_url": (str | None, None),
            "name": (str | None, None),
            "md5": (str | None, None),
            "arch": (str | None, None),
            "compiler": (str | None, None),
            "limit": (int, 100),
        },
    )
    _assert_fields(
        "bsim_update_executable_metadata",
        {
            "bsim_url": (str | None, None),
            "categories": (dict[str, object], ...),
            "md5": (str | None, None),
            "name": (str | None, None),
        },
    )
    _assert_fields(
        "bsim_query_function",
        {
            "bsim_url": (str | None, None),
            "address": (str | None, None),
            "function_name": (str | None, None),
            "similarity_threshold": (float, 0.7),
            "significance_threshold": (float, 0.0),
            "matches_per_function": (int, 10),
            "max_results": (int, 100),
            "addresses": (list[str] | None, None),
            "function_names": (list[str] | None, None),
            "exclude_self": (bool, True),
        },
    )
    _assert_fields(
        "bsim_load_matched_executable",
        {
            "matched_ref": (dict[str, object], ...),
            "target": (str | None, None),
        },
    )


def test_registry_and_shared_sync_adapters_are_configured():
    specs = get_all_tool_specs()

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
    specs = get_all_tool_specs()

    assert tuple(public_parameter_names(specs["list_functions"]))[-1] == "target"
    assert tuple(public_parameter_names(specs["register_target"]))[0] == "target"
    assert tuple(public_parameter_names(specs["list_targets"])) == ()
    assert hasattr(specs["create_session"], "output_model")
    assert specs["rename_function"].public_name_overrides == {
        "oldName": "old_name",
        "newName": "new_name",
    }
    assert specs["list_strings"].omit_falsey_keys == frozenset({"filter"})
    assert specs["list_targets"].description is not None
    assert specs["list_targets"].safety_tag == ToolSafetyTag.READ_ONLY
    assert specs["list_targets"].idempotent_hint is True


def test_checkout_required_tools_are_declared_on_specs():
    assert get_checkout_required_tool_names() == {
        "rename_function",
        "rename_data",
        "rename_variable",
        "set_comment",
        "set_function_prototype",
        "set_local_variable_type",
        "set_global_data_type",
        "create_function",
        "delete_function",
        "analyze_program",
        "create_struct",
        "delete_data_type",
        "rename_data_type",
        "add_struct_members",
        "remove_struct_members",
        "set_bytes",
        "add_bookmark",
        "delete_bookmark",
        "create_label",
        "undo_program_change",
        "redo_program_change",
        "create_enum",
        "set_enum_values",
        "parse_c_declarations",
        "bsim_apply_matches",
    }


def test_all_output_models_are_strict_and_typed():
    specs = get_all_tool_specs()

    list_output_tools = {
        "list_functions",
        "disassemble_function",
        "disassemble_range",
        "get_callee",
        "get_xrefs_to",
        "get_xrefs_from",
        "get_function_xrefs",
        "list_segments",
        "list_imports",
        "list_exports",
        "list_namespaces",
        "list_data_items",
        "list_data_types",
        "list_strings",
        "get_data_by_label",
        "search_bytes",
        "search_symbols",
        "list_bookmarks",
        "list_targets",
        "list_project_programs",
    }
    scalar_output_tools = {
        "decompile_function": str,
        "get_bytes": str,
    }

    direct_output_fields: dict[str, dict[str, tuple[type[Any], Any]]] = {
        "load_project_program": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "reloaded": (bool, False),
            "version": (int | None, None),
            "read_only": (bool, False),
        },
        "import_program": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
        },
        "create_session": {
            "status": (str, ...),
            "target": (str, ...),
            "project_location": (str, ...),
            "project_name": (str | None, None),
            "domain_path": (str | None, None),
        },
        "close_session": {
            "status": (str, ...),
            "closed": (bool, ...),
            "target": (str, ...),
            "remove_program": (bool, ...),
        },
        "close_session_and_remove_program": {
            "status": (str, ...),
            "closed": (bool, ...),
            "target": (str, ...),
            "remove_program": (bool, ...),
        },
        "save_project_program": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "saved": (bool, ...),
        },
        "get_project_sync_status": {
            "target": (str, ...),
            "program": (str, ...),
            "is_versioned": (bool, ...),
            "is_checked_out": (bool, ...),
            "is_checked_out_exclusive": (bool, ...),
            "is_latest_version": (bool | None, ...),
            "modified_since_checkout": (bool, ...),
            "can_add_to_repository": (bool, ...),
            "can_checkout": (bool, ...),
            "can_checkin": (bool, ...),
            "can_merge": (bool, ...),
            "is_hijacked": (bool, ...),
            "version": (int | None, ...),
            "latest_version": (int | None, ...),
            "checkout_status": (dict[str, object] | None, ...),
            "checkouts": (list[object], ...),
            "shared_project_url": (str | None, ...),
        },
        "get_version_history": {
            "target": (str, ...),
            "program": (str, ...),
            "current_version": (int, ...),
            "latest_version": (int, ...),
            "total_versions": (int, ...),
            "versions": (list[object], ...),
        },
        "get_version_diff": {
            "target": (str, ...),
            "program": (str, ...),
            "from_version": (int, ...),
            "to_version": (int, ...),
            "total_diff_addresses": (int, ...),
            "total_diff_ranges": (int, ...),
            "diff_types": (list[object], ...),
            "ranges": (list[object], ...),
            "ranges_truncated": (bool, ...),
            "details": (list[object], ...),
            "details_truncated": (bool, ...),
            "warnings": (str | None, ...),
        },
        "checkout_project_program": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "checked_out": (bool, ...),
            "already_checked_out": (bool, ...),
            "exclusive": (bool, ...),
        },
        "add_project_program_to_version_control": {
            "status": (str, ...),
            "reason": (str | None, None),
            "target": (str, ...),
            "program": (str, ...),
            "is_versioned": (bool | None, None),
            "version": (int | None, None),
            "latest_version": (int | None, None),
            "checked_out": (bool | None, None),
            "effective_keep_checked_out": (bool | None, None),
        },
        "commit_project_program": {
            "status": (str, ...),
            "reason": (str | None, None),
            "target": (str, ...),
            "program": (str, ...),
            "required_action": (str | None, None),
            "can_add_to_repository": (bool | None, None),
            "message": (str | None, None),
            "new_version": (int | None, None),
            "version": (int | None, None),
            "latest_version": (int | None, None),
            "checked_out": (bool | None, None),
            "effective_keep_checked_out": (bool | None, None),
            "is_latest_version": (bool | None, None),
            "discarded_local_changes": (bool | None, None),
            "merged": (bool | None, None),
            "committed": (bool | None, None),
            "conflict_discarded": (bool | None, None),
            "conflict_kept": (bool | None, None),
            "kept_program": (str | None, None),
        },
        "pull_project_program": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "updated": (bool, ...),
            "merged": (bool, ...),
            "discarded_local_changes": (bool, ...),
            "discarded_hijacked_file": (bool | None, None),
            "followed_latest": (bool, ...),
            "reloaded": (bool, ...),
            "checked_out": (bool, ...),
            "version": (int | None, ...),
            "latest_version": (int | None, ...),
            "is_latest_version": (bool | None, ...),
        },
        "undo_checkout_project_program": {
            "status": (str, ...),
            "reason": (str | None, None),
            "target": (str, ...),
            "program": (str, ...),
            "checked_out": (bool | None, None),
            "version": (int | None, None),
            "is_latest_version": (bool | None, None),
            "kept_program": (str | None, None),
        },
        "terminate_project_program_checkout": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "checkout_id": (int, ...),
            "active_checkouts": (list[object], ...),
        },
        "delete_shared_project_file": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "domain_path": (str, ...),
            "deleted": (bool, ...),
            "content_type": (str | None, ...),
            "was_versioned": (bool, ...),
            "version": (int | None, ...),
            "latest_version": (int | None, ...),
            "atomic_version_guard": (bool, ...),
        },
        "bsim_load_matched_executable": {
            "status": (str, ...),
            "target": (str, ...),
            "program": (str, ...),
            "matched_function_address": (str | None, None),
            "matched_function_name": (str | None, None),
            "executable_md5": (str | None, None),
            "matched_ref_version": (int, 1),
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
    specs = get_all_tool_specs()

    for spec in specs.values():
        assert spec.output_model is not None
        assert isinstance(tuple(public_parameter_names(spec)), tuple)

        fields = tuple(spec.public_name_overrides.get(key, key) for key in spec.input_model.model_fields)
        if spec.executor_kind == ExecutorKind.CORE_COMMAND and spec.include_target:
            expected_signature = (*fields, "target")
        elif spec.include_target:
            expected_signature = ("target", *fields)
        else:
            expected_signature = fields
        assert tuple(public_parameter_names(spec)) == expected_signature


def _assert_input_fields(tool_name: str, expected_fields: dict[str, tuple[Any, Any]]) -> None:
    fields = get_all_tool_specs()[tool_name].input_model.model_fields
    assert set(fields.keys()) == set(expected_fields.keys()), tool_name
    for name, (expected_type, expected_default) in expected_fields.items():
        field = fields[name]
        if expected_default is ...:
            assert field.is_required(), f"{tool_name}.{name} should be required"
        else:
            assert field.default == expected_default, f"{tool_name}.{name} default"
        if expected_type in (int, float):
            # Bounded numbers are Annotated[...] aliases; compare the underlying type.
            import typing

            annotation = field.annotation
            if typing.get_origin(annotation) is typing.Annotated:
                annotation = typing.get_args(annotation)[0]
            assert annotation is expected_type, f"{tool_name}.{name} type"
        else:
            assert field.annotation == expected_type, f"{tool_name}.{name} type"


def test_new_bsim_tool_specs_declare_their_parameters():
    _assert_input_fields(
        "bsim_query_target",
        {
            "bsim_url": (str | None, None),
            "similarity_threshold": (float, 0.7),
            "significance_threshold": (float, 0.0),
            "matches_per_function": (int, 10),
            "max_results": (int, 500),
            "exclude_self": (bool, True),
            "min_function_size": (int, 0),
        },
    )
    _assert_input_fields(
        "bsim_register_target",
        {
            "bsim_url": (str | None, None),
            "categories": (dict[str, object] | None, None),
        },
    )
    _assert_input_fields(
        "bsim_apply_matches",
        {
            "bsim_url": (str | None, None),
            "similarity_threshold": (float, 0.9),
            "significance_threshold": (float, 0.0),
            "matches_per_function": (int, 5),
            "max_functions": (int, 500),
            "only_default_names": (bool, True),
            "exclude_self": (bool, True),
            "min_function_size": (int, 0),
            "dry_run": (bool, False),
            "addresses": (list[str] | None, None),
            "function_names": (list[str] | None, None),
        },
    )
    _assert_input_fields("bsim_update_target_signatures", {"bsim_url": (str | None, None)})
    _assert_input_fields(
        "bsim_delete_executable",
        {
            "confirm": (str, ...),
            "bsim_url": (str | None, None),
            "md5": (str | None, None),
            "name": (str | None, None),
        },
    )
    specs = get_all_tool_specs()
    assert specs["bsim_delete_executable"].safety_tag == ToolSafetyTag.DESTRUCTIVE_WRITE
    assert specs["bsim_delete_executable"].include_target is False
    assert specs["bsim_apply_matches"].checkout_required is True
    assert specs["bsim_apply_matches"].safety_tag == ToolSafetyTag.WRITE
