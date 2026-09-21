from __future__ import annotations

import pytest

from ghidra_mcp import cli
from ghidra_mcp.contracts.tool_spec import (
    ToolCategoryTag,
    ToolOperationLevel,
    ToolProfile,
    ToolSafetyTag,
    filter_tool_specs,
    get_all_tool_specs,
)

ALL_SPECS = get_all_tool_specs()
ALL_TOOL_NAMES = set(ALL_SPECS)
DEFAULT_CATEGORIES = {
    ToolCategoryTag.CORE,
    ToolCategoryTag.FUNCTION_ANALYSIS,
    ToolCategoryTag.MEMORY_DATA,
    ToolCategoryTag.SYMBOL_COMMENT_EDIT,
    ToolCategoryTag.DATATYPE_OPS,
}


def _manual_selected_names(
    *,
    categories: set[ToolCategoryTag] | None = None,
    safety_tags: set[ToolSafetyTag] | None = None,
    operation_levels: set[ToolOperationLevel] | None = None,
    enable_tools: set[str] | None = None,
    disable_tools: set[str] | None = None,
) -> set[str]:
    selected = {
        name
        for name, spec in ALL_SPECS.items()
        if (categories is None or spec.category_tag in categories)
        and (safety_tags is None or spec.safety_tag in safety_tags)
        and (operation_levels is None or spec.operation_level in operation_levels)
    }
    selected.update(enable_tools or set())
    selected.difference_update(disable_tools or set())
    return selected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], _manual_selected_names(categories=set(DEFAULT_CATEGORIES))),
        (["--tool-profile", "default"], _manual_selected_names(categories=set(DEFAULT_CATEGORIES))),
        (
            ["--tool-profile", "default", "--allow-safety", "read_only"],
            _manual_selected_names(
                categories=set(DEFAULT_CATEGORIES),
                safety_tags={ToolSafetyTag.READ_ONLY},
            ),
        ),
        (
            ["--tool-profile", "default", "--allow-category", "shared_sync"],
            _manual_selected_names(categories={ToolCategoryTag.SHARED_SYNC}),
        ),
        (
            ["--tool-profile", "default", "--add-category", "shared_sync"],
            _manual_selected_names(categories=set(DEFAULT_CATEGORIES) | {ToolCategoryTag.SHARED_SYNC}),
        ),
        (
            ["--tool-profile", "full"],
            ALL_TOOL_NAMES,
        ),
        (
            ["--tool-profile", "readonly", "--add-category", "shared_sync"],
            _manual_selected_names(
                categories=set(DEFAULT_CATEGORIES) | {ToolCategoryTag.SHARED_SYNC},
                safety_tags={ToolSafetyTag.READ_ONLY},
            ),
        ),
        (
            ["--tool-profile", "full", "--allow-safety", "read_only"],
            _manual_selected_names(safety_tags={ToolSafetyTag.READ_ONLY}),
        ),
        (
            ["--tool-profile", "readonly", "--enable-tool", "apply_edits"],
            _manual_selected_names(
                categories=set(DEFAULT_CATEGORIES),
                safety_tags={ToolSafetyTag.READ_ONLY},
                enable_tools={"apply_edits"},
            ),
        ),
        (
            ["--tool-profile", "full", "--disable-tool", "set_bytes"],
            ALL_TOOL_NAMES - {"set_bytes"},
        ),
        (
            ["--tool-profile", "full", "--enable-tool", "set_bytes", "--disable-tool", "set_bytes"],
            ALL_TOOL_NAMES - {"set_bytes"},
        ),
    ],
)
def test_cli_tool_filters_match_expected_tool_sets(argv, expected):
    args = cli.parse_args(argv)
    resolved = cli.resolve_tool_specs_from_args(args)
    assert set(resolved) == expected


def test_filter_tool_specs_combines_same_type_with_or_and_different_types_with_and():
    filtered = filter_tool_specs(
        profile=ToolProfile.FULL,
        allow_categories=[ToolCategoryTag.CORE.value, ToolCategoryTag.SHARED_SYNC.value],
        allow_safety=[
            ToolSafetyTag.READ_ONLY.value,
            ToolSafetyTag.WRITE.value,
        ],
        allow_operation_levels=[
            ToolOperationLevel.BASIC.value,
            ToolOperationLevel.ADVANCED.value,
        ],
    )

    expected = _manual_selected_names(
        categories={ToolCategoryTag.CORE, ToolCategoryTag.SHARED_SYNC},
        safety_tags={
            ToolSafetyTag.READ_ONLY,
            ToolSafetyTag.WRITE,
        },
        operation_levels={
            ToolOperationLevel.BASIC,
            ToolOperationLevel.ADVANCED,
        },
    )
    assert set(filtered) == expected


def test_default_profile_contains_current_non_shared_sync_tools():
    default_specs = filter_tool_specs(profile=ToolProfile.DEFAULT)
    legacy_default_specs = {
        name
        for name, spec in get_all_tool_specs().items()
        if spec.category_tag not in {ToolCategoryTag.SHARED_SYNC, ToolCategoryTag.BSIM, ToolCategoryTag.SCRIPTS}
    }

    assert set(default_specs) == legacy_default_specs
    assert "run_script" not in default_specs
    assert "get_project_sync_status" not in default_specs
    assert "bsim_query" not in default_specs


def test_full_profile_exposes_current_tools_without_legacy_names():
    assert set(filter_tool_specs(profile=ToolProfile.FULL)) == set(ALL_SPECS)
    for name in ("get_callee", "rename_function", "create_session", "bsim_query_function"):
        assert name not in ALL_SPECS
        assert name not in filter_tool_specs(enable_tools=[name])


def test_existing_management_and_type_edit_exposure_is_preserved():
    default = filter_tool_specs()
    assert {
        "close_session_and_remove_program",
        "remove_struct_members",
        "delete_data_type",
        "set_enum_values",
        "set_local_variable_type",
    } <= set(default)
    for category, names in [
        (ToolCategoryTag.BSIM, {"bsim_delete_executable", "bsim_query"}),
        (ToolCategoryTag.SHARED_SYNC, {"delete_shared_project_file", "terminate_project_program_checkout"}),
    ]:
        assert names <= set(filter_tool_specs(add_categories=[category]))
