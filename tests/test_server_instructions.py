"""Discovery guidance must describe the exposed operations, not the profile name."""

import pytest

from ghidra_mcp.contracts.tool_spec import (
    ToolCategoryTag,
    ToolProfile,
    filter_tool_specs,
    get_all_tool_specs,
    get_tool_spec,
)
from ghidra_mcp.presentation.config import ToolPresentationConfig
from ghidra_mcp.presentation.server_instructions import build_server_instructions


def instructions(specs, *, mode="resource"):
    return build_server_instructions(specs=specs, config=ToolPresentationConfig(large_result_mode=mode))


@pytest.mark.parametrize("profile", list(ToolProfile))
@pytest.mark.parametrize("mode", ["resource", "inline"])
def test_discovery_guidance_has_tasks_docs_and_bounded_stable_text(profile, mode):
    specs = filter_tool_specs(profile=profile)
    text = instructions(specs, mode=mode)
    assert "static binary analysis" in text
    assert "Search this server's tools when" in text
    assert "decompilation" in text
    assert "cross-reference queries" in text
    assert "list_targets" in text
    assert "intended target" in text
    assert "ghidra://docs/tools/{tool_name}" in text
    assert "do not automatically repeat completed changes" in text
    assert len(text.encode("utf-8")) <= 1900
    assert text == instructions(dict(reversed(list(specs.items()))), mode=mode)
    assert ("read_result" in text) == (mode == "resource")
    assert ("search_result" in text) == (mode == "resource")
    assert ("RESULT_TOO_LARGE" in text) == (mode == "resource")
    if mode == "resource":
        assert "continue_offset_chars" in text
        assert "isError" in text


def test_readonly_does_not_advertise_mutations_or_optional_categories():
    text = instructions(filter_tool_specs(profile=ToolProfile.READONLY))
    for phrase in (
        "type edits",
        "byte patches",
        "symbol/comment edits",
        "function edits",
        "project/program management",
    ):
        assert phrase not in text
    for phrase in ("BSim", "repository", "script execution", "script discovery"):
        assert phrase not in text
    assert "type inspection" in text
    assert "comment queries" in text


def test_individual_filters_override_category_capabilities():
    specs = filter_tool_specs(
        profile=ToolProfile.READONLY,
        disable_tools=["decompile_function", "disassemble", "list_targets", "get_xrefs"],
        enable_tools=["set_bytes"],
    )
    text = instructions(specs)
    assert "byte patches" in text
    for phrase in ("decompilation", "disassembly", "list_targets", "cross-reference queries", "type edits"):
        assert phrase not in text


@pytest.mark.parametrize(
    ("name", "present", "absent"),
    [
        ("get_data_type", "type inspection", "type edits"),
        ("create_struct", "type edits", "type inspection"),
        ("get_comments", "comment queries", "symbol/comment edits"),
        ("list_scripts", "script discovery", "script execution"),
        ("run_script", "configured script execution", "script discovery"),
        ("bsim_query", "BSim similarity search", "BSim workflows"),
        ("get_bsim_database_status", "BSim database inspection", "BSim similarity search"),
        ("get_version_history", "repository status/history", "repository synchronization"),
        ("commit_project_program", "repository synchronization", "repository status/history"),
    ],
)
def test_single_tool_does_not_advertise_sibling_operations(name, present, absent):
    text = instructions({name: get_tool_spec(name)})
    assert present in text
    assert absent not in text


def test_optional_readonly_categories_do_not_advertise_writes():
    specs = filter_tool_specs(profile=ToolProfile.FULL, allow_safety=["read_only"])
    text = instructions(specs)
    assert "BSim similarity search" in text
    assert "repository status/history" in text
    assert "script discovery" in text
    for phrase in ("BSim workflows", "repository synchronization", "script execution"):
        assert phrase not in text


def test_empty_selection_does_not_invent_analysis_capabilities():
    text = instructions({}, mode="inline")
    assert "No analysis capabilities are advertised" in text
    assert "Search this server's tools when" not in text
    assert "list_targets" not in text
    assert "intended target" not in text
    assert "read_result" not in text


def test_byte_budget_for_categories_and_individual_tools():
    for category in ToolCategoryTag:
        assert len(instructions(filter_tool_specs(allow_categories=[category])).encode("utf-8")) <= 1900
    for name, spec in get_all_tool_specs().items():
        assert len(instructions({name: spec}).encode("utf-8")) <= 1900
