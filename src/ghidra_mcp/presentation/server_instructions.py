"""Concise discovery guidance derived from the tools actually exposed."""

from __future__ import annotations

from collections.abc import Mapping

from ghidra_mcp.contracts.tool_spec import ToolCategoryTag, ToolSafetyTag, ToolSpec
from ghidra_mcp.presentation.config import ToolPresentationConfig

# Fixed order keeps discovery instructions stable across registration order.
# Each phrase must still be true when only one of its tools is enabled.
_CAPABILITIES = (
    ("target/program inspection", "list_targets list_project_programs get_program_info"),
    (
        "project/program management",
        "create_project open_program register_target close_session close_session_and_remove_program "
        "import_program load_project_program save_project_program export_program",
    ),
    ("decompilation", "decompile_function"),
    ("disassembly", "disassemble"),
    ("function/namespace queries", "list_functions list_namespaces get_function"),
    ("call graph queries", "get_call_edges"),
    ("cross-reference queries", "get_xrefs"),
    ("function edits", "create_function delete_function"),
    ("program analysis", "analyze_program"),
    (
        "memory/data inspection",
        "list_segments list_imports list_exports list_data_items get_data_by_label",
    ),
    ("string queries", "list_strings"),
    ("byte queries", "get_bytes search_bytes"),
    ("byte patches", "set_bytes"),
    ("symbol queries", "search_symbols"),
    ("comment queries", "get_comments"),
    ("bookmark queries", "list_bookmarks"),
    ("type inspection", "get_data_type list_data_types"),
    (
        "type edits",
        "set_function_prototype set_local_variable_type set_global_data_type create_struct add_struct_members "
        "delete_data_type remove_struct_members rename_data_type create_enum set_enum_values parse_c_declarations",
    ),
    ("symbol/comment edits", "apply_edits"),
    ("label creation", "create_label"),
    ("bookmark edits", "add_bookmark delete_bookmark"),
    ("undo/redo", "undo_program_change redo_program_change"),
    ("BSim similarity search", "bsim_query"),
    ("script discovery", "list_scripts get_script_info"),
    ("configured script execution", "run_script"),
)


def build_server_instructions(*, specs: Mapping[str, ToolSpec], config: ToolPresentationConfig) -> str:
    """Explain when to find enabled tools, without duplicating their schemas.

    Descriptions of individual operations live on the tools and docs resources.
    Keep this introduction below the 2 KB truncation used by some clients; the
    tests enforce a 1,900-byte budget even with every capability enabled.
    """
    enabled = specs.keys()
    capabilities = [label for label, names in _CAPABILITIES if enabled & set(names.split())]
    for category, read_label, write_label in (
        (ToolCategoryTag.BSIM, "BSim database inspection", "BSim workflows"),
        (ToolCategoryTag.SHARED_SYNC, "repository status/history", "repository synchronization"),
    ):
        category_specs = [
            spec for spec in specs.values() if spec.category_tag == category and spec.name != "bsim_query"
        ]
        if any(spec.safety_tag == ToolSafetyTag.READ_ONLY for spec in category_specs):
            capabilities.append(read_label)
        if any(spec.safety_tag != ToolSafetyTag.READ_ONLY for spec in category_specs):
            capabilities.append(write_label)
    if "batch_read" in enabled:
        capabilities.append("batched supported reads")

    parts = ["Mecha Ghidra: tools for static binary analysis in Ghidra projects."]
    if capabilities:
        parts.append("Search this server's tools when a binary-analysis task needs: " + "; ".join(capabilities) + ".")
    else:
        parts.append("No analysis capabilities are advertised for this tool selection; consult the tool catalog.")
    if "list_targets" in enabled:
        parts.append("Start with list_targets to identify the program context.")
    if any(spec.include_target for spec in specs.values()):
        parts.append("Pass the intended target across calls; paths refer to the server filesystem.")
    parts.append("Tool details: ghidra://docs/tools and ghidra://docs/tools/{tool_name}.")
    if config.large_result_mode == "resource":
        parts.append(
            "Large results may return a preview and result_id. Use read_result to page/select JSON items or fields, "
            "or search_result for regex matches and next_cursor. Full content: ghidra://results/{result_id}. "
            "Summary previews are not raw prefixes; follow continue_offset_chars. "
            "RESULT_TOO_LARGE may mean execution succeeded but content could not be cached."
        )
    parts.append("Check isError, status and completion metadata; do not automatically repeat completed changes.")
    return "\n".join(parts)
