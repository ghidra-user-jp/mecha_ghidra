"""Catalog of core (in-JVM) command names grouped by tool category."""

from __future__ import annotations

FUNCTION_COMMANDS: tuple[str, ...] = (
    "list_functions",
    "get_function",
    "decompile_function",
    "disassemble_function",
    "disassemble_range",
    "create_function",
    "delete_function",
    "analyze_program",
    "get_program_info",
    "undo_program_change",
    "redo_program_change",
    "export_program",
    "get_callee",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_function_xrefs",
)

MEMORY_COMMANDS: tuple[str, ...] = (
    "list_segments",
    "list_imports",
    "list_exports",
    "list_namespaces",
    "list_data_items",
    "list_strings",
    "get_data_by_label",
    "get_bytes",
    "search_bytes",
    "list_data_types",
    "get_struct",
    "get_enum",
)

SYMBOL_COMMANDS: tuple[str, ...] = (
    "rename_function",
    "rename_data",
    "rename_variable",
    "set_comment",
    "get_comments",
    "search_symbols",
    "create_label",
    "set_function_prototype",
    "set_local_variable_type",
    "set_global_data_type",
    "set_bytes",
    "add_bookmark",
    "list_bookmarks",
    "delete_bookmark",
)

DATATYPE_COMMANDS: tuple[str, ...] = (
    "create_struct",
    "add_struct_members",
    "delete_data_type",
    "create_enum",
    "set_enum_values",
    "parse_c_declarations",
    "remove_struct_members",
    "rename_data_type",
)

BSIM_COMMANDS: tuple[str, ...] = (
    "bsim_query_target",
    "bsim_query_function",
    "bsim_register_target",
    "bsim_apply_matches",
    "bsim_update_target_signatures",
)

CORE_COMMANDS: frozenset[str] = frozenset(
    (*FUNCTION_COMMANDS, *MEMORY_COMMANDS, *SYMBOL_COMMANDS, *DATATYPE_COMMANDS, *BSIM_COMMANDS)
)

__all__ = [
    "BSIM_COMMANDS",
    "CORE_COMMANDS",
    "DATATYPE_COMMANDS",
    "FUNCTION_COMMANDS",
    "MEMORY_COMMANDS",
    "SYMBOL_COMMANDS",
]
