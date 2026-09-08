[English](tools.md) | [日本語](tools.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Tool reference

Use this index to find a tool by task. Consult the client-visible tool schema before calling it. Full arguments, constraints, and error codes are available as MCP resources at `ghidra://docs/tools` and `ghidra://docs/tools/{tool_name}`.

Most program tools select a `target` (default `default`). The `shared_sync` and `bsim` categories are not exposed by default; enable them through [configuration](configuration.md#tool-exposure).

- [Projects and sessions](#core)
- [Function analysis](#function-analysis)
- [Memory and data](#memory-data)
- [Symbols and comments](#symbol-comment-edit)
- [Data types](#datatype-ops)
- [Shared-project tools](#shared-sync)
- [BSim tools](#bsim)
- [Large-result retrieval](#result-retrieval)

<a id="core"></a>

## Projects and sessions

See [first analysis](usage.md#first-analysis) for operation order and saving behavior.

| Tool | Purpose |
| --- | --- |
| `list_targets` | List registered targets and associated project metadata |
| `create_project` | Create an empty local Ghidra project |
| `create_session` | Add a target by opening an existing project program |
| `register_target` | Register project metadata to a target without opening a program |
| `close_session` | Close a target session |
| `close_session_and_remove_program` | Close a session and remove the program from the project |
| `list_project_programs` | List programs in the target's opened project |
| `import_program` | Import a binary or `.gzf` into the project |
| `load_project_program` | Load an existing program by `domain_path`; loading the program the target already holds reloads it in place, and `version=N` opens a past shared-project version read-only |
| `save_project_program` | Persist the currently loaded program after edits |
| `get_program_info` | Language, compiler, image base, md5/sha256, entry points, analysis flag, unsaved changes, undo availability |
| `undo_program_change` / `redo_program_change` | Undo or redo the most recent transactions on the loaded program |
| `export_program` | Write the program as a `.gzf` archive or raw bytes (restrict with `--allowed-export-root`) |

<a id="function-analysis"></a>

## Function analysis

| Tool | Purpose |
| --- | --- |
| `list_functions` | List functions with size and thunk flag; `filter` narrows by name, `only_default_names=true` lists the still-unnamed `FUN_` functions |
| `list_namespaces` | List namespaces as `{name, is_class}` (paginated); `classes_only=true` for classes |
| `decompile_function` | Get C-like pseudocode by function name or address (`address` wins if both are set) |
| `disassemble_function` | Get disassembly for a function |
| `disassemble_range` | Get disassembly for an address range |
| `get_function` | Get a function's signature, parameters, locals, body range, thunk target, and namespace by name or address (`address` wins if both are set) |
| `create_function` | Create a function at an address |
| `delete_function` | Delete a function by address |
| `analyze_program` | Run analysis when the program is marked unanalyzed; `force=true` runs it again |
| `get_function_xrefs` | List the callers of a function (by address or name) with the calling function's name |
| `get_callee` | List the functions called from the function at an address as `{name, entry, is_external}` |

<a id="memory-data"></a>

## Memory and data

| Tool | Purpose |
| --- | --- |
| `list_segments` | Get memory segment/layout info |
| `list_imports` | List imported symbols with library and address |
| `list_exports` | List exported symbols with address |
| `list_data_items` | List data items with label, length, and value |
| `list_strings` | List strings (case-insensitive `filter`) |
| `get_xrefs_to` | Get cross-references to an address, including the referencing function |
| `get_xrefs_from` | Get cross-references from an address, including the referenced function |
| `get_data_by_label` | Get data by label name |
| `get_bytes` | Read bytes at an address |
| `search_bytes` | Search byte patterns; `??` is a wildcard byte |

<a id="symbol-comment-edit"></a>

## Symbols and comments

| Tool | Purpose |
| --- | --- |
| `rename_function` | Rename a function by old name or address (`address` wins if both are set) |
| `rename_variable` | Rename a local variable or argument (function by `function_address` or `function_name`) |
| `rename_data` | Rename a data label |
| `set_function_prototype` | Set function prototype (function by `function_address` or `function_name`) |
| `set_local_variable_type` | Set type for local variable/argument (function by `function_address` or `function_name`) |
| `set_global_data_type` | Set global data type (`clear_mode` optional) |
| `set_bytes` | Write bytes into memory |
| `set_comment` | Set a `pre` (decompiler), `eol` (listing), `post`, `plate` (function header), or `repeatable` comment |
| `get_comments` | Read every comment slot at an address |
| `search_symbols` | Search all symbols by name (globs allowed), optionally by symbol type |
| `create_label` | Create a label at an address that has no symbol yet |
| `add_bookmark` | Add bookmark |
| `list_bookmarks` | List bookmarks |
| `delete_bookmark` | Delete a bookmark by ID or by address/type/category |

<a id="datatype-ops"></a>

## Data types

| Tool | Purpose |
| --- | --- |
| `create_struct` | Create struct |
| `add_struct_members` | Add struct members |
| `remove_struct_members` | Remove selected struct members, or every member when `members` is omitted |
| `delete_data_type` | Delete a data type (struct, union, enum, typedef, ...) |
| `get_struct` | Get struct definition |
| `list_data_types` | List program data types |
| `rename_data_type` | Rename a data type |
| `get_enum` | Get enum definition |
| `create_enum` / `set_enum_values` | Create an enum and add, replace, or remove its values |
| `parse_c_declarations` | Parse C structs, unions, enums, typedefs, and prototypes into the program's types |

<a id="shared-sync"></a>

## Shared-project tools

Expose with `--add-category shared_sync`. See [shared workflows, conflicts, and deletion conditions](shared-projects.md).

| Tool | Purpose |
| --- | --- |
| `get_project_sync_status` | Get sync state against shared project |
| `get_version_history` | Get version history (version/user/comment/time) |
| `get_version_diff` | Get summarized differences between two versions (count/type/address range); `include_details=true` adds Ghidra's Diff description per range |
| `checkout_project_program` | Checkout program; `exclusive` omitted follows `--shared-sync-exclusive-checkout` |
| `add_project_program_to_version_control` | Add private program to shared version control |
| `commit_project_program` | Check in checked-out changes; on a stale checkout `on_conflict="keep"` parks the local edits in a `.keep` copy and `on_conflict="discard"` drops them |
| `pull_project_program` | Pull latest state (with optional discard/follow behavior) |
| `undo_checkout_project_program` | Undo checkout (optional local change discard) |
| `terminate_project_program_checkout` | Force-close an existing checkout by checkout ID |
| `delete_shared_project_file` | Delete an unloaded file after `confirm` matches `domain_path`; versioned files additionally require `expected_latest_version` and explicit `allow_non_atomic_versioned_delete=true` |

<a id="bsim"></a>

## BSim tools

Requires `--add-category bsim` and a database URL. See the [BSim guide](bsim.md).

| Tool | Purpose |
| --- | --- |
| `get_bsim_database_status` | Database metadata, executable count, configured categories and function tags |
| `bsim_add_executable_category` | Add an executable metadata category |
| `list_bsim_executables` / `get_bsim_executable` | Browse or fetch executable records |
| `bsim_update_executable_metadata` | Change categories on an existing record |
| `bsim_register_target` | Generate signatures for the loaded program and insert them (optional `categories`) |
| `bsim_update_target_signatures` | Push the loaded program's current function names back to its records |
| `bsim_delete_executable` | Remove an executable and its function records (`confirm` must repeat the md5 or name) |
| `bsim_query_target` / `bsim_query_function` | Find similar functions for the whole program or for a list of functions; self matches are excluded by default |
| `bsim_apply_matches` | Rename default-named functions after their best match in one transaction (`dry_run` available) |
| `bsim_load_matched_executable` | Open the executable behind a match as a new target; `ghidra://` matches need `--bsim-remote-cache-dir` |

<a id="result-retrieval"></a>

## Large-result retrieval

Exposed in `--large-result-mode resource`. See [retrieval and cache behavior](configuration.md#large-results).

| Tool | Purpose |
| --- | --- |
| `read_result` | Read a slice of a stored large tool result (page with `offset_chars` / `limit_chars` until `has_more` is false; `limit_chars` defaults to a third of the compaction threshold) |
| `search_result` | Regex-search a stored large tool result; returns at most 100 snippets with up to 2,000 context characters per side, plus match offsets usable as `read_result` offsets. `max_matches=0` counts up to the 10,000-match scan cap without snippets; check `scan_truncated` before treating `match_count` as complete |

Save edits with `save_project_program`. Editing versioned shared files requires a checkout. `remove_struct_members.members` accepts either member-name strings or `{"name": ...}` objects.
