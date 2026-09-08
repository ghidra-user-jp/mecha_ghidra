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
| `open_program` | Open an existing project program in a new target |
| `register_target` | Register project metadata to a target without opening a program |
| `close_session` | Close a target session |
| `close_session_and_remove_program` | Close a session and remove the program from the project |
| `list_project_programs` | List programs in the target's opened project |
| `import_program` | Import a binary or `.gzf` into the project |
| `load_project_program` | Load an existing program by `domain_path`; loading the program the target already holds reloads it in place, and `version=N` opens a past shared-project version read-only |
| `save_project_program` | Persist the currently loaded program after edits |
| `get_program_info` | Language, compiler, image base, md5/sha256, entry points, analysis flag, unsaved changes, undo availability, and a `revision` for change detection |
| `undo_program_change` / `redo_program_change` | Undo or redo the most recent transactions on the loaded program |
| `export_program` | Write the program as a `.gzf` archive or raw bytes (restrict with `--allowed-export-root`) |

<a id="function-analysis"></a>

## Function analysis

| Tool | Purpose |
| --- | --- |
| `list_functions` | List functions with size and thunk flag; `filter` narrows by name, `only_default_names=true` lists the still-unnamed `FUN_` functions |
| `list_namespaces` | List namespaces as `{name, is_class}` (paginated); `classes_only=true` for classes |
| `decompile_function` | Get C-like pseudocode by function name or address (`address` wins if both are set) |
| `disassemble` | Read existing instructions for a function or address range, with pagination |
| `get_function` | Get a function's signature, parameters, locals, body range, thunk target, and namespace by name or address (`address` wins if both are set) |
| `create_function` | Create a function at an address |
| `delete_function` | Delete a function by address |
| `analyze_program` | Run analysis when the program is marked unanalyzed; `force=true` runs it again |
| `get_call_edges` | Read incoming/outgoing calls with call sites; distinguish tail calls, thunk transfers, and unresolved calls |

### Query results and continuation

`get_xrefs`, `get_call_edges`, and `disassemble` return `program`, `revision`, `items`, `has_more`, and `next_cursor`. Set `limit` to control the page size (default 100, maximum 10,000). For the next page, repeat the query with the returned cursor; only `limit` may change. Stop when `has_more=false`.

A revision identifies the current loaded program state. Edits, undo/redo, and reloads can invalidate a cursor. On `SESSION_CHANGED`, restart the query from the current state. These pages are independent of [large-result retrieval](configuration.md#large-results): a large page may itself be stored as a result resource.

Call edges include caller/callee identities and the instruction address in `call_site`. Data references are excluded. Unresolved outgoing calls have `resolved=false`; a semantic thunk transfer without an instruction reference has `call_site=null`. Tail-call edges represent cross-function jump references, not a proof of high-level control-flow semantics.

<a id="memory-data"></a>

## Memory and data

| Tool | Purpose |
| --- | --- |
| `list_segments` | Get memory segment/layout info |
| `list_imports` | List imported symbols with library and address |
| `list_exports` | List exported symbols with address |
| `list_data_items` | List data items with label, length, and value |
| `list_strings` | List strings (case-insensitive `filter`) |
| `get_xrefs` | Read both reference endpoints and their functions; select `direction="to"` or `"from"` |
| `get_data_by_label` | Get data by label name |
| `get_bytes` | Read bytes at an address |
| `search_bytes` | Search byte patterns; `??` is a wildcard byte |

<a id="symbol-comment-edit"></a>

## Symbols and comments

| Tool | Purpose |
| --- | --- |
| `apply_edits` | Batch function/variable/data renames, types, and comments, with atomic rollback, dry runs, and before/after state |
| `set_function_prototype` | Set function prototype (function by `function_address` or `function_name`) |
| `set_local_variable_type` | Set type for local variable/argument (function by `function_address` or `function_name`) |
| `set_global_data_type` | Set global data type (`clear_mode` optional) |
| `set_bytes` | Write bytes into memory |
| `get_comments` | Read every comment slot at an address |
| `search_symbols` | Search all symbols by name (globs allowed), optionally by symbol type |
| `create_label` | Create a label at an address that has no symbol yet |
| `add_bookmark` | Add bookmark |
| `list_bookmarks` | List bookmarks |
| `delete_bookmark` | Delete a bookmark by ID or by address/type/category |

### Batch annotations

`apply_edits` applies 1–100 ordered operations to one target. Supported kinds are `rename_function`, `rename_data`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_global_data_type`, and `set_comment`. Each kind has its own strict schema. Obtain addresses from analysis tools and use full type paths when names are ambiguous.

Example arguments (replace addresses):

```json
{
  "target": "default",
  "atomic": true,
  "dry_run": true,
  "edits": [
    {"kind": "rename_function", "address": "0x401000", "new_name": "decode_config"},
    {"kind": "set_comment", "address": "0x401000", "comment_type": "pre", "comment": "Decodes the configuration buffer."}
  ]
}
```

The default `atomic=true` commits all edits together or rolls all of them back. `atomic=false` keeps successful items and reports failures individually. `dry_run=true` executes the edits to obtain their actual before/after states, then rolls back; it still requires a writable program and a checkout for a versioned shared file. A dry run can advance the revision even though it leaves no edits behind.

To guard against intervening edits, pass `expected_revision` from the latest `get_program_info` or query response. A successful preview returns the revision to use for applying its edits with `dry_run=false`.

Inspect `status`, `applied_count`, and every item in `results`: `applied`, `partial`, `rolled_back`, `dry_run`, and `dry_run_failed` are batch statuses. Item failures appear inside a normal tool result, so transport success alone does not mean edits were applied. Successful items include `before` and `after`; rolled-back and simulated items are labeled accordingly. Save retained changes with `save_project_program`.

Standalone type editors remain available. Batch global typing checks for space; use the standalone `set_global_data_type` when you need its explicit `clear_mode` options.

<a id="datatype-ops"></a>

## Data types

| Tool | Purpose |
| --- | --- |
| `create_struct` | Create struct |
| `add_struct_members` | Add struct members |
| `remove_struct_members` | Remove selected struct members, or every member with explicit `clear_all=true` |
| `delete_data_type` | Delete a data type (struct, union, enum, typedef, ...) |
| `get_data_type` | Describe a type by full path or unique name, including struct/union members, enum values, or typedef base type |
| `list_data_types` | List program data types |
| `rename_data_type` | Rename a data type |
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
| `bsim_query` | Search the whole program with `scope="program"`, or selected `addresses` / `function_names` with `scope="functions"`; self matches are excluded by default |
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
