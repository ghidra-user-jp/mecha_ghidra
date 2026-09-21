[English](tools.md) | [日本語](tools.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Tool reference

Use this index to find a tool by task. Consult the client-visible tool schema before calling it. Full arguments, constraints, and error codes are available as MCP resources at `ghidra://docs/tools` and `ghidra://docs/tools/{tool_name}`.

Most program tools select a `target` (default `default`). The `shared_sync` and `bsim` categories are not exposed by default; enable them through [configuration](configuration.md#tool-exposure).

- [Projects and sessions](#core)
- [Batch reads](#batch-read)
- [Function analysis](#function-analysis)
- [Memory and data](#memory-data)
- [Symbols and comments](#symbol-comment-edit)
- [Data types](#datatype-ops)
- [Shared-project tools](#shared-sync)
- [BSim tools](#bsim)
- [Ghidra scripts](#scripts)
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
| `close_session` | Close a target session; `discard_changes=true` closes without saving (also the recovery path after `TARGET_EXECUTION_INVALID`) |
| `close_session_and_remove_program` | Close a session and remove the program from the project |
| `list_project_programs` | List programs in the target's opened project |
| `import_program` | Import a binary or `.gzf` into the project |
| `load_project_program` | Load an existing program by `domain_path`; loading the program the target already holds reloads it in place, and `version=N` opens a past shared-project version read-only |
| `save_project_program` | Persist the currently loaded program after edits |
| `get_program_info` | Language, compiler, image base, md5/sha256, entry points, analysis flag, unsaved changes, undo availability, and a `revision` for change detection |
| `undo_program_change` / `redo_program_change` | Undo or redo the most recent transactions on the loaded program |
| `export_program` | Write the program as a `.gzf` archive or raw bytes (restrict with `--allowed-export-root`) |

<a id="batch-read"></a>

## Batch reads

`batch_read` executes 1–20 independent reads on one `target` sequentially, with one tool call and one target/project lock acquisition. It is exposed in the default, readonly and full profiles. Supported children are `get_function`, `get_comments`, `get_data_type`, `get_xrefs` and `get_call_edges`. Each child must also be individually enabled; batch access cannot reach disabled tools.

```json
{
  "target": "default",
  "requests": [
    {"id": "function", "tool": "get_function", "arguments": {"address": "0x401000"}, "fields": ["entry", "name"]},
    {"id": "references", "tool": "get_xrefs", "arguments": {"address": "0x401000", "direction": "to", "limit": 20}}
  ],
  "timeout_seconds": 10,
  "max_output_chars": 12000
}
```

IDs must be unique, 1–32 ASCII letters/digits/underscores/hyphens. `arguments` uses the child's usual parameters without `target`. All input shapes, types, selectors and tool exposure checks run before execution. The sum of page limits for xrefs/call edges must not exceed 2,000. Dependencies between requests, recursive batches, writes and scripts are unsupported.

Optional `fields` (1–32 keys) projects top-level result keys, or row keys for paged tools while retaining `program`, `revision`, `has_more` and `next_cursor`. Missing keys are omitted; nested paths are not interpreted. Continue each child's page with its original query arguments and cursor.

The response is one JSON text block. Overall `status` is `ok` if all items succeeded, `partial` if some succeeded, and `error` if none succeeded. Inspect `succeeded_count`, `failed_count`, `not_run_count`, and ordered `items` containing `id`, `tool`, `status`, and `data` or `error`. Expected query failures continue; unexpected backend failures abort. MCP `isError=true` means no reads succeeded or the entire request failed; a partial result has `isError=false` and still contains failed items.

Optional `expected_revision` rejects stale reads before execution. A revision/context change during execution fails the entire batch with `SESSION_CHANGED`, discarding mixed results. `timeout_seconds` (default 10, range 1–60) is checked before starting each read after lock acquisition. It is not a hard interruption deadline and does not include lock waits. Unstarted requests become `not_run` with reason `time_budget_exhausted`.

`max_output_chars` (default 12,000, range 2,048–12,000) bounds the entire response JSON text, excluding the outer MCP envelope; it is not a token count. This tool uses its own output limit. Oversized batches store all projected items in one result-cache entry and return counts, item statuses, complete small results that fit, and a shared `result_id`. Use an omitted item's `offset_items` to retrieve it with `read_result`, for example:

```json
{"result_id": "returned-id", "mode": "json", "path": "/items", "offset_items": 1, "limit_items": 1}
```

Increase `limit_items` to retrieve several items together. If a single item exceeds the retrieval limit, `read_result` skips it (`item_too_large=true`, `next_offset_items` advances past it) and reports its raw-text offset: read it with `mode="text"` or locate relevant text with `search_result`. If even the status manifest exceeds the budget, counts and `item_summaries_omitted=true` remain inline; retrieve the manifest from the cache. Cache refusal returns `result_unavailable=true`; IDs remain subject to normal LRU eviction. In `large_result_mode=inline`, oversized responses fail with guidance to narrow fields, page limits or request count.

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

<a id="scripts"></a>

## Ghidra scripts

Exposed by the tool profile / category flags like every other category (`--tool-profile full` or `--add-category scripts`); `run_script` takes the script text directly; `--script-root` only adds a catalog of pre-made scripts. Scripts run with the server process's OS privileges. See [script execution](configuration.md#scripts) for how runs are wrapped in a transaction and what happens on failure.

| Tool | Purpose |
| --- | --- |
| `list_scripts` | Catalog of executable scripts (`script_id` = `<root>:<file name>`; only the top-level files of each root are listed, subdirectories are not, as in the Script Manager) with runtime (`Java` / `Jython` / `PyGhidra`), category, description and availability; `include_bundled=true` adds Ghidra's own scripts when the operator allowed them |
| `get_script_info` | One script's header metadata and (with `include_source=true`) its source, so its expected `args` can be read before running |
| `run_script` | Run a script against the loaded program, as the Script Manager would. Pass `source` (the script text; Java is recognised by `public class X extends GhidraScript`, Python by an `# @runtime PyGhidra` / `# @runtime Jython` header, else pass `runtime`) or `script_id` (a catalog script). `args` are positional strings. The run is wrapped in a transaction: committed on success, rolled back on exception or timeout. The result carries `transaction_outcome`, stdout/stderr and Java compiler diagnostics, so a failing script can be corrected and re-run |

Failures roll back: `SCRIPT_FAILED` / `SCRIPT_TIMEOUT` carry `details.transaction_outcome` (`rolled_back`, `unchanged`, `unknown`), captured `stdout` / `stderr` (bounded, with `dropped_bytes`), and for Java `SCRIPT_COMPILE_FAILED` the compiler diagnostics.

<a id="result-retrieval"></a>

## Large-result retrieval

Exposed in `--large-result-mode resource`. See [retrieval and cache behavior](configuration.md#large-results).

| Tool | Purpose |
| --- | --- |
| `read_result` | Read a slice of a stored large tool result (page with `offset_chars` / `limit_chars` until `has_more` is false; `limit_chars` defaults to a third of the compaction threshold) |
| `search_result` | Regex-search a stored large tool result; returns at most 100 snippets with up to 2,000 context characters per side, plus match offsets usable as `read_result` offsets. `max_matches=0` counts up to the 10,000-match scan cap without snippets; check `scan_truncated` before treating `match_count` as complete |

Save edits with `save_project_program`. Editing versioned shared files requires a checkout. `remove_struct_members.members` accepts either member-name strings or `{"name": ...}` objects.

For `add_struct_members`, an explicit member `offset` switches a packed structure (including those created by `parse_c_declarations`) to manual layout before editing, preserving the offsets of members outside the replacement. The structure grows if needed to accommodate the specified position. An omitted `offset` appends using the structure's current layout policy; members are processed in the order supplied.
