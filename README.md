<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" />

[English](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/README.md) | [日本語](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/README.ja.md)

# Mecha Ghidra - Headless Ghidra MCP for Ghidra Server
Mecha Ghidra is a Python package that exposes Ghidra as a headless MCP server with PyGhidra and the official MCP Python SDK (`mcp` 2.x). It supports analysis and editing in Ghidra projects, multi-target session management, import/load switching, and tag-based shared-project sync workflows for collaborative AI-assisted reverse engineering.

## Documentation

- [Usage Guide](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.md) | [日本語](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.ja.md): setup, shared-project operations, multi-target workflows, and Codex/Claude/Kilocode integration
- [Development Guide](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/development.md) | [日本語](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/development.ja.md): development flow and testing

## Quick Start

1. Sync dependencies
   ```bash
   uv sync
   ```
2. Set the Ghidra path
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
3. Start the server (Streamable HTTP)
   ```bash
   uv run ghidra-mcp \
       --project-location /path/to/ghidra_project.gpr \
       --transport http
   ```

For operational patterns and shared-project authentication details, see the [Usage Guide](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.md).

## Docker Quick Start

If you want a Ghidra-bundled setup, use the included `Dockerfile` and `docker-compose.yml`.

1. Create a directory for analysis targets
   ```bash
   mkdir -p samples
   ```
2. Build the image (recommended)
   ```bash
   ./build_docker_image.sh
   ```
3. Start the MCP server
   ```bash
   docker compose up -d
   ```
4. Point your MCP client to `http://127.0.0.1:8081/mcp`

- `docker compose build` is still supported. The bundled compose file defaults to `DOCKER_PLATFORM=linux/amd64`, which is required for the bundled Linux decompiler.
- The bundled Compose port is published on host loopback only (`127.0.0.1:8081`). Remote exposure requires an explicit port override plus TLS, authentication, and network access controls.
- When you switch to `linux/arm64`, Docker now uses the upstream official Ghidra distribution plus the bundled mecha_ghidra decompiler natives overlay. If ARM64 starts without the overlay, the build fails early with a clear error instead of failing later inside `decompile_function`.
- You can still override the Ghidra distribution by setting both `GHIDRA_DIST_URL` and `GHIDRA_DIST_SHA256`. For ARM64 overlay overrides, also set both `GHIDRA_DECOMPILER_NATIVES_URL` and `GHIDRA_DECOMPILER_NATIVES_SHA256`.
- For native decompiler artifact types, build commands, and release asset selection, see the [Usage Guide](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.md#native-decompiler-artifacts).
- `./samples` is shared into the container as `/samples` in read-only mode. Use `/samples/<filename>` with `import_program`.
- The container starts with `--allowed-import-root /samples --allowed-project-root /data/projects --allowed-export-root /data/exports` (`./exports` on the host), so MCP clients can only import files from the shared samples directory and only create or open projects under the project volume. It also runs as a non-root user (uid 10001) and exposes a TCP health check on port 8081.
- Ghidra project data is persisted in the named volume `ghidra-projects`, and the default project path is `/data/projects/default.gpr`. Create that project once before first use, or mount an existing Ghidra project there.
- The server starts with project metadata only and no program loaded. Run `import_program(target="default", binary_path="/samples/<filename>")`, then pass the returned `domain_path` to `load_project_program`.
- The recommended sharing model is `input bind mount (read-only) + Ghidra project named volume (read-write)`. `import_program` copies the input into the project, so the source file does not need write access, and the `.rep` tree tends to behave more reliably on a volume than a bind mount.

## Key Features

- **Function and symbol operations**: list functions, decompile, rename, retrieve xrefs, and more.
- **Data-type editing**: create/update/delete structs and inspect enums.
- **Memory access**: read/search/write bytes and apply global data types.
- **Comments**: set disassembly/decompiler comments.
- **PyGhidra-based runtime**: calls Ghidra APIs directly from CPython (not Jython).
- **Multi-target management**: hold multiple sessions in one process and switch by target name.
- **Project operations**: create local projects with `create_project`, list programs with `list_project_programs`, import new binaries with `import_program`, and switch loaded programs with `load_project_program`.
- **Context-efficient large results**: large tool results are replaced by a shorter preview plus a `result_id` when that reduces context; stored payloads are fetched on demand with `read_result` / `search_result` (see [Large Result Compaction](#large-result-compaction)).

Tool implementations are grouped under `ghidra_headless.handlers.core` and exposed to MCP clients through `ghidra_mcp.cli`. For full CLI options, run `uv run ghidra-mcp --help`.

### Available Tools

#### Core Operations

- `list_targets` - List registered targets and associated project metadata
- `create_project` - Create an empty local Ghidra project
- `create_session` - Add a target by opening an existing project program
- `register_target` - Register project metadata to a target without opening a program
- `close_session` - Close a target session
- `close_session_and_remove_program` - Close a session and remove the program from the project
- `list_project_programs` - List programs in the target's opened project
- `import_program` - Import a binary or `.gzf` into the project
- `load_project_program` - Load an existing program by `domain_path`; loading the program the target already holds reloads it in place, and `version=N` opens a past shared-project version read-only
- `save_project_program` - Persist the currently loaded program after edits
- `get_program_info` - Language, compiler, image base, md5/sha256, entry points, analysis flag, unsaved changes, undo availability
- `undo_program_change` / `redo_program_change` - Undo or redo the most recent transactions on the loaded program
- `export_program` - Write the program as a `.gzf` archive or raw bytes (restrict with `--allowed-export-root`)

#### Function Analysis

- `list_functions` - List functions with size and thunk flag; `filter` narrows by name, `only_default_names=true` lists the still-unnamed `FUN_` functions
- `list_namespaces` - List namespaces as `{name, is_class}` (paginated); `classes_only=true` for classes
- `decompile_function` - Get C-like pseudocode by function name or address (`address` wins if both are set)
- `disassemble_function` - Get disassembly for a function
- `disassemble_range` - Get disassembly for an address range
- `get_function` - Get a function's signature, parameters, locals, body range, thunk target, and namespace by name or address (`address` wins if both are set)
- `create_function` - Create a function at an address
- `delete_function` - Delete a function by address
- `analyze_program` - Run analysis when the program is marked unanalyzed; `force=true` runs it again
- `get_function_xrefs` - List the callers of a function (by address or name) with the calling function's name
- `get_callee` - List the functions called from the function at an address as `{name, entry, is_external}`

#### Memory and Data

- `list_segments` - Get memory segment/layout info
- `list_imports` - List imported symbols with library and address
- `list_exports` - List exported symbols with address
- `list_data_items` - List data items with label, length, and value
- `list_strings` - List strings (case-insensitive `filter`)
- `get_xrefs_to` - Get cross-references to an address, including the referencing function
- `get_xrefs_from` - Get cross-references from an address, including the referenced function
- `get_data_by_label` - Get data by label name
- `get_bytes` - Read bytes at an address
- `search_bytes` - Search byte patterns; `??` is a wildcard byte

#### Symbol and Comment Editing

- `rename_function` - Rename a function by old name or address (`address` wins if both are set)
- `rename_variable` - Rename a local variable or argument (function by `function_address` or `function_name`)
- `rename_data` - Rename a data label
- `set_function_prototype` - Set function prototype (function by `function_address` or `function_name`)
- `set_local_variable_type` - Set type for local variable/argument (function by `function_address` or `function_name`)
- `set_global_data_type` - Set global data type (`clear_mode` optional)
- `set_bytes` - Write bytes into memory
- `set_comment` - Set a `pre` (decompiler), `eol` (listing), `post`, `plate` (function header), or `repeatable` comment
- `get_comments` - Read every comment slot at an address
- `search_symbols` - Search all symbols by name (globs allowed), optionally by symbol type
- `create_label` - Create a label at an address that has no symbol yet
- `add_bookmark` - Add bookmark
- `list_bookmarks` - List bookmarks
- `delete_bookmark` - Delete a bookmark by ID or by address/type/category

After mutating tools such as `rename_function`, call `save_project_program(target="default")` to persist edits into the Ghidra project. If the same program is already open in the Ghidra GUI, reopen or reload it there to see the saved state.

#### Data Type Operations

- `create_struct` - Create struct
- `add_struct_members` - Add struct members
- `remove_struct_members` - Remove selected struct members, or every member when `members` is omitted
- `delete_data_type` - Delete a data type (struct, union, enum, typedef, ...)
- `get_struct` - Get struct definition
- `list_data_types` - List program data types
- `rename_data_type` - Rename a data type
- `get_enum` - Get enum definition
- `create_enum` / `set_enum_values` - Create an enum and add, replace, or remove its values
- `parse_c_declarations` - Parse C structs, unions, enums, typedefs, and prototypes into the program's types

#### Shared Project Sync (`shared_sync` category)

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `add_to_version_control` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `delete_shared_project_file` support optional `domain_path` where documented (if omitted, the currently loaded program is used; deletion always requires an explicit `domain_path`).

- `get_project_sync_status` - Get sync state against shared project
- `get_version_history` - Get version history (version/user/comment/time)
- `get_version_diff` - Get summarized differences between two versions (count/type/address range); `include_details=true` adds Ghidra's Diff description per range
- `checkout_project_program` - Checkout program; `exclusive` omitted follows `--shared-sync-exclusive-checkout`
- `add_project_program_to_version_control` - Add private program to shared version control
- `commit_project_program` - Check in checked-out changes; on a stale checkout `on_conflict="keep"` parks the local edits in a `.keep` copy and `on_conflict="discard"` drops them
- `pull_project_program` - Pull latest state (with optional discard/follow behavior)
- `undo_checkout_project_program` - Undo checkout (optional local change discard)
- `terminate_project_program_checkout` - Force-close an existing checkout by checkout ID
- `delete_shared_project_file` - Delete an unloaded file after `confirm` matches `domain_path`; versioned files additionally require `expected_latest_version` and explicit `allow_non_atomic_versioned_delete=true`

#### BSim (`bsim` category)

Function-similarity search against a Ghidra BSim database (`--bsim-url` or a per-call `bsim_url`). See [docs/bsim-postgresql-macos.md](docs/bsim-postgresql-macos.md) for database setup.

- `get_bsim_database_status` - Database metadata, executable count, configured categories and function tags
- `bsim_add_executable_category` - Add an executable metadata category
- `list_bsim_executables` / `get_bsim_executable` - Browse or fetch executable records
- `bsim_update_executable_metadata` - Change categories on an existing record
- `bsim_register_target` - Generate signatures for the loaded program and insert them (optional `categories`)
- `bsim_update_target_signatures` - Push the loaded program's current function names back to its records
- `bsim_delete_executable` - Remove an executable and its function records (`confirm` must repeat the md5 or name)
- `bsim_query_target` / `bsim_query_function` - Find similar functions for the whole program or for a list of functions; self matches are excluded by default
- `bsim_apply_matches` - Rename default-named functions after their best match in one transaction (`dry_run` available)
- `bsim_load_matched_executable` - Open the executable behind a match as a new target; `ghidra://` matches need `--bsim-remote-cache-dir`

#### Large Result Retrieval

Registered while `--large-result-mode resource` (the default) is active:

- `read_result` - Read a slice of a stored large tool result (page with `offset_chars` / `limit_chars` until `has_more` is false; `limit_chars` defaults to a third of the compaction threshold)
- `search_result` - Regex-search a stored large tool result; returns at most 100 snippets with up to 2,000 context characters per side, plus match offsets usable as `read_result` offsets. `max_matches=0` counts up to the 10,000-match scan cap without snippets; check `scan_truncated` before treating `match_count` as complete

See the [Usage Guide](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/docs/usage.md) for detailed workflows and constraints.

### Tool Exposure Controls

Every tool now carries three tags:

- `category`: `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`, `shared_sync`, `bsim`
- `safety`: `read_only`, `write`, `destructive_write`
- `operation_level`: `basic`, `standard`, `advanced`

Profiles:

- `default`: existing-compatible default. Categories = `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`
- `readonly`: `default` categories + `read_only` only
- `full`: every category, including `shared_sync` and `bsim`

Rules:

- No tool flags means the same result as `--tool-profile default`
- `shared_sync` is now a normal `category`
- `shared_sync` and `bsim` are not included by default; add them with `--add-category shared_sync` / `--add-category bsim`. BSim tools also need `--bsim-url` or a per-call `bsim_url`.
- `--enable-shared-project-sync` has been removed
- Repeating the same allow flag is OR
- Different allow flag types combine with AND
- `--allow-category` replaces the current category set
- `--add-category` adds categories on top of the current set
- `--enable-tool` adds tools after tag/profile filtering
- `--disable-tool` removes tools last and always wins

Examples:

Existing-compatible startup:

```bash
uv run ghidra-mcp --project-location /path/to/project.gpr --domain-path /main
```

Readonly profile:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile readonly
```

Full profile:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile full
```

Default profile plus shared-project sync:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile default \
    --add-category shared_sync
```

Full profile narrowed to readonly tools only:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile full \
    --allow-safety read_only
```

Individual enable/disable overrides:

```bash
uv run ghidra-mcp \
    --project-location /path/to/project.gpr \
    --domain-path /main \
    --tool-profile readonly \
    --enable-tool rename_function \
    --disable-tool set_bytes
```

### Large Result Compaction

Local LLMs slow down as context grows, and most of that growth comes from large tool
outputs such as decompiled code and long listings. To keep agent contexts small, tool
results larger than a threshold are compacted when the resulting envelope is smaller
than the inline response. A compacted tool call returns:

- a preview followed by concrete instructions for fetching the rest — text payloads show their first lines (cut at a line boundary). List and dict results show their first complete items/entries as valid JSON when at least one complete item/entry fits the preview budget; otherwise the preview falls back to a raw payload prefix and may not itself be valid JSON,
- a `result_id` and an MCP resource link (`ghidra://results/{result_id}`),
- `structuredContent` metadata (`size_chars`, `mime_type`, `result_type`, `item_count`, ...).

When it fits the configured cache, the full payload is kept in an in-memory LRU store
on the server and can be accessed three ways:

- `read_result(result_id, offset_chars, limit_chars)` - paged reads; works with tools-only MCP clients
- `search_result(result_id, pattern, context_chars, max_matches)` - regex search; returns at most 100 snippets with at most 2,000 context characters per side, and its offsets feed straight into `read_result`
- `resources/read` on `ghidra://results/{result_id}` - for clients with MCP resource support

Results at or below the threshold, error results, and empty-list results are returned
inline, unchanged. A result above the threshold also stays inline unless the complete
preview/resource envelope is smaller than the serialized inline response. If a result
entry (its UTF-8 payload plus retained metadata) cannot fit in the entire cache byte
budget, the tool execution still counts as successful, but the full result cannot be
retained in the cache for later retrieval. When it is smaller than the inline response,
the server returns a compact `RESULT_TOO_LARGE` result-unavailable notice without the
original payload; otherwise it preserves the smaller inline result, including its full
payload. Do not automatically repeat a
side-effecting tool call in response to this notice; for a safe call, narrow the query or
increase the byte budget before explicitly running it again. Repeated identical stored
results reuse the same `result_id` (content-addressed), so a looping agent does not grow
the store.

Flags:

- `--large-result-mode {resource,inline}` (default `resource`): `resource` conditionally compacts eligible large results only when doing so reduces the complete response; `inline` always returns full payloads.
- `--large-result-threshold-chars N` (default `12000`): successful results above this character threshold are considered for compaction.
- `--large-result-preview-chars N` (default `4000`): initial preview upper bound. Text payloads use up to the full bound; JSON list and dict results use up to a quarter of it (a few complete example items/entries convey the schema), and full `CallToolResult` dumps use up to half. The preview is reduced further when JSON escaping or response metadata would otherwise exceed the complete-response budget. If no complete list item or dict entry fits, the preview uses a raw prefix instead and may not be valid JSON.
- `--result-cache-max-entries N` (default `512`) / `--result-cache-max-bytes N` (default `134217728`): LRU store budget; the byte budget accounts for UTF-8 payloads plus retained metadata. Reading an evicted `result_id` warns against automatically re-running the original tool because it may have had side effects; regenerate only when the call is known safe or idempotent. A result entry above the byte budget is not stored and returns a successful `RESULT_TOO_LARGE` result-unavailable notice without its full content only when that notice is smaller; otherwise the inline result is preserved. Do not automatically retry side-effecting calls.
- `--tool-description-mode {full,short,none}` (default `full`): `tools/list` description verbosity. `short` prefers a spec's `short_description` and falls back to the first sentence. Full per-tool documentation is always available as MCP resources at `ghidra://docs/tools` and `ghidra://docs/tools/{tool_name}`.

## Security and Concurrency Flags

- `--allowed-import-root DIR` (repeatable): `import_program` accepts only files below these directories. Symlinks are resolved before the check, so a link inside a root cannot escape it. Without the flag any file readable by the server process can be imported and then read back through `get_bytes` or `list_strings`.
- `--allowed-project-root DIR` (repeatable): `create_project`, `create_session`, and `register_target` accept only project locations below these directories.
- Both flags are optional for local stdio use. For `--transport http` or `sse` the server logs a warning at start-up when neither is configured; configure both for any network deployment.
- `--lock-timeout-seconds N` (default `30`): tool calls run in worker threads, so an agent that issues several calls against the same target in parallel queues behind the busy one. A call that waits longer than this returns a retryable `LOCK_TIMEOUT` error instead of blocking forever.
- `--shared-sync-exclusive-checkout`: `checkout_project_program` without an explicit `exclusive` (and the automatic checkout made by `commit_project_program`) takes an exclusive checkout. Headless Ghidra cannot merge, so this prevents the conflicts that would otherwise force a `keep`/`discard` decision. Recommended when an agent edits programs that people also edit.
- `--allowed-export-root DIR` (repeatable): `export_program` writes only below these directories. Without it the loaded program can be written anywhere the server process can write.
- `--bsim-remote-cache-dir DIR`: lets `bsim_load_matched_executable` open matches that live on a Ghidra Server by creating one local cache project per repository under this directory. It must lie under an `--allowed-project-root` when project roots are restricted.

## Behavior Notes

- `load_project_program` and `close_session` save the previously loaded program when it has unsaved changes. Call `save_project_program` explicitly when you need the save to happen at a known point.
- `load_project_program(version=N)` opens a past shared-project version read-only in the target. Read tools work on it; mutating tools fail with `READ_ONLY_PROGRAM`, and sync tools ignore such a session. Load the program without `version` to return to the current file.
- `rename_variable` and `set_local_variable_type` never start auto-analysis on their own. On an unanalyzed program they fail with `PROGRAM_NOT_ANALYZED`; run `analyze_program` first.
- Every tool failure is returned to the client as an MCP tool error whose text starts with a stable code such as `CHECKOUT_REQUIRED:` or `PATH_NOT_ALLOWED:`; the same codes appear in `ghidra://docs/tools/{tool_name}`.
- On the `stdio` transport the server redirects the JVM's `System.out` to stderr after start-up so Ghidra console output cannot corrupt the JSON-RPC stream. Prefer `--transport http` when running inside a container.
- On shared projects the repository connection check that precedes every mutating command is trusted for two seconds after it succeeds, so bursts of edits do not pay a server round-trip each. Version and checkout state are still read fresh on every call.
- `remove_struct_members` accepts either member names or `{"name": ...}` objects, matching the shape used by `create_struct` and `add_struct_members`.

## Upgrading

- New tools: `get_program_info`, `undo_program_change` / `redo_program_change`, `export_program` (with `--allowed-export-root`), `get_comments`, `search_symbols`, `create_label`, `create_enum` / `set_enum_values`, and `parse_c_declarations`.
- Seven core tools were folded into their neighbours: `search_functions_by_name` → `list_functions(filter=...)`, `list_classes` → `list_namespaces(classes_only=true)`, `reanalyze_program` → `analyze_program(force=true)`, `set_decompiler_comment` / `set_disassembly_comment` → `set_comment(kind="pre"|"eol")`, `clear_struct` → `remove_struct_members` without `members`, and `delete_struct` → `delete_data_type`. `get_function` now returns the full signature, parameters, and locals; `list_imports`, `list_exports`, `list_namespaces`, and `get_callee` return objects instead of strings; `get_xrefs_to`/`get_xrefs_from` add the function at the other end; `rename_variable`, `set_function_prototype`, and `set_local_variable_type` accept either `function_address` or `function_name`; `search_bytes` accepts `??` wildcards; `list_strings.filter` is case-insensitive.
- Three tools were removed: `reload_project_program` (call `load_project_program` with the domain path the target already holds; the response has `reloaded=true`), `list_bsim_categories` (`get_bsim_database_status` returns `categories` and `function_tags`), and `bsim_set_target_metadata` (pass `categories` to `bsim_register_target`). New tools: `bsim_apply_matches`, `bsim_update_target_signatures`, `bsim_delete_executable`. `checkout_project_program.exclusive` now defaults to the server policy (`--shared-sync-exclusive-checkout`) instead of `false`, `commit_project_program.on_conflict` accepts `keep`, `get_version_diff` gained `include_details`, and `bsim_query_target` excludes the program's own database record unless `exclude_self=false`.
- Version 0.1.4 moves to the `mcp` 2.x SDK (`mcp>=2.1.1,<3`). Tool calls now execute in worker threads instead of blocking the server event loop, and the SDK's `Tool`/`MCPServer` public APIs are used exclusively, so future SDK releases are tracked by the advisory `latest-mcp-sdk` CI job and Dependabot.
- `pull_project_program` now declares the `checked_out` field its runtime always returned; before this fix the pull completed on the server and then failed output validation. Re-registering an already ingested program returns `BSIM_ALREADY_REGISTERED`, and a checkout refused because another user holds an exclusive checkout returns `CHECKOUT_UNAVAILABLE` instead of a generic `SYNC_OPERATION_FAILED`.
- The unused `format` parameter of `add_bookmark` was removed. `on_conflict`, `on_local_changes`, and `clear_mode` are now enumerated in the tool schema, and numeric limits (`get_bytes.size`, BSim thresholds, version numbers) are published as schema bounds.

## License

Licensed under the Apache License, Version 2.0. See the bundled
[LICENSE](https://github.com/ghidra-user-jp/mecha_ghidra/blob/main/LICENSE) file.
