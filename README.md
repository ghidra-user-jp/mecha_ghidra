<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" />

[English](README.md) | [日本語](README.ja.md)

# Mecha Ghidra - Headless Ghidra MCP for Ghidra Server
Mecha Ghidra is a Python package that exposes Ghidra as a headless MCP server with PyGhidra and FastMCP. It supports analysis and editing in Ghidra projects, multi-target session management, import/load switching, and tag-based shared-project sync workflows for collaborative AI-assisted reverse engineering.

## Documentation

- [Usage Guide](docs/usage.md) | [日本語](docs/usage.ja.md): setup, shared-project operations, multi-target workflows, and Codex/Claude/Kilocode integration
- [Development Guide](docs/development.md) | [日本語](docs/development.ja.md): development flow and testing

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
       --project-location /Users/samsepi0l/ghidra_project.gpr \
       --transport http
   ```

For operational patterns and shared-project authentication details, see the [Usage Guide](docs/usage.md).

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
- When you switch to `linux/arm64`, Docker now uses the upstream official Ghidra distribution plus the bundled mecha_ghidra decompiler natives overlay. If ARM64 starts without the overlay, the build fails early with a clear error instead of failing later inside `decompile_function`.
- You can still override the Ghidra distribution by setting both `GHIDRA_DIST_URL` and `GHIDRA_DIST_SHA256`. For ARM64 overlay overrides, also set both `GHIDRA_DECOMPILER_NATIVES_URL` and `GHIDRA_DECOMPILER_NATIVES_SHA256`.
- For native decompiler artifact types, build commands, and release asset selection, see the [Usage Guide](docs/usage.md#native-decompiler-artifacts).
- `./samples` is shared into the container as `/samples` in read-only mode. Use `/samples/<filename>` with `import_program`.
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
- **Context-efficient large results**: tool results beyond a size threshold are returned as a short preview plus a `result_id`; the full payload stays server-side and is fetched on demand with `read_result` / `search_result` (see [Large Result Compaction](#large-result-compaction)).

FastMCP tools are grouped under `ghidra_headless.handlers.core` and exposed to MCP clients through `ghidra_mcp.cli`. For full CLI options, run `uv run ghidra-mcp --help`.

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
- `load_project_program` - Load an existing program by `domain_path`
- `save_project_program` - Persist the currently loaded program after edits

#### Function Analysis

- `list_functions` - List functions
- `list_classes` - List classes
- `list_namespaces` - List namespaces (with pagination)
- `search_functions_by_name` - Partial-match search by function name
- `decompile_function` - Get C-like pseudocode by function name or address (`address` wins if both are set)
- `disassemble_function` - Get disassembly for a function
- `disassemble_range` - Get disassembly for an address range
- `get_function` - Get function metadata by name or address (`address` wins if both are set)
- `create_function` - Create a function at an address
- `delete_function` - Delete a function by address
- `analyze_program` - Run analysis when the program is marked unanalyzed
- `reanalyze_program` - Force program analysis to run again
- `get_function_xrefs` - Get incoming/outgoing references from a function name
- `get_callee` - Get callee function at a specific address

#### Memory and Data

- `list_segments` - Get memory segment/layout info
- `list_imports` - List imported symbols
- `list_exports` - List exported symbols
- `list_data_items` - List data items
- `list_strings` - List strings (filterable)
- `get_xrefs_to` - Get cross-references to an address
- `get_xrefs_from` - Get cross-references from an address
- `get_data_by_label` - Get data by label name
- `get_bytes` - Read bytes at an address
- `search_bytes` - Search byte patterns

#### Symbol and Comment Editing

- `rename_function` - Rename a function by old name or address (`address` wins if both are set)
- `rename_variable` - Rename a local variable or argument
- `rename_data` - Rename a data label
- `set_function_prototype` - Set function prototype
- `set_local_variable_type` - Set type for local variable/argument
- `set_global_data_type` - Set global data type (`clear_mode` optional)
- `set_bytes` - Write bytes into memory
- `set_decompiler_comment` - Set decompiler comment
- `set_disassembly_comment` - Set disassembly comment
- `add_bookmark` - Add bookmark
- `list_bookmarks` - List bookmarks
- `delete_bookmark` - Delete a bookmark by ID or by address/type/category

After mutating tools such as `rename_function`, call `save_project_program(target="default")` to persist edits into the Ghidra project. If the same program is already open in the Ghidra GUI, reopen or reload it there to see the saved state.

#### Data Type Operations

- `create_struct` - Create struct
- `add_struct_members` - Add struct members
- `clear_struct` - Remove all struct members
- `remove_struct_members` - Remove selected struct members
- `delete_struct` - Delete a struct data type
- `get_struct` - Get struct definition
- `list_data_types` - List program data types
- `rename_data_type` - Rename a data type
- `get_enum` - Get enum definition

#### Shared Project Sync (`shared_sync` category)

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `add_to_version_control` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `delete_shared_project_file` / `reload` support optional `domain_path` where documented (if omitted, the currently loaded program is used; deletion always requires an explicit `domain_path`).

- `get_project_sync_status` - Get sync state against shared project
- `get_version_history` - Get version history (version/user/comment/time)
- `get_version_diff` - Get summarized differences between two versions (count/type/address range)
- `checkout_project_program` - Checkout program (exclusive optional)
- `add_project_program_to_version_control` - Add private program to shared version control
- `commit_project_program` - Check in checked-out changes (`on_conflict="discard"` is required to drop a conflicted checkout)
- `pull_project_program` - Pull latest state (with optional discard/follow behavior)
- `undo_checkout_project_program` - Undo checkout (optional local change discard)
- `terminate_project_program_checkout` - Force-close an existing checkout by checkout ID
- `delete_shared_project_file` - Delete an unloaded shared-project file after `confirm` matches `domain_path`
- `reload_project_program` - Reload currently opened program

#### Large Result Retrieval

Registered while `--large-result-mode resource` (the default) is active:

- `read_result` - Read a slice of a stored large tool result (page with `offset_chars` / `limit_chars` until `has_more` is false; `limit_chars` defaults to a third of the compaction threshold)
- `search_result` - Regex-search a stored large tool result; returns match offsets (usable as `read_result` offsets) with surrounding context. `max_matches=0` counts matches without returning snippets

See the [Usage Guide](docs/usage.md) for detailed workflows and constraints.

### Tool Exposure Controls

Every tool now carries three tags:

- `category`: `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`, `shared_sync`
- `safety`: `read_only`, `write`, `destructive_write`
- `operation_level`: `basic`, `standard`, `advanced`

Profiles:

- `default`: existing-compatible default. Categories = `core`, `function_analysis`, `memory_data`, `symbol_comment_edit`, `datatype_ops`
- `readonly`: `default` categories + `read_only` only
- `full`: every category, including `shared_sync`

Rules:

- No tool flags means the same result as `--tool-profile default`
- `shared_sync` is now a normal `category`
- `shared_sync` is not included by default
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
results larger than a threshold are not returned inline. Instead the tool returns:

- a preview followed by concrete instructions for fetching the rest — text payloads show their first lines (cut at a line boundary), list and dict results show their first complete items/entries as valid JSON,
- a `result_id` and an MCP resource link (`ghidra://results/{result_id}`),
- `structuredContent` metadata (`size_chars`, `mime_type`, `result_type`, `item_count`, ...).

The full payload is kept in an in-memory LRU store on the server and can be accessed three ways:

- `read_result(result_id, offset_chars, limit_chars)` - paged reads; works with tools-only MCP clients
- `search_result(result_id, pattern, context_chars, max_matches)` - regex search; returned offsets feed straight into `read_result`
- `resources/read` on `ghidra://results/{result_id}` - for clients with MCP resource support

Results at or below the threshold, error results, and empty-list results are returned
inline, unchanged. Repeated identical results reuse the same `result_id`
(content-addressed), so a looping agent does not grow the store.

Flags:

- `--large-result-mode {resource,inline}` (default `resource`): `inline` restores the previous behavior of always returning full payloads.
- `--large-result-threshold-chars N` (default `12000`): compaction threshold.
- `--large-result-preview-chars N` (default `4000`): preview budget. Text payloads use the full budget; JSON list and dict results use a quarter of it (a few complete example items/entries convey the schema), full `CallToolResult` dumps use half.
- `--result-cache-max-entries N` (default `512`) / `--result-cache-max-bytes N` (default `134217728`): LRU store budget. Reading an evicted `result_id` returns an error asking to re-run the original tool.
- `--tool-description-mode {full,short,none}` (default `full`): `tools/list` description verbosity. `short` prefers a spec's `short_description` and falls back to the first sentence. Full per-tool documentation is always available as MCP resources at `ghidra://docs/tools` and `ghidra://docs/tools/{tool_name}`.

## License

See the bundled LICENSE file for project licensing.
