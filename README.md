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
       --transport http \
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
- When you switch to `linux/arm64`, Docker now auto-selects the bundled mecha_ghidra patched Ghidra distribution. If you force the upstream official ZIP on ARM64, the build fails early with a clear error instead of failing later inside `decompile_function`.
- You can still override the bundle by setting both `GHIDRA_DIST_URL` and `GHIDRA_DIST_SHA256`.
- `./samples` is shared into the container as `/samples` in read-only mode. Use `/samples/<filename>` with `import_program`.
- Ghidra project data is persisted in the named volume `ghidra-projects`, and the default project path is `/data/projects/default.gpr`. Create that project once before first use, or mount an existing Ghidra project there.
- The server starts with project metadata only and no program loaded. Run `import_program(target="default", binary_path="/samples/<filename>")`, then pass the returned `domain_path` to `load_project_program`.
- The recommended sharing model is `input bind mount (read-only) + Ghidra project named volume (read-write)`. `import_program` copies the input into the project, so the source file does not need write access, and the `.rep` tree tends to behave more reliably on a volume than a bind mount.

## Linux ARM64 Decompiler Artifacts

The repository now ships a dedicated build path for Linux ARM64 Ghidra decompiler binaries.

- `./scripts/build_linux_arm64_decompiler.sh` builds `linux_arm_64` native `decompile` and `sleigh`.
- The release workflow publishes two artifacts:
  - `ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `ghidra_*_linux_arm_64_decompiler.zip`
- The overlay archive preserves the exact path `Ghidra/Features/Decompiler/os/linux_arm_64/{decompile,sleigh}` so it can be unpacked directly into an existing Ghidra install.
- The patched ZIP is intended for ARM Linux Docker builds and direct ARM Linux installs.
- GitHub releases also publish `mecha_ghidra_docker_arm64_*.zip` / `*.tar.gz` assets whose names explicitly indicate they are for Apple Silicon / Linux ARM64 Docker or overlay use.
- For the normal repository snapshot, use GitHub's built-in `Source code (zip)` / `Source code (tar.gz)` links.

Example ARM64 Docker build:

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

Override example:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DIST_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/<release-tag>/ghidra_12.0.4_PUBLIC_20260303_linux_arm_64_decompiler.zip \
GHIDRA_DIST_SHA256=<release-asset-sha256> \
docker compose build
```

If ARM Linux starts without the patched binaries, Mecha Ghidra now returns a clear startup/decompiler error explaining that `linux_arm_64` natives are missing.

## Key Features

- **Function and symbol operations**: list functions, decompile, rename, retrieve xrefs, and more.
- **Data-type editing**: create/update/delete structs, enums, and class-like data types.
- **Memory access**: read/search/write bytes and apply global data types.
- **Comments**: set disassembly/decompiler comments.
- **PyGhidra-based runtime**: calls Ghidra APIs directly from CPython (not Jython).
- **Multi-target management**: hold multiple sessions in one process and switch by target name.
- **Project operations**: create local projects with `create_project`, list programs with `list_project_programs`, import new binaries with `import_program`, and switch loaded programs with `load_project_program`.

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

- `list_methods` - List methods (with pagination)
- `list_functions` - List functions
- `list_classes` - List classes
- `list_namespaces` - List namespaces (with pagination)
- `search_functions_by_name` - Partial-match search by function name
- `decompile_function` - Get C-like pseudocode by function name
- `decompile_function_by_address` - Get C-like pseudocode by address
- `disassemble_function` - Get disassembly for a function
- `disassemble_range` - Get disassembly for an address range
- `get_function_by_address` - Get function metadata by address
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

- `rename_function` - Rename a function (by old name)
- `rename_function_by_address` - Rename a function (by address)
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

After mutating tools such as `rename_function_by_address`, call `save_project_program(target="default")` to persist edits into the Ghidra project. If the same program is already open in the Ghidra GUI, reopen or reload it there to see the saved state.

#### Data Type Operations

- `create_struct` - Create struct
- `add_struct_members` - Add struct members
- `clear_struct` - Remove all struct members
- `remove_struct_members` - Remove selected struct members
- `delete_struct` - Delete a struct data type
- `get_struct` - Get struct definition
- `list_data_types` - List program data types
- `rename_data_type` - Rename a data type
- `create_enum` - Create enum
- `add_enum_values` - Add enum values
- `remove_enum_values` - Remove enum values
- `delete_enum` - Delete an enum data type
- `get_enum` - Get enum definition
- `create_class` - Create GhidraClass namespace and backing struct
- `add_class_members` - Add members to class-like data type
- `remove_class_members` - Remove members from class-like data type

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

## License

See the bundled LICENSE file for project licensing.
