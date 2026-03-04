<img width="4096" height="700" alt="mecha_ghidra_one_line" src="https://github.com/user-attachments/assets/def48147-f8cf-4a6a-b4e6-cb3a43798d56" />

[English](README.md) | [日本語](README.ja.md)

# Mecha Ghidra - Headless Ghidra MCP for Ghidra Server
Mecha Ghidra is a Python package that exposes Ghidra as a headless MCP server with PyGhidra and FastMCP. It supports analysis and editing in Ghidra projects, multi-target session management, import/load switching, and optional shared-project sync workflows for collaborative AI-assisted reverse engineering.

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
       --domain-path /main \
       --transport http \
       --mcp-host 127.0.0.1 \
       --mcp-port 8081 \
       --mcp-path /mcp
   ```

For operational patterns and shared-project authentication details, see the [Usage Guide](docs/usage.md).

## Key Features

- **Function and symbol operations**: list functions, decompile, rename, retrieve xrefs, and more.
- **Data-type editing**: create/update/delete structs, enums, and class-like data types.
- **Memory access**: read/search/write bytes and apply global data types.
- **Comments**: set disassembly/decompiler comments.
- **PyGhidra-based runtime**: calls Ghidra APIs directly from CPython (not Jython).
- **Multi-target management**: hold multiple sessions in one process and switch by target name.
- **Project operations**: list project programs with `list_project_programs`, import new binaries with `import_program`, and switch loaded programs with `load_project_program`.

FastMCP tools are grouped under `ghidra_headless.handlers.core` and exposed to MCP clients through `ghidra_mcp.cli`. For full CLI options, run `uv run ghidra-mcp --help`.

### Available Tools

#### Core Operations

- `list_targets` - List registered targets and associated project metadata
- `create_session` - Add a target by opening an existing project program
- `register_target` - Register project metadata to a target without opening a program
- `close_session` - Close a target session
- `close_session_and_remove_program` - Close a session and remove the program from the project
- `list_project_programs` - List programs in the target's opened project
- `import_program` - Import a binary or `.gzf` into the project
- `load_project_program` - Load an existing program by `domain_path`

#### Function Analysis

- `list_methods` - List methods (with pagination)
- `list_functions` - List functions
- `list_classes` - List classes
- `list_namespaces` - List namespaces (with pagination)
- `search_functions_by_name` - Partial-match search by function name
- `decompile_function` - Get C-like pseudocode by function name
- `decompile_function_by_address` - Get C-like pseudocode by address
- `disassemble_function` - Get disassembly for a function
- `get_function_by_address` - Get function metadata by address
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

#### Data Type Operations

- `create_struct` - Create struct
- `add_struct_members` - Add struct members
- `clear_struct` - Remove all struct members
- `remove_struct_members` - Remove selected struct members
- `get_struct` - Get struct definition
- `create_enum` - Create enum
- `add_enum_values` - Add enum values
- `remove_enum_values` - Remove enum values
- `get_enum` - Get enum definition
- `create_class` - Create GhidraClass namespace and backing struct
- `add_class_members` - Add members to class-like data type
- `remove_class_members` - Remove members from class-like data type

#### Shared Project Sync (only with `--enable-shared-project-sync`)

`get_project_sync_status` / `get_version_history` / `get_version_diff` / `checkout` / `commit` / `pull` / `undo_checkout` / `terminate_checkout` / `reload` support optional `domain_path` (if omitted, the currently loaded program is used).

- `get_project_sync_status` - Get sync state against shared project
- `get_version_history` - Get version history (version/user/comment/time)
- `get_version_diff` - Get summarized differences between two versions (count/type/address range)
- `checkout_project_program` - Checkout program (exclusive optional)
- `add_project_program_to_version_control` - Add private program to shared version control
- `commit_project_program` - Check in checked-out changes
- `pull_project_program` - Pull latest state (with optional discard/follow behavior)
- `undo_checkout_project_program` - Undo checkout (optional local change discard)
- `terminate_project_program_checkout` - Force-close an existing checkout by checkout ID
- `reload_project_program` - Reload currently opened program

See the [Usage Guide](docs/usage.md) for detailed workflows and constraints.

## License

See the bundled LICENSE file for project licensing.
