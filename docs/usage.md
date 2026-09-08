[English](usage.md) | [日本語](usage.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Getting started

Install Mecha Ghidra, connect an MCP client, and open your first program. The shell examples use Bash/zsh; replace `/absolute/path/...` with paths on the machine running the server. For a Ghidra-bundled environment, use the [Docker guide](docker.md).

## Documentation map

| I want to… | Read |
| --- | --- |
| Install and analyze a first binary | Continue on this page |
| Connect an AI assistant | [MCP clients](clients.md) |
| Change tool exposure, paths, or output size | [Configuration](configuration.md) |
| Find a tool | [Tool reference](tools.md) |
| Run a container | [Docker](docker.md) |
| Share analysis through Ghidra Server | [Shared projects](shared-projects.md) |
| Search for similar functions | [BSim](bsim.md) |
| Resolve an error or update an old configuration | [Troubleshooting and upgrades](troubleshooting.md) |
| Change or release the code | [Development](development.md) |

<a id="requirements"></a>

## Requirements

| Component | Requirement |
| --- | --- |
| Python | 3.10 or newer |
| Package manager | [uv](https://docs.astral.sh/uv/getting-started/installation/) |
| Ghidra | A full installation, including native decompiler files for your OS/CPU |
| Java | The JDK required by that Ghidra distribution; Ghidra 12.1.x uses JDK 21 |
| MCP client | Streamable HTTP or stdio support |

The build scripts pin Ghidra 12.1.3 in [ghidra_release.env](../scripts/ghidra_release.env). Ghidra Server and a BSim database are optional.

<a id="native-decompiler-artifacts"></a>

### Native decompiler files

The upstream Ghidra 12.1.3 ZIP omits native decompiler directories for Linux ARM64 and both macOS architectures. Choose the matching assets from [Mecha Ghidra releases](https://github.com/ghidra-user-jp/mecha_ghidra/releases):

| Asset | Use |
| --- | --- |
| `ghidra_12.1.3_decompiler_natives_all.zip` | A complete Ghidra installation with the additional natives already installed |
| `ghidra_decompiler_natives_all.zip` | An overlay to extract into an existing Ghidra 12.1.3 installation |
| GitHub's `Source code` archives | Mecha Ghidra source code; not a Ghidra installation |

The overlay supplies matching `decompile` and `sleigh` files under `Ghidra/Features/Decompiler/os/{linux_arm_64,mac_arm_64,mac_x86_64}/`. Keep the native files and Ghidra version together. To build them yourself, see [native builds](development.md#native-builds).

<a id="local-setup"></a>

## 1. Install and start the server

```bash
git clone https://github.com/ghidra-user-jp/mecha_ghidra.git
cd mecha_ghidra
uv sync
```

Put a binary named `sample.bin` in the `samples` directory created below. It can be a recognized executable format such as PE, ELF, or Mach-O; raw binaries need explicit language/import settings from the tool schema.

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
mkdir -p projects samples exports

uv run ghidra-mcp \
  --project-location "$PWD/projects" \
  --project-name analysis \
  --transport http \
  --allowed-import-root "$PWD/samples" \
  --allowed-project-root "$PWD/projects" \
  --allowed-export-root "$PWD/exports"
```

This registers a target named `default` pointing to the future `projects/analysis.gpr`. It does not yet create the project or load a program. Keep the server running and complete the MCP calls below from a second application.

On PowerShell, set the installation path with `$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"`; use PowerShell line continuation or put each shell command on one line.

## 2. Connect a client

Use Streamable HTTP at `http://127.0.0.1:8081/mcp`. See [client configuration](clients.md) for complete examples. Call `list_targets` to confirm that `default` is registered.

<a id="first-analysis"></a>

## 3. Create, import, and load

These are **MCP tool calls**, shown as a name followed by JSON arguments. They are not shell commands. Substitute the repository's absolute path for `/absolute/path/to/mecha_ghidra`.

Create the empty project once with `create_project`:

```json
{
  "project_location": "/absolute/path/to/mecha_ghidra/projects",
  "project_name": "analysis"
}
```

Import the file with `import_program`:

```json
{
  "target": "default",
  "binary_path": "/absolute/path/to/mecha_ghidra/samples/sample.bin"
}
```

The import response's **`program` field** is the path inside the Ghidra project, usually `/sample.bin`. Pass that exact value as `domain_path` to `load_project_program`:

```json
{
  "target": "default",
  "domain_path": "/sample.bin"
}
```

Then call `list_functions` with `{"target":"default","limit":20}`. Choose an address from the response and pass it to `decompile_function` as `{"target":"default","address":"<function-address>"}`. You should receive C-like pseudocode, or a preview with instructions to retrieve a [large result](configuration.md#large-results).

On later starts, reuse the existing project. Skip creation and import, list its programs, then load one. `create_project` refuses an existing project unless `overwrite=true`; overwriting is unnecessary for ordinary startup.

<a id="project-concepts"></a>

## Project, program, and target

| Name | Meaning | Example |
| --- | --- | --- |
| Project location | Host directory containing a project, or an existing `.gpr` file | `/work/projects` or `/work/projects/analysis.gpr` |
| Project name | Name without `.gpr`; used with a directory | `analysis` |
| Domain path | Program path inside the project | `/samples/sample.bin` |
| Target | Name of a registered project/program in this server process | `default`, `reference` |

For `--project-name` and `project_name`, omit `.gpr`; names ending in it are rejected. To open an existing `.gpr` file, pass it as `project_location` and omit `project_name`. A `.gpr` file and its sibling `.rep` directory together form the local project.

`register_target` registers project metadata; `open_program` adds a target and opens a program; `load_project_program` loads or switches a program on an existing target. Use `list_targets` to inspect the available names. Most program tools accept `target`, with `default` used when it is omitted.

## Saving and analysis

Call `save_project_program` after edits when you need an explicit save point. Switching programs or calling `close_session` also saves unsaved changes. Each program-editing tool call is a transaction; `undo_program_change` and `redo_program_change` operate on the current session's history, which is lost on reload. `get_program_info` reports analysis, unsaved changes, and undo availability.

On first load per target/program, automatic analysis runs if Ghidra marks the program unanalyzed and the program is writable. Reloading the same program does not request another pass. Use `analyze_program`, with `force=true` to rerun analysis. Historical versions and shared programs without the required checkout are not automatically analyzed.

Close a local project in the Ghidra GUI before opening that same `.gpr/.rep` in the server. For concurrent GUI and MCP work, use [separate local caches of a shared repository](shared-projects.md).
