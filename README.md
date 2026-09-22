# Mecha Ghidra

A Ghidra MCP server that supports fully automated AI analysis and the handoff of results and insights to human analysts. It runs independently of Ghidra plugins and provides low-level tools for operations such as decompilation and editing. The AI decides the analysis strategy and steps, selecting and combining the tools it needs.

[English](README.md) | [日本語](README.ja.md) · [Get started](docs/usage.md) · [Tools](docs/tools.md) · [Releases](https://github.com/ghidra-user-jp/mecha_ghidra/releases)

<img src="https://github.com/user-attachments/assets/0adbf0e3-4ad9-4a7b-87a6-62a2f9921bb7" alt="Mecha Ghidra" width="480" />

## Features

- Run independently of Ghidra plugins
  - A standalone MCP server that accesses Ghidra APIs through PyGhidra
  - No plugin installation or GUI operation required
- Hand AI analysis results back to people
  - Save names, types, comments, and other AI edits to a shared Ghidra Server repository
  - Human analysts can retrieve the changes in the Ghidra GUI and continue the analysis
- The AI decides the analysis strategy and steps
  - Provide tools for decompilation, reference lookups, and name or type edits
  - The AI selects and combines tools without the server prescribing a fixed analysis workflow
- Reduce context consumption
  - Expose only the tools needed for the task to reduce context consumed by tool definitions
  - Page through or search large results to retrieve only the parts needed
- Switch between and compare multiple analysis targets
  - Keep multiple sessions open and switch targets during analysis
  - Compare variants and versions, or investigate related EXEs and DLLs
- Use previous analysis results through BSim
  - Search registered binaries for similar functions
  - Open a matched binary as another analysis target and compare the code

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/architecture.svg">
  <img alt="Mecha Ghidra architecture: MCP clients analyze local Ghidra projects, with optional BSim and Ghidra Server integrations." src="docs/assets/architecture.svg">
</picture>

## What you can do

- **Analyze binaries:** decompile and disassemble functions, inspect imports, strings, memory, and cross-references.
- **Record findings:** rename symbols, edit types and comments, undo changes, and export programs.
- **Compare programs:** keep multiple named targets open and search a BSim function database.
- **Work with a team:** check out, save, and check in programs through Ghidra Server.
- **Control context size:** retrieve large results in pages or search within them.

Local analysis works without Ghidra Server or BSim. Shared editing uses checkout/check-in; headless conflict merging is unsupported. See the [shared-project workflow](docs/shared-projects.md).

## Get started

Choose a setup:

| Setup | Start here |
| --- | --- |
| Ghidra is installed on your machine | [Local installation and first analysis](docs/usage.md#local-setup) |
| You want Ghidra bundled in a container | [Docker guide](docs/docker.md) |
| The server is already running | [Connect your MCP client](docs/clients.md) |

The local setup requires Python 3.10+, [uv](https://docs.astral.sh/uv/getting-started/installation/), Ghidra, and a compatible JDK. The repository's native builds currently target Ghidra 12.1.4. See [requirements and native decompiler files](docs/usage.md#requirements) before choosing a Ghidra distribution.

For an **existing** `analysis.gpr` project, this is the minimal stdio launch command. Replace both absolute paths:

```bash
git clone https://github.com/ghidra-user-jp/mecha_ghidra.git
cd mecha_ghidra
uv sync
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra

uv run mecha_ghidra \
  --project-location /absolute/path/to/analysis.gpr \
  --transport stdio
```

Configure your MCP client to launch that command using the [client examples](docs/clients.md). After connecting, call `list_project_programs`, load a program with `load_project_program`, then use `list_functions` and `decompile_function`.

**Starting from a binary file?** Follow [first analysis](docs/usage.md#first-analysis): create a project, import the binary, then load it. Starting the server alone does not create a project or import a file.

## Documentation

| Guide | Contents |
| --- | --- |
| [Getting started](docs/usage.md) | Requirements, installation, first analysis, project concepts |
| [MCP clients](docs/clients.md) | Codex, Claude Code, Kilo Code, and stdio configuration |
| [Configuration](docs/configuration.md) | Transports, tool profiles, file access, large results |
| [Tool reference](docs/tools.md) | All tools, grouped by task |
| [Docker](docs/docker.md) | Build, volumes, first import, ARM64 |
| [Shared projects](docs/shared-projects.md) | Ghidra Server, checkout/check-in, conflicts, version history |
| [BSim](docs/bsim.md) | Similarity search, database registration, matched programs |
| [Troubleshooting and upgrades](docs/troubleshooting.md) | Error codes, common failures, renamed tools |
| [Development](docs/development.md) | Architecture, tests, native builds, releases |

## Contributing

See the [development guide](docs/development.md) for setup and required checks. For a bug report, include the Mecha Ghidra revision, Ghidra/Java versions, transport, a minimal reproduction, and the error code. Report issues through [GitHub Issues](https://github.com/ghidra-user-jp/mecha_ghidra/issues).

## License

[Apache License 2.0](LICENSE). Ghidra and other dependencies retain their own licenses.
