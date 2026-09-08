[English](clients.md) | [日本語](clients.ja.md) · [Documentation](usage.md) · [README](../README.md)

# MCP clients

Choose one connection method per client. **HTTP** connects to a server you start separately; **stdio** lets the client start and stop its own server process. For HTTP, complete [local setup](usage.md#local-setup) or [Docker setup](docker.md) first.

## Codex

For the running HTTP server, add this to `~/.codex/config.toml`:

```toml
[mcp_servers.ghidra_headless]
url = "http://127.0.0.1:8081/mcp"
```

Or register the same URL from the CLI:

```bash
codex mcp add ghidra_headless --url http://127.0.0.1:8081/mcp
```

For stdio, use this entry **instead**. Replace all absolute paths; `analysis.gpr` must already exist.

```toml
[mcp_servers.ghidra_headless]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "ghidra-mcp",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

See [Codex MCP configuration](https://developers.openai.com/codex/mcp) for client settings, including startup and tool timeouts.

## Claude Code

Connect to the running HTTP server:

```bash
claude mcp add --transport http ghidra_headless http://127.0.0.1:8081/mcp
```

Use `/mcp` in Claude Code to inspect the connection. Configuration scopes and stdio options are described in the [Claude Code MCP guide](https://code.claude.com/docs/en/mcp).

## Kilo Code and JSON-based clients

For Kilo Code's VS Code extension, add an enabled server entry to its MCP settings:

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "url": "http://127.0.0.1:8081/mcp",
      "disabled": false
    }
  }
}
```

See [Kilo Code MCP configuration](https://kilo.ai/docs/automate/mcp/using-in-kilo-code). Other clients may require a transport field such as `type`; use their own schema.

For a client using the `mcpServers` stdio format, including Roo Code, the launch entry is:

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mecha_ghidra",
        "run", "ghidra-mcp",
        "--project-location", "/absolute/path/to/analysis.gpr",
        "--transport", "stdio"
      ],
      "env": { "GHIDRA_INSTALL_DIR": "/absolute/path/to/ghidra" }
    }
  }
}
```

## Check the connection

1. Confirm that the client lists Mecha Ghidra's tools.
2. Call `list_targets`. A registered target does not necessarily have a program loaded.
3. Follow [first analysis](usage.md#first-analysis) or use `list_project_programs` and `load_project_program` for an existing project.

If a GUI client cannot find `uv`, use its absolute executable path. Give the stdio process `GHIDRA_INSTALL_DIR` explicitly, as above; a GUI app may not inherit shell variables. Configure a client timeout long enough for import and analysis; `--lock-timeout-seconds` only controls queue waiting and does not extend client timeouts.

For legacy SSE clients, start the server with `--transport sse` and use `/sse`. Shared-repository credentials belong to the server's [Ghidra Server configuration](shared-projects.md), not the HTTP client entry.
