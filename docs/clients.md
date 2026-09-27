[English](clients.md) | [日本語](clients.ja.md) · [Documentation](usage.md) · [README](../README.md)

# MCP clients

Choose one connection method per client. **HTTP** connects to a server you start separately; **stdio** lets the client start and stop its own server process. For HTTP, complete [local setup](usage.md#local-setup) or [Docker setup](docker.md) first.

HTTP uses stateless JSON responses, with no MCP session ID or stateful compatibility option. See [transport configuration](configuration.md#transports) for application state and timeout behavior.

With `--backend gui` ([live sharing with the GUI](gui-live.md)) both methods work. Over stdio, the client starts a relay: the first one starts the Ghidra GUI, later ones and other clients share it, and the GUI stays open when the client exits. Add `--backend gui` to the stdio arguments below, as in [the GUI examples](#gui). Over HTTP, connect to the server you started with `--backend gui --transport http`.

## Tool discovery

Mecha Ghidra exposes tool definitions through standard `tools/list`. Clients supporting tool search can load the relevant definitions on demand. The server's `instructions` describe binary-analysis tasks and search capabilities using the tools actually enabled by the profile and individual filters: a readonly profile does not advertise editing operations. Optional BSim, repository and script capabilities appear only when their tools are exposed. With the GUI tools exposed, they also say that a human edits the same programs in the GUI and that `show_in_gui` is for when the human asks. Detailed usage stays in tool descriptions and `ghidra://docs/tools/{tool_name}`.

The guidance is deterministic and limited to 1,900 UTF-8 bytes in the tested configurations. This follows the [server-author guidance](https://code.claude.com/docs/en/mcp#for-mcp-server-authors) to explain the tasks, when to search and key capabilities concisely. Search and deferral still depend on the client; `--tool-description-mode full` does not force that client to load every definition into the model context.

## Codex

For the running HTTP server, add this to `~/.codex/config.toml`:

```toml
[mcp_servers.mecha_ghidra]
url = "http://127.0.0.1:8081/mcp"
```

Or register the same URL from the CLI:

```bash
codex mcp add mecha_ghidra --url http://127.0.0.1:8081/mcp
```

For stdio, use this entry **instead**. Replace all absolute paths; `analysis.gpr` must already exist.

```toml
[mcp_servers.mecha_ghidra]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "mecha_ghidra",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

See [Codex MCP configuration](https://developers.openai.com/codex/mcp) for client settings, including startup and tool timeouts.

## Claude Code

Connect to the running HTTP server:

```bash
claude mcp add --transport http mecha_ghidra http://127.0.0.1:8081/mcp
```

Use `/mcp` in Claude Code to inspect the connection. Configuration scopes and stdio options are described in the [Claude Code MCP guide](https://code.claude.com/docs/en/mcp).

<a id="gui"></a>

## The Ghidra GUI over stdio

The relay starts the Ghidra GUI with the environment the client gives it, which holds few variables: set `GHIDRA_INSTALL_DIR`, and on Linux also `DISPLAY` (and `XAUTHORITY` where the X server needs it). Replace all absolute paths; `analysis.gpr` must already exist.

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.mecha_ghidra_gui]
command = "uv"
args = [
  "--directory", "/absolute/path/to/mecha_ghidra",
  "run", "mecha_ghidra", "--backend", "gui",
  "--project-location", "/absolute/path/to/analysis.gpr",
  "--transport", "stdio"
]
env = { GHIDRA_INSTALL_DIR = "/absolute/path/to/ghidra" }
```

Claude Code:

```bash
claude mcp add mecha_ghidra_gui -e GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra -- uv --directory /absolute/path/to/mecha_ghidra run mecha_ghidra --backend gui --project-location /absolute/path/to/analysis.gpr --transport stdio
```

Clients that share one GUI must start it with the same options that apply to the whole runtime (path roots, `--domain-path`, targets); see [stdio clients](gui-live.md#stdio).

## Kilo Code and JSON-based clients

For Kilo Code's VS Code extension, add an enabled server entry to its MCP settings:

```json
{
  "mcpServers": {
    "mecha_ghidra": {
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
    "mecha_ghidra": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mecha_ghidra",
        "run", "mecha_ghidra",
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
3. Follow [first analysis](usage.md#first-analysis) or use `list_project_programs` and `load_project_program` for an existing project. Loading never analyzes; run `analyze_program` when the load reports `is_analyzed: false`.

If a GUI client cannot find `uv`, use its absolute executable path. Give the stdio process `GHIDRA_INSTALL_DIR` explicitly, as above; a GUI app may not inherit shell variables. No call keeps the client waiting for more than about 50 seconds: `import_program`, `analyze_program` and `run_script` reply within `wait_seconds` and run as background jobs, and any other call still running after 40 seconds replies `deferred: true` and continues on the server ([long calls](usage.md#long-calls)). A default 60-second client timeout is therefore enough. `--lock-timeout-seconds` only controls queue waiting and does not extend client timeouts.

Shared-repository credentials belong to the server's [Ghidra Server configuration](shared-projects.md), not the HTTP client entry.
