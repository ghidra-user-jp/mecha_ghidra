[English](usage.md) | [日本語](usage.ja.md)

# Usage Guide

This document explains installation and operations for `ghidra-mcp`. For the full tool list, see the [README](../README.md).

## Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (Python package and virtual environment manager)
- Ghidra installation (`GHIDRA_INSTALL_DIR` must be set so PyGhidra can locate it)
- Java/Ghidra versions required by PyGhidra (Ghidra 11.3+ recommended)

## Setup

1. **Install uv**
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
   Or use a platform-specific package.

2. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd GhidraMCP_headless
   ```

3. **Sync dependencies**
   ```bash
   uv sync
   ```
   `uv` automatically creates a virtual environment and installs dependencies from `pyproject.toml` (`requests`, `mcp`, `pyghidra`, etc.).

4. **Set environment variables**
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```
   or
   ```bash
   $env:GHIDRA_INSTALL_DIR="C:\path\to\ghidra"
   ```
   
   This is required for PyGhidra to locate Ghidra.

   If you use Ghidra Server, set the password you configured when creating users:
   ```bash
   export GHIDRA_SERVER_PASSWORD='your-password'
   ```

5. **Start the MCP server**
   ```bash
   uv run ghidra-mcp --project-location /Users/samsepi0l/ghidra_project.gpr --domain-path /main --transport http --mcp-host 127.0.0.1 --mcp-port 8081 --mcp-path /mcp
   ```

## Docker Setup

If you want to try the server without installing Ghidra on the host, use the bundled `Dockerfile` and `docker-compose.yml`.

1. **Create a directory for analysis targets**
   ```bash
   mkdir -p samples
   ```
2. **Build the Docker image (recommended)**
   ```bash
   ./build_docker_image.sh
   ```
3. **Start the MCP server**
   ```bash
   docker compose up -d
   ```
4. **Connect your MCP client**
   `http://127.0.0.1:8081/mcp`

In this compose setup, the server starts with `--project-location /data/projects --project-name default` and expects the project files to live at `/data/projects/default.gpr` and `/data/projects/default.rep`. Create that Ghidra project once before first use, then import a binary and load it. No program is loaded at startup, so the first workflow is `import_program` followed by `load_project_program`.

- `docker compose build` is still supported. The bundled compose file defaults to `DOCKER_PLATFORM=linux/amd64`, matching the bundled Linux decompiler.
- You can override `DOCKER_PLATFORM`. When you use `linux/arm64`, the Docker build now auto-selects the bundled mecha_ghidra patched Ghidra distribution.
- If you explicitly force the upstream official ZIP on ARM64, Docker now fails fast during build instead of failing later inside `decompile_function`.
- If you want a custom artifact, provide both `GHIDRA_DIST_URL` and `GHIDRA_DIST_SHA256`.

### ARM64 Docker Build

For Linux ARM64 or Apple Silicon Docker builds, `DOCKER_PLATFORM=linux/arm64` is now enough to use the default patched ARM64 distribution.

```bash
DOCKER_PLATFORM=linux/arm64 docker compose build
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

To override the bundled ARM64 artifact:

```bash
DOCKER_PLATFORM=linux/arm64 \
GHIDRA_DIST_URL=https://github.com/ghidra-user-jp/mecha_ghidra/releases/download/<release-tag>/ghidra_12.0.4_PUBLIC_20260303_linux_arm_64_decompiler.zip \
GHIDRA_DIST_SHA256=<release-asset-sha256> \
docker compose build
```

For direct artifact generation, run:

```bash
./scripts/build_linux_arm64_decompiler.sh
```

This creates:

- `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
- `dist/ghidra_*_linux_arm_64_decompiler.zip`

### Docker Path Sharing

- Analysis targets: bind mount `./samples` to `/samples` (read-only)
- Ghidra project: mount the named volume `ghidra-projects` at `/data/projects` (read-write)

This is the recommended default for two reasons.

- `import_program` copies the input file into the Ghidra project, so the source file only needs to be readable.
- The `.rep` tree inside a Ghidra project produces many small I/O operations, and on Docker Desktop a named volume is typically more stable and faster than a bind mount.

### Import Example After Docker Startup

If you place `./samples/hello.bin` on the host, use it from the MCP client like this:

- `import_program(target="default", binary_path="/samples/hello.bin")`
- `load_project_program(target="default", domain_path="/hello.bin")`

`import_program` imports into the project root, so the returned `domain_path` is usually `/<filename>`. Reuse that `domain_path` for `load_project_program` and any shared-project sync tools.

## Notes

- `--transport http` is recommended for HTTP connectivity. This starts FastMCP in Streamable HTTP mode and serves `http://127.0.0.1:8081/mcp`.
- `--transport sse` is still available for compatibility (`/sse`).
- If you bind to `--mcp-host 0.0.0.0` (or `::`), protection assumptions differ from local-only mode. Use reverse proxy, TLS, and access controls for external exposure.
- Enable shared-project sync tools with `--enable-shared-project-sync` only when you need to expose `commit/pull/checkout` operations.
- If shared-project authentication is required, specify `--ghidra-server-user` together with exactly one of `--ghidra-server-password` or `--ghidra-server-password-env`. Supplying only one side, or supplying both password options together, causes startup failure.
- Startup also fails when `--ghidra-server-password` is empty or when the env var specified by `--ghidra-server-password-env` is unset or empty. The password value is never logged. If you want to avoid exposing secrets in process arguments, prefer `--ghidra-server-password-env`.
- On Linux ARM64, startup/decompiler initialization now fails with a specific message when `Ghidra/Features/Decompiler/os/linux_arm_64` is missing or not executable.
- If `--domain-path` is omitted, startup registers only the project target (works with empty projects). In this mode, import with `import_program` and open with `load_project_program`.
- Use `load_project_program` to load/switch programs on an existing target. Use `create_session` to create a new target. Use `register_target` when you want to register only project info first.
- In `load_project_program` (and equivalent internal `create_session` path), analysis runs only on the first load per `target + domain_path`. Reloading the same program in the same target lifecycle does not re-run analysis.
- Use `add_project_program_to_version_control` when you want to put a private project program under shared version control (only when the option is enabled).
- Shared-project sync tools target the currently loaded program when `domain_path` is omitted, and directly target the specified program when `domain_path` is provided.
- In shared projects, mutating tools like `rename_*` and `set_*` require `checkout_project_program` beforehand (`CHECKOUT_REQUIRED` error if not checked out).
- `commit_project_program`, `pull_project_program`, and `undo_checkout_project_program` internally close/reopen only when targeting the currently loaded program, to avoid `DomainFile` in-use constraints.
- Due to Ghidra limitations, merge conflict resolution is not supported in headless mode (`checkin/merge` return `requires merge ... not supported in headless mode`).
- `pull_project_program(on_local_changes="discard")` uses `undoCheckout(keep=False)` for local changes, and if `can_merge=true` on a checked-out program it follows the latest server state by dropping the stale checkout instead of calling `DomainFile.merge()`.
- When `can_merge=true` but there is no disposable checkout to drop, `pull_project_program` fails with `UNSAFE_MERGE_REQUIRED` instead of invoking Ghidra's PropertyList merge path.
- `commit_project_program` detects merge conflicts (`can_merge=true`) and, by default, discards local changes to follow the latest state, returning `status=noop` / `reason=conflict_discarded` (human-side updates are prioritized).
- In the Docker setup, the defaults are `./samples:/samples:ro` and `ghidra-projects:/data/projects`. Pass input files as `/samples/<filename>`.
- The Docker server starts with project metadata only, so import first with `import_program` and then open the imported program with `load_project_program`.

### Startup Example with Shared-Project Authentication

```bash
export GHIDRA_SERVER_PASSWORD='your-password'
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --domain-path /main \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --mcp-path /mcp \
    --ghidra-server-user your-user \
    --ghidra-server-password-env GHIDRA_SERVER_PASSWORD
```

You can also pass the password directly:

```bash
uv run ghidra-mcp \
    --project-location /Users/samsepi0l/ghidra_project.gpr \
    --domain-path /main \
    --transport http \
    --mcp-host 127.0.0.1 \
    --mcp-port 8081 \
    --mcp-path /mcp \
    --ghidra-server-user your-user \
    --ghidra-server-password 'your-password'
```

## Ghidra Server Setup

### Installation and User Setup

Install the server:
```bash
sudo GHIDRA_INSTALL_DIR/server/svrInstall
```

Register your own user and a dedicated user for Mecha Ghidra:
```bash
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add your_username
sudo GHIDRA_INSTALL_DIR/server/svrAdmin -add mecha-ghidra
```

Edit `GHIDRA_INSTALL_DIR/server/server.conf` to allow user-based connections.
Make sure `${ghidra.repositories.dir}` is the last argument:
```text
wrapper.app.parameter.1=-a0
wrapper.app.parameter.2=-u
wrapper.app.parameter.3=${ghidra.repositories.dir}
```

Restart Ghidra Server:
```bash
sudo server/ghidraSvr restart
```

Create a Shared Project from "New Project".

<img width="508" height="388" alt="Image" src="https://github.com/user-attachments/assets/1091c615-1590-4a49-aa2c-7628d6efed70" />

Connect to localhost.

<img width="508" height="388" alt="image" src="https://github.com/user-attachments/assets/0d1a0cef-fbee-4513-af18-3193a3529c2f" />

Log in with the created user. The initial password is `changeme`.

<img width="350" height="179" alt="image" src="https://github.com/user-attachments/assets/e03718b4-89df-4a2b-8609-521a42dd1878" />

At first login, you are prompted to change the password. Update passwords for both users.

<img width="353" height="181" alt="image" src="https://github.com/user-attachments/assets/24da9ede-db7b-4ba2-8107-2fb7fe895968" />

Create the project and set the LLM account permission to Read/Write.

<img width="652" height="383" alt="image" src="https://github.com/user-attachments/assets/3da1693c-3dd7-4ba8-a6e6-95b4767cf95c" />

<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/76ef63d5-de7a-48ca-8758-76b5157a98c3" />

<img width="531" height="389" alt="image" src="https://github.com/user-attachments/assets/80a8aa7e-659b-4d8e-bf5f-65eea292dc7f" />

## MCP Configuration for Codex

In the Codex app/CLI, configure `mcp_servers` in `~/.codex/config.toml`.
Recommended `streamable-http` example:

```toml
[mcp_servers.ghidra_headless]
enabled = true
url = "http://127.0.0.1:8081/mcp"
```

If you want to launch directly with `stdio`:

```toml
[mcp_servers.ghidra_headless]
enabled = true
command = "/Users/samsepi0l/.local/bin/uv"
args = [
  "--directory",
  "/Users/samsepi0l/ghidra/GhidraMCP_headless",
  "run",
  "ghidra-mcp",
  "--project-location",
  "/Users/samsepi0l/ghidra_project.gpr",
  "--transport",
  "stdio"
]
```

## MCP Configuration for Claude Code

In Claude Code, you can register the MCP server from CLI.
Recommended `streamable-http` example:

```bash
claude mcp add --transport http ghidra_headless http://127.0.0.1:8081/mcp
```

If shared-project authentication is required on the server side, start `ghidra-mcp` with `--ghidra-server-user` and either `--ghidra-server-password` or `--ghidra-server-password-env`.

## MCP Configuration for Kilocode/Roocode

Kilocode/Roocode MCP settings can be written as JSON. Example for launching via `stdio`:

```json
{
  "mcpServers": {
    "ghidra_headless": {
      "command": "/Users/samsepi0l/.local/bin/uv",
      "args": [
        "--directory",
        "/Users/samsepi0l/GhidraMCP_headless",
        "run",
        "ghidra-mcp",
        "--project-location",
        "/Users/samsepi0l/ghidra_project.gpr",
        "--transport",
        "stdio"
      ],
      "timeout": 300,
      "disabled": true
    }
  }
}
```

For Streamable HTTP mode, specify the endpoint like this:

```json
"ghidra_headless": {
  "disabled": false,
  "timeout": 60,
  "type": "streamable-http",
  "url": "http://127.0.0.1:8081/mcp",
}
```

For clients that require streamable-http, start with `--transport http` and use `http://127.0.0.1:8081/mcp`.
