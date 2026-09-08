[English](docker.md) | [日本語](docker.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Docker

Run Mecha Ghidra with Ghidra and Java included in the image. Install Docker with Compose support, clone this repository, and run the following commands from its root.

## Build and start

```bash
mkdir -p samples exports
./build_docker_image.sh
docker compose up -d
docker compose ps
docker compose logs --tail=100 ghidra-mcp
```

Connect your [MCP client](clients.md) to `http://127.0.0.1:8081/mcp`. The service starts with target `default` and project metadata only. On a fresh volume, complete the next section before using analysis tools.

`docker compose build` is also supported. The default platform is `linux/amd64`. The image runs as UID/GID `10001:10001`; the port is published on host loopback. Its health check tests TCP connectivity, not whether a program is loaded or a decompilation succeeds.

## First import

Place the analysis file at `./samples/sample.bin` on the host. These are MCP tool names and JSON arguments:

1. `create_project` — run once on a fresh volume:

   ```json
   {"project_location":"/data/projects","project_name":"default"}
   ```

2. `import_program`:

   ```json
   {"target":"default","binary_path":"/samples/sample.bin"}
   ```

3. `load_project_program` — copy the import response's `program` value into `domain_path`:

   ```json
   {"target":"default","domain_path":"/sample.bin"}
   ```

Now call `list_functions` or `decompile_function`. Subsequent starts can load the existing program without recreating or reimporting it.

## Storage and paths

| Host storage | Container path | Purpose |
| --- | --- | --- |
| `./samples` | `/samples` | Read-only input files |
| Compose volume `ghidra-projects` | `/data/projects` | Persistent Ghidra projects |
| `./exports` | `/data/exports` | Exported `.gzf` files or raw bytes |

The default project is `/data/projects/default.gpr` with sibling `default.rep`. Compose may prefix the volume name with its project name. Import copies the input into the Ghidra project, so the source needs only read access.

The container sets all three [allowed-root options](configuration.md#file-access) to these paths. Pass `/samples/sample.bin`, not the host path, to `import_program`. Exports must go under `/data/exports`. On Linux, ensure the export bind mount is writable by UID 10001; Docker Desktop's permissions may differ.

To stop the service while retaining the project volume:

```bash
docker compose down
```

The `-v` option also removes named volumes and their project data. Back up both `.gpr` and `.rep` before replacing storage.

## ARM64 and custom Ghidra builds

On Linux ARM64 or Apple Silicon, use the same platform for both build and startup:

```bash
DOCKER_PLATFORM=linux/arm64 ./build_docker_image.sh
DOCKER_PLATFORM=linux/arm64 docker compose up -d
```

The default ARM64 build applies this repository's native decompiler overlay to the pinned upstream Ghidra ZIP. It fails during the build if the required executables are missing.

| Override | Required pair |
| --- | --- |
| Ghidra distribution | `GHIDRA_DIST_URL` and `GHIDRA_DIST_SHA256` |
| Native decompiler overlay | `GHIDRA_DECOMPILER_NATIVES_URL` and `GHIDRA_DECOMPILER_NATIVES_SHA256` |

Pass these environment variables to the build command. When overriding the Ghidra distribution on ARM64, supply an overlay matching that version or a distribution that already contains the native files. Do not reuse an overlay from another Ghidra version. See [artifact selection](usage.md#native-decompiler-artifacts) and [native builds](development.md#native-builds).

## Shared repositories and BSim

These categories are not enabled by the default image command. To use them, extend the Compose service's `command` with the flags in [shared projects](shared-projects.md) or [BSim](bsim.md), retaining the project, transport, and allowed-root flags from the [Dockerfile](../Dockerfile). Pass backend passwords through the service environment. A backend running on the host is not at the container's `localhost`; configure a hostname reachable from the container.
