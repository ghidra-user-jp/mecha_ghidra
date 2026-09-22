[English](development.md) | [日本語](development.ja.md) · [Documentation](usage.md) · [README](../README.md)

# Development

This guide covers contributor setup, runtime constraints, and release maintenance. For running the server, start with [usage](usage.md).

## Set up and check a change

```bash
uv sync --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest
```

The `dev` extra includes test dependencies, Ruff, and packaging tools. Use `uv sync --extra test` if you only need tests. Add/remove dependencies with `uv add` / `uv remove`; commit the corresponding lockfile changes. Ruff configuration is in [pyproject.toml](../pyproject.toml); unused suppression comments fail `RUF100`.

Ordinary tests fake the JVM. Passing them does not establish real Ghidra behavior. Select the real-runtime checks below for changes involving execution threads, transports, JVM startup, project ownership, decompilation, or shared operations.

## Code map

| Area | Responsibility |
| --- | --- |
| [`ghidra_mcp/presentation`](../src/ghidra_mcp/presentation) | CLI, transports, MCP tool registration, result presentation |
| [`ghidra_mcp/application`](../src/ghidra_mcp/application) | Use cases, path/locking policy, ports for runtime capabilities |
| [`ghidra_mcp/contracts`](../src/ghidra_mcp/contracts) and [`domain`](../src/ghidra_mcp/domain) | Tool schemas, value objects, errors |
| [`ghidra_mcp/infrastructure`](../src/ghidra_mcp/infrastructure) | Ghidra adapters and runtime integration |
| [`ghidra_headless`](../src/ghidra_headless) | JVM launcher, project/session ownership, Ghidra commands |
| [`tests`](../tests) | Unit, schema, architecture, and opt-in real-runtime tests |

The CLI keeps no server state in module scope: `main()` builds one `CLIApplication` (runtime bundle plus the tool callables bound to its registry, see `build_application`/`bind_tools` in `presentation/cli.py`) and passes it along; tests build their own through `tests/cli_support.py`. Module-level mutable state is rejected by ruff (`PLW0603`): use `functools.cache` for lazy JVM class lookups and an explicit holder object for process-wide state that must be reset (see `ghidra_headless/scripts/providers.py`). Package `__init__` files resolve their re-exports lazily (`ghidra_mcp/_lazy.py`), so importing a leaf layer such as `ghidra_mcp.contracts` loads neither the CLI nor the MCP SDK or JVM bridge; `test_layering.py` checks this in a fresh interpreter. [`test_layering.py`](../tests/test_layering.py) enforces dependency direction: presentation uses application; application declares ports implemented by infrastructure; infrastructure uses `ghidra_headless`. `domain` and `contracts` do not import upper layers, and `ghidra_headless` never imports `ghidra_mcp`. The one exception is [`ghidra_headless/contracts`](../src/ghidra_headless/contracts): JVM-free rules the core enforces (the `batch_read` request and function rename rules) that `ghidra_mcp/contracts` imports so the schema and the core validate with the same code; the layering test also checks that importing that package loads no `jpype`/`pyghidra`/`ghidra` module. Add new application-facing capabilities to [`ports.py`](../src/ghidra_mcp/application/services/ports.py).

Tool definitions live in [`tool_spec.py`](../src/ghidra_mcp/contracts/tool_spec.py). When a handler reads a new `params.get(...)` key, update its schema and `COMMAND_DEP_KEYS`; [`test_spec_handler_parameters.py`](../tests/test_spec_handler_parameters.py) checks that contract.

Large-result handling is split between `result_store.py` (LRU), `result_compaction.py` (preview/envelope decisions), and `result_tools.py` (retrieval/search), with `result_resources.py` as the facade. Shared synchronization lives in `infrastructure/ghidra_adapter/runtime/sync_operations.py` and the `sync_locking`, `sync_identity`, `sync_postconditions`, `sync_active_program`, and `sync_reopen` mixins.

## Runtime rules

### JVM startup

Start the JVM only through `ghidra_headless.launcher.start_headless_jvm()`, never directly through `pyghidra.start()`. It sets `-Djava.awt.headless=true` before JVM startup and rejects an already-running non-headless JVM with `JVM_NOT_HEADLESS`.

This matters on macOS: MCP 2.x executes handlers in worker threads, and first-time AWT initialization there can wait indefinitely for AppKit's main thread. Setting headless mode after startup is too late. Display-dependent operations must fail with `HEADLESS_UNSUPPORTED`.

### Programs, transactions, and resources

Open programs using `DomainFile.getDomainObject(project, ...)` and release them with `Program.release(project)`. Do not replace this with `GhidraProject.openProgram`: its permanent batch transaction hides `isChanged()`, prevents undo, and can block `.gzf` exports.

Each mutation needs its own transaction: handlers use `core_helpers._txn`; session/runtime operations use `ghidra_headless.session.transactions.run_in_transaction`. Imported programs can use GhidraProject because they are closed immediately after import. Replacing a program context must release its old decompiler, and failed replacement must preserve the usable context.

For shared commands, the successful repository connection check is trusted for two seconds; version and checkout state are still read fresh on each call. Keep this distinction when changing the synchronization path.

### MCP SDK

The supported range is `mcp>=2.2.0,<3`. Register `on_list_tools`, `on_call_tool`, and resource handlers on the official low-level `Server`, and publish explicit input/output schemas through `mcp.types.Tool`. Do not overwrite SDK function metadata. Validate inputs with strict Pydantic models and outgoing `structuredContent` with JSON Schema. Run synchronous handlers in worker threads. Serve HTTP with `Server.streamable_http_app(stateless_http=True, json_response=True, ...)`; serve stdio with `stdio_server()` and `Server.run()`. The `latest-mcp-sdk` CI job tests the latest release in that range; Dependabot groups `mcp`/`mcp-types` updates.

Use `jpype.JClass` for Java classes and `Thread.threadId()` for thread identifiers. Raw imports use public `BinaryLoader` metadata through a read-only `FileByteProvider`; do not use reflection into `ProgramLoader` or the deprecated `RandomAccessByteProvider`. Encode integer file offsets and lengths with `hex()` because Ghidra's `HexLong` options parse even unprefixed strings as hexadecimal.

### PyGhidra dependency and script failures

PyGhidra is pinned to upstream commit [`263160cf57db21a9e25f1e0a8bc42fde5b8824eb`](https://github.com/NationalSecurityAgency/ghidra/commit/263160cf57db21a9e25f1e0a8bc42fde5b8824eb), which identifies itself as 3.2.0 but is an **unreleased snapshot**. As of 2026-09-20, PyPI's latest release is 3.1.0 and swallows script exceptions ([upstream issue](https://github.com/NationalSecurityAgency/ghidra/issues/9288)). The snapshot propagates them, so the local private runner patch has been removed. The pin lives in `[tool.uv.sources]` of `pyproject.toml`, so it applies to `uv sync`/`uv run` (and the Docker image) and `uv.lock` records its SHA-256, while the published metadata only requires `pyghidra>=3.1.0` and stays installable from PyPI. On a PyPI PyGhidra without the fix the startup probe marks every script runtime unavailable (`SCRIPT_RUNTIME_UNAVAILABLE`); all other tools work. The first `uv sync` downloads the Ghidra source archive. Remove the source entry and raise the lower bound together once a release contains the fix: the snapshot also calls itself 3.2.0.

PyPI publication is outside the release scope. Keep this validated commit pinned for repository and release-asset distribution; a stable PyGhidra release is not a prerequisite for v1.0. When updating the dependency, regenerate the lockfile and rerun the runtime and packaging checks below. Local wheel installation and repository installation have been verified with this dependency.

Startup verifies exception propagation through the standard provider. If that check fails, all three script runtimes are unavailable, including Java/Jython parents that could invoke PyGhidra children. Normal analysis tools remain usable. Every script execution entry point also checks readiness before opening a transaction. If Jython is installed, every script run receives a shared interpreter through `GhidraState`, allowing nested Jython exceptions and output to reach the caller. `runScript()` can invoke files in subdirectories and sources registered during execution, so the absence of top-level `.py` files cannot justify skipping this state. Do not replace upstream runners or access private loader methods.

Comment reads and writes use `ghidra.program.model.listing.CommentType` and the public overloads accepting that enum. Do not use the integer constants or integer overloads scheduled for removal. `ScriptBarrier` waits and records ownership under one `Condition`, without a second, unbounded lock acquisition after the timed wait.

## Real-runtime validation

Set a compatible JDK and a real Ghidra install. For local commands and resource ownership:

```bash
GHIDRA_RUNTIME_VALIDATION=1 \
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
GHIDRA_RUNTIME_BINARY_PATH=/bin/ls \
uv run pytest \
  tests/test_runtime_readonly_commands.py \
  tests/test_runtime_mutating_commands.py \
  tests/test_runtime_resource_safety.py
```

`/bin/ls` is a macOS/Linux example; provide a suitable binary on other hosts. Use disposable test projects for mutating validation. A running MCP server or GUI must not have the same local test project open.

With the same runtime flag, `tests/test_runtime_mcp_transport.py` launches the real CLI in separate processes over stdio and localhost Streamable HTTP. It creates disposable projects and a tiny raw binary, so it does not require `GHIDRA_RUNTIME_BINARY_PATH`. It verifies schemas, mutations, rollback, and large-result retrieval, plus direct HTTP calls without initialization, responses without session IDs, and resource retrieval from a fresh connection.

To include Jython, install the Jython extension matching your Ghidra version and set both `GHIDRA_RUNTIME_VALIDATION=1` and `GHIDRA_JYTHON_RUNTIME_VALIDATION=1` when running `tests/test_runtime_script_commands.py` and `tests/test_runtime_mcp_transport.py`. The additional flag fails validation if Jython is unavailable and enables Jython cases over both stdio and HTTP. For isolation, use Java's `-Dapplication.settingsdir=...` setting and install the extension under that settings area's Ghidra extension directory.

| Validation | Additional environment |
| --- | --- |
| Shared-project sync | `GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`, `GHIDRA_RUNTIME_SHARED_PROJECT_NAME`, `GHIDRA_RUNTIME_SHARED_DOMAIN_PATH`, `GHIDRA_RUNTIME_SHARED_SERVER_USER` (or `GHIDRA_SERVER_USER`), `GHIDRA_SERVER_PASSWORD` |
| BSim | `GHIDRA_BSIM_RUNTIME_VALIDATION=1`, `GHIDRA_INSTALL_DIR`, `GHIDRA_BSIM_URL`, and either `GHIDRA_BSIM_PASSWORD` or `GHIDRA_BSIM_PASSWORD_ENV` |
| BSim query/load/decompile | Also `GHIDRA_BSIM_PROJECT_LOCATION`, `GHIDRA_BSIM_PROJECT_NAME`, `GHIDRA_BSIM_QUERY_DOMAIN_PATH`, `GHIDRA_BSIM_QUERY_FUNCTION` |
| BSim matches stored on Ghidra Server | Also `GHIDRA_BSIM_REMOTE_CACHE_DIR`; set both `GHIDRA_SERVER_USER` and `GHIDRA_SERVER_PASSWORD` for password authentication |

[`validate_bsim_runtime.sh`](../scripts/validate_bsim_runtime.sh) enables the BSim runtime flag and can prompt on a TTY if neither password variable is supplied. Separate project caches may connect to the same repository, but must have different local `.gpr/.rep` paths.

Run `tests/test_runtime_registry_shared_sync_commands.py` for the shared lifecycle, including checkout, commit, updates from a second client, and deletion of test files. BSim category and metadata writes require `GHIDRA_BSIM_MUTATION_VALIDATION=1`; use a disposable database because category definitions remain after the tests.

<a id="native-builds"></a>

## Native decompiler builds

| Platform | Command |
| --- | --- |
| Linux ARM64 | `./scripts/build_linux_arm64_decompiler.sh` |
| Apple Silicon macOS | `./scripts/build_decompiler_natives.sh --platform mac_arm_64` |
| Intel macOS | `./scripts/build_decompiler_natives.sh --platform mac_x86_64` |

The Linux ARM64 helper falls back to a `linux/arm64` Docker container on other hosts. Each build emits `dist/ghidra_*_<platform>_decompiler_overlay.tar.gz`, a patched `dist/ghidra_*_<platform>_decompiler.zip`, and matching `.sha256` files. Each platform needs both `decompile` and `sleigh`.

The [release workflow](../.github/workflows/release-decompiler-natives.yml) uses native hosted runners: `ubuntu-24.04-arm`, `macos-15`, and `macos-15-intel`. End users should follow [artifact selection](usage.md#native-decompiler-artifacts).

## Release process

1. Run the Python test/package gate and the relevant real-runtime validation.
2. Before tagging, dispatch `release-decompiler-natives` manually. Verify the `mecha-ghidra-release-assets` workflow artifact.
3. Record its run in `MECHA_GHIDRA_RELEASE_NATIVE_ASSET_RUN_ID` in [ghidra_release.env](../scripts/ghidra_release.env). Keep the verified native asset hashes and [Dockerfile](../Dockerfile) pins aligned when native contents change.
4. Tag builds reuse those verified native ZIPs, while Python packages are rebuilt from the final tag. Verify that the published native ZIP hashes match the pins.
5. Check the two user-facing ZIPs (complete Ghidra bundle and overlay) and the Python source distribution attached to the release. PyPI publication is outside the release scope.

Manual workflow dispatch uploads artifacts without publishing a release. Rerunning an existing tag updates assets without replacing release notes; publishing removes legacy assets and standalone `.sha256` files. Release notes should explain which ZIP to choose and which platform paths were added. Avoid copying the native version/hash defaults into more documents; link to the authoritative release configuration.

## Maintain the documentation

Keep README focused on purpose, first use, and navigation. Put a workflow in its dedicated guide; document exact arguments in the tool schema. Update English and Japanese pages together, retain stable anchors used by other pages, and validate relative links plus JSON/TOML examples. Preserve historical validation versions when revising the Japanese BSim administration guides.
